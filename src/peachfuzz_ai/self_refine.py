"""Self-refinement engine for PeachFuzz AI.

This module performs autonomous *analysis* and generates human-reviewable update
proposals. It does not push to GitHub, merge PRs, or edit protected branches.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
from typing import Any

from .personas import MYTHOS_GLASSWING, system_prompt


@dataclass(frozen=True)
class RefinementRecommendation:
    """One proposed improvement derived from fuzz evidence."""

    title: str
    rationale: str
    files_to_consider: tuple[str, ...]
    test_commands: tuple[str, ...]
    risk_level: str = "low"
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RefinementPlan:
    """A full self-refinement proposal."""

    persona: str
    crash_count: int
    unique_exception_types: list[str]
    recommendations: list[RefinementRecommendation]
    pull_request_title: str
    pull_request_body: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "persona": self.persona,
            "crash_count": self.crash_count,
            "unique_exception_types": self.unique_exception_types,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "pull_request_title": self.pull_request_title,
            "pull_request_body": self.pull_request_body,
        }


class SelfRefinementEngine:
    """Analyze fuzz reports and generate safe update proposals."""

    def __init__(self, report_dir: str | Path = "reports") -> None:
        self.report_dir = Path(report_dir)

    def load_findings(self) -> list[dict[str, Any]]:
        """Load crash findings from report JSON files."""
        findings: list[dict[str, Any]] = []
        crash_dir = self.report_dir / "crashes"
        if crash_dir.exists():
            for path in sorted(crash_dir.glob("*.json")):
                try:
                    findings.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue

        # Also support summary files emitted by the deterministic runner.
        for path in sorted(self.report_dir.glob("*-summary.json")):
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for finding in summary.get("crashes", []):
                if isinstance(finding, dict):
                    findings.append(finding)
        return findings

    def build_plan(self) -> RefinementPlan:
        """Create a polished Mythos Glasswing update plan."""
        findings = self.load_findings()
        exception_types = sorted({str(f.get("exception_type", "Unknown")) for f in findings})
        recs: list[RefinementRecommendation] = []

        if any(f.get("exception_type") == "ValueError" and "endpoint" in str(f.get("message", "")).lower() for f in findings):
            recs.append(
                RefinementRecommendation(
                    title="Add endpoint-normalization regression corpus",
                    rationale=(
                        "A JSON fuzz mutation produced a malformed endpoint path. "
                        "Add a regression seed and keep the parser strict so unsafe "
                        "relative API paths cannot pass schema validation."
                    ),
                    files_to_consider=("corpus/json_api/", "tests/test_targets.py", "src/peachfuzz_ai/targets.py"),
                    test_commands=(
                        "pytest -q",
                        "python -m peachfuzz_ai.cli run --target json --runs 500 corpus/json_api",
                    ),
                )
            )

        if any(f.get("exception_type") == "PermissionError" for f in findings):
            recs.append(
                RefinementRecommendation(
                    title="Preserve permission-boundary crash as high-signal guardrail",
                    rationale=(
                        "PermissionError findings represent blocked unsafe routing, "
                        "which should become explicit regression tests and audit evidence."
                    ),
                    files_to_consider=("tests/test_targets.py", "docs/SAFETY.md"),
                    test_commands=("pytest -q tests/test_targets.py",),
                    risk_level="medium",
                )
            )

        if not recs:
            recs.append(
                RefinementRecommendation(
                    title="Expand corpus diversity without changing runtime behavior",
                    rationale=(
                        "No actionable crashes were found. Improve future coverage by "
                        "adding more valid and malformed local-only seed inputs."
                    ),
                    files_to_consider=("corpus/", "tests/"),
                    test_commands=("pytest -q", "make fuzz"),
                )
            )

        body_lines = [
            "## Mythos Glasswing self-refinement proposal",
            "",
            system_prompt(),
            "",
            "## Evidence",
            f"- Crash findings analyzed: {len(findings)}",
            f"- Unique exception types: {', '.join(exception_types) if exception_types else 'none'}",
            "",
            "## Recommendations",
        ]
        for idx, rec in enumerate(recs, 1):
            body_lines += [
                f"{idx}. **{rec.title}**",
                f"   - Rationale: {rec.rationale}",
                f"   - Files: {', '.join(rec.files_to_consider)}",
                f"   - Tests: `{'; '.join(rec.test_commands)}`",
            ]

        body_lines += [
            "",
            "## Safety",
            "- Proposal-only automation.",
            "- Human review required before merge.",
            "- No network scanning, exploitation, or credential activity.",
        ]

        return RefinementPlan(
            persona=MYTHOS_GLASSWING.codename,
            crash_count=len(findings),
            unique_exception_types=exception_types,
            recommendations=recs,
            pull_request_title="chore(self-refine): apply Mythos Glasswing fuzzing recommendations",
            pull_request_body="\n".join(body_lines),
        )

    def write_plan(self, output_path: str | Path = "MYTHOS_GLASSWING_PLAN.md") -> Path:
        """Write a markdown plan and adjacent JSON summary."""
        output = Path(output_path)
        plan = self.build_plan()
        output.write_text(plan.pull_request_body + "\n", encoding="utf-8")
        output.with_suffix(".json").write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")
        return output


def sanitize_branch_name(name: str) -> str:
    """Sanitize generated branch names for local proposal automation."""
    safe = re.sub(r"[^a-zA-Z0-9._/-]+", "-", name.strip().lower())
    safe = re.sub(r"-+", "-", safe).strip("-/")
    return safe[:96] or "mythos-glasswing-update"
