"""Roadmap scoring for PeachFuzz/CactusFuzz."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class RoadmapItem:
    title: str
    edition: str
    why_it_wins: str
    implementation: str
    tests: tuple[str, ...]
    impact: int
    effort: int
    safety_risk: int

    @property
    def score(self) -> float:
        return round((self.impact * 2 - self.effort - self.safety_risk) / 2, 2)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["score"] = self.score
        return data


ROADMAP: tuple[RoadmapItem, ...] = (
    RoadmapItem(
        title="Backend adapter interface",
        edition="both",
        why_it_wins="Lets PeachFuzz orchestrate Atheris now and AFL++/LibAFL later without becoming a monolith.",
        implementation="BackendAdapter protocol now exists with deterministic, atheris, and disabled external-sandbox adapters.",
        tests=("pytest -q", "peachfuzz run --target json --runs 250 corpus/json_api"),
        impact=9,
        effort=4,
        safety_risk=2,
    ),
    RoadmapItem(
        title="Agent guardrail fuzzing pack",
        edition="cactusfuzz",
        why_it_wins="Owns the fast-growing AI-agent security niche better than general fuzzers.",
        implementation="Add adversarial prompt/tool-call corpora, approval-gate oracle, and refusal regression metrics.",
        tests=("pytest -q tests/test_cactusfuzz.py", "cactusfuzz --target local-lab --scope local-lab"),
        impact=10,
        effort=3,
        safety_risk=3,
    ),
    RoadmapItem(
        title="Schema-aware mutators",
        edition="peachfuzz",
        why_it_wins="Moves beyond random bytes into useful JSON/OpenAPI/GraphQL/API fuzzing.",
        implementation="Add grammar profiles for JSON, OpenAPI snippets, GraphQL documents, and webhook envelopes.",
        tests=("pytest -q", "peachfuzz run --target json --runs 1000 corpus/json_api"),
        impact=9,
        effort=5,
        safety_risk=1,
    ),
    RoadmapItem(
        title="Crash minimizer and reproducer generator",
        edition="both",
        why_it_wins="Makes results actionable and developer-friendly, not just noisy.",
        implementation="Add delta-style minimization for byte/text payloads and generate pytest regression files.",
        tests=("pytest -q tests/test_engine.py",),
        impact=8,
        effort=5,
        safety_risk=1,
    ),
    RoadmapItem(
        title="OSS-Fuzz/ClusterFuzzLite project generator",
        edition="peachfuzz",
        why_it_wins="Makes the project immediately useful to open-source maintainers.",
        implementation="Generate project.yaml, Dockerfile, build.sh, GitHub workflow, and artifact layout.",
        tests=("pytest -q", "python -m peachfuzz_ai.cli radar --format json"),
        impact=8,
        effort=4,
        safety_risk=1,
    ),
    RoadmapItem(
        title="Evidence-first red-team report mode",
        edition="cactusfuzz",
        why_it_wins="Differentiates CactusFuzz from unsafe exploit tools by producing scoped, audit-ready evidence.",
        implementation="Add scope manifest, scenario transcript, blocked/allowed decision log, and remediation section.",
        tests=("pytest -q tests/test_cactusfuzz.py",),
        impact=8,
        effort=3,
        safety_risk=2,
    ),
)


def ranked() -> list[RoadmapItem]:
    return sorted(ROADMAP, key=lambda item: (-item.score, item.title.lower()))


def to_json() -> str:
    return json.dumps([item.to_dict() for item in ranked()], indent=2, sort_keys=True)


def to_markdown() -> str:
    rows = [
        "| Score | Edition | Feature | Why it wins | Implementation |",
        "|---:|---|---|---|---|",
    ]
    for item in ranked():
        rows.append(
            f"| {item.score} | {item.edition} | {item.title} | {item.why_it_wins} | {item.implementation} |"
        )
    return "\n".join(rows)
