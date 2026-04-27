import json
from pathlib import Path

from peachfuzz_ai.personas import MYTHOS_GLASSWING, system_prompt
from peachfuzz_ai.self_refine import (
    RefinementPlan,
    RefinementRecommendation,
    SelfRefinementEngine,
    sanitize_branch_name,
)


class TestPersona:
    """Tests for persona and system_prompt."""

    def test_persona_guardrails_are_proposal_only(self) -> None:
        prompt = system_prompt()
        assert "Never auto-merge" in prompt
        assert "Never perform network scanning" in prompt
        assert MYTHOS_GLASSWING.codename == "mythos-glasswing"


class TestRefinementRecommendation:
    """Tests for RefinementRecommendation class."""

    def test_to_dict_conversion(self) -> None:
        rec = RefinementRecommendation(
            title="Test Title",
            rationale="Test Rationale",
            files_to_consider=("file1.py", "file2.py"),
            test_commands=("pytest -q",),
            risk_level="medium",
            human_review_required=True,
        )
        data = rec.to_dict()
        assert data["title"] == "Test Title"
        assert data["rationale"] == "Test Rationale"
        assert data["files_to_consider"] == ("file1.py", "file2.py")
        assert data["test_commands"] == ("pytest -q",)
        assert data["risk_level"] == "medium"
        assert data["human_review_required"] is True


class TestRefinementPlan:
    """Tests for RefinementPlan class."""

    def test_to_dict_conversion(self) -> None:
        rec = RefinementRecommendation(
            title="Test", rationale="Test", files_to_consider=(), test_commands=()
        )
        plan = RefinementPlan(
            persona="test-persona",
            crash_count=5,
            unique_exception_types=["ValueError", "TypeError"],
            recommendations=[rec],
            pull_request_title="PR Title",
            pull_request_body="PR Body",
        )
        data = plan.to_dict()
        assert data["persona"] == "test-persona"
        assert data["crash_count"] == 5
        assert data["unique_exception_types"] == ["ValueError", "TypeError"]
        assert len(data["recommendations"]) == 1
        assert data["pull_request_title"] == "PR Title"
        assert data["pull_request_body"] == "PR Body"


class TestSelfRefinementEngine:
    """Tests for SelfRefinementEngine class."""

    def test_self_refinement_plan_from_summary(self, tmp_path: Path) -> None:
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "json-summary.json").write_text(
            json.dumps(
                {
                    "target_name": "json",
                    "crashes": [
                        {
                            "exception_type": "ValueError",
                            "message": "endpoint must be an absolute API path",
                            "payload_sha256": "abc",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        engine = SelfRefinementEngine(report_dir=reports)
        plan = engine.build_plan()
        assert plan.persona == "mythos-glasswing"
        assert plan.crash_count == 1
        assert "endpoint-normalization" in plan.recommendations[0].title

    def test_write_plan_outputs_markdown_and_json(self, tmp_path: Path) -> None:
        engine = SelfRefinementEngine(report_dir=tmp_path / "missing")
        out = engine.write_plan(tmp_path / "PLAN.md")
        assert out.exists()
        assert out.with_suffix(".json").exists()
        assert "Human review required" in out.read_text(encoding="utf-8")

    def test_load_findings_from_crash_dir(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash1.json").write_text(
            json.dumps({"exception_type": "ValueError", "message": "test"}),
            encoding="utf-8",
        )
        (crash_dir / "crash2.json").write_text(
            json.dumps({"exception_type": "TypeError", "message": "test2"}),
            encoding="utf-8",
        )

        engine = SelfRefinementEngine(report_dir=tmp_path)
        findings = engine.load_findings()
        assert len(findings) == 2

    def test_load_findings_handles_invalid_json(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "bad.json").write_text("not valid json", encoding="utf-8")

        engine = SelfRefinementEngine(report_dir=tmp_path)
        findings = engine.load_findings()
        assert findings == []

    def test_load_findings_from_summary_with_invalid_json(self, tmp_path: Path) -> None:
        (tmp_path / "bad-summary.json").write_text("not valid json", encoding="utf-8")

        engine = SelfRefinementEngine(report_dir=tmp_path)
        findings = engine.load_findings()
        assert findings == []

    def test_load_findings_summary_with_non_dict_crashes(self, tmp_path: Path) -> None:
        (tmp_path / "test-summary.json").write_text(
            json.dumps({"crashes": ["not_a_dict", 123, None]}), encoding="utf-8"
        )

        engine = SelfRefinementEngine(report_dir=tmp_path)
        findings = engine.load_findings()
        assert findings == []

    def test_build_plan_with_permission_error(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "perm.json").write_text(
            json.dumps({"exception_type": "PermissionError", "message": "blocked"}),
            encoding="utf-8",
        )

        engine = SelfRefinementEngine(report_dir=tmp_path)
        plan = engine.build_plan()
        rec_titles = [r.title for r in plan.recommendations]
        assert any("permission-boundary" in t.lower() for t in rec_titles)

    def test_build_plan_with_no_crashes(self, tmp_path: Path) -> None:
        engine = SelfRefinementEngine(report_dir=tmp_path)
        plan = engine.build_plan()
        assert plan.crash_count == 0
        assert len(plan.recommendations) == 1
        assert "corpus diversity" in plan.recommendations[0].title.lower()


class TestSanitizeBranchName:
    """Tests for sanitize_branch_name function."""

    def test_sanitize_branch_name_basic(self) -> None:
        assert sanitize_branch_name("Mythos Glasswing Update!!") == "mythos-glasswing-update"

    def test_sanitize_branch_name_long(self) -> None:
        long_name = "a" * 200
        result = sanitize_branch_name(long_name)
        assert len(result) <= 96

    def test_sanitize_branch_name_empty(self) -> None:
        assert sanitize_branch_name("") == "mythos-glasswing-update"
        assert sanitize_branch_name("   ") == "mythos-glasswing-update"

    def test_sanitize_branch_name_preserves_valid_chars(self) -> None:
        assert sanitize_branch_name("feature/my-branch_v1.0") == "feature/my-branch_v1.0"

    def test_sanitize_branch_name_removes_special_chars(self) -> None:
        assert sanitize_branch_name("feature@#$%branch") == "feature-branch"
