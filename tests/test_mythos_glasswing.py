import json
from pathlib import Path

from peachfuzz_ai.personas import MYTHOS_GLASSWING, system_prompt
from peachfuzz_ai.self_refine import SelfRefinementEngine, sanitize_branch_name


def test_persona_guardrails_are_proposal_only():
    prompt = system_prompt()
    assert "Never auto-merge" in prompt
    assert "Never perform network scanning" in prompt
    assert MYTHOS_GLASSWING.codename == "mythos-glasswing"


def test_self_refinement_plan_from_summary(tmp_path: Path):
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


def test_write_plan_outputs_markdown_and_json(tmp_path: Path):
    engine = SelfRefinementEngine(report_dir=tmp_path / "missing")
    out = engine.write_plan(tmp_path / "PLAN.md")
    assert out.exists()
    assert out.with_suffix(".json").exists()
    assert "Human review required" in out.read_text(encoding="utf-8")


def test_sanitize_branch_name():
    assert sanitize_branch_name("Mythos Glasswing Update!!") == "mythos-glasswing-update"
