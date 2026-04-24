import json

from peachfuzz_ai.backends import (
    BackendRunRequest,
    backend_matrix_json,
    backend_matrix_markdown,
    backend_names,
    get_backend,
)
from peachfuzz_ai.targets import get_target


def test_backend_registry_safe_defaults():
    assert "deterministic" in backend_names()
    assert "external-sandbox" not in backend_names()
    assert "external-sandbox" in backend_names(include_unsafe=True)


def test_backend_matrix_mentions_safety():
    matrix = backend_matrix_markdown(include_unsafe=True)
    assert "deterministic" in matrix
    assert "external-sandbox" in matrix
    assert "Requires sandbox" in matrix


def test_backend_matrix_json_serializable():
    data = backend_matrix_json(include_unsafe=True)
    assert any(item["name"] == "deterministic" for item in data)
    json.dumps(data)


def test_deterministic_backend_runs(tmp_path):
    backend = get_backend("deterministic")
    outcome = backend.run(
        BackendRunRequest(
            target_name="findings",
            target=get_target("findings"),
            corpus=[b"INFORMATIONAL: ok"],
            runs=5,
            report_dir=tmp_path,
        )
    )
    assert outcome.status == "ok"
    assert outcome.result is not None
    assert outcome.result.iterations == 5
    assert (tmp_path / "findings-summary.json").exists()


def test_external_backend_blocks_by_default(tmp_path):
    backend = get_backend("external-sandbox")
    outcome = backend.run(
        BackendRunRequest(
            target_name="bytes",
            target=get_target("bytes"),
            corpus=[b"seed"],
            runs=1,
            report_dir=tmp_path,
        )
    )
    assert outcome.status == "blocked"
    assert not outcome.ok
    assert "sandboxed executor" in outcome.detail


def test_atheris_backend_metadata():
    backend = get_backend("atheris")
    assert backend.capabilities.coverage_guided
    assert backend.capabilities.in_process
