from pathlib import Path
import importlib.util

from peachfuzz_ai.cli import main
from peachfuzz_ai.minimizer import CrashSignature
from peachfuzz_ai.reproducer import (
    ReproducerRequest,
    render_pytest_reproducer,
    sanitize_identifier,
    write_pytest_reproducer,
)


def test_sanitize_identifier():
    assert sanitize_identifier("GraphQL Crash!!") == "graphql_crash"
    assert sanitize_identifier("123") == "_123"


def test_sanitize_identifier_edge_cases():
    """Test edge cases for sanitize_identifier function."""
    # Empty string should return 'payload'
    assert sanitize_identifier("") == "payload"
    # Whitespace only should return 'payload'
    assert sanitize_identifier("   ") == "payload"
    # Special characters only should return 'payload'
    assert sanitize_identifier("@#$%^&*") == "payload"
    # Single underscore only
    assert sanitize_identifier("_") == "payload"
    # Leading underscore is stripped by design (strip("_"))
    assert sanitize_identifier("_valid") == "valid"
    # Multiple leading digits get underscore prefix
    assert sanitize_identifier("999test") == "_999test"
    # Mixed with valid chars
    assert sanitize_identifier("test_123_value") == "test_123_value"



def test_render_pytest_reproducer_contains_base64_payload():
    content = render_pytest_reproducer(
        ReproducerRequest(
            target_name="bytes",
            payload=b"PEACHFUZZ_CRASH_SENTINEL",
            signature=CrashSignature("ValueError", "synthetic crash sentinel reached"),
        )
    )
    assert "base64.b64decode" in content
    assert "get_target('bytes')" in content or 'get_target("bytes")' in content


def test_write_pytest_reproducer_file(tmp_path: Path):
    result = write_pytest_reproducer(
        ReproducerRequest(
            target_name="bytes",
            payload=b"PEACHFUZZ_CRASH_SENTINEL",
            signature=CrashSignature("ValueError", "synthetic crash sentinel reached"),
        ),
        output_dir=tmp_path,
    )
    path = Path(result.output_path)
    assert path.exists()
    assert "test_repro_bytes_valueerror" in result.test_name


def test_generated_pytest_reproducer_passes(tmp_path: Path):
    result = write_pytest_reproducer(
        ReproducerRequest(
            target_name="bytes",
            payload=b"PEACHFUZZ_CRASH_SENTINEL",
            signature=CrashSignature("ValueError", "synthetic crash sentinel reached"),
        ),
        output_dir=tmp_path,
    )
    spec = importlib.util.spec_from_file_location("generated_reproducer", result.output_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    getattr(module, result.test_name)()


def test_cli_reproduce(tmp_path: Path, capsys):
    payload = tmp_path / "crash.bin"
    payload.write_bytes(b"PEACHFUZZ_CRASH_SENTINEL")
    out_dir = tmp_path / "regression"
    rc = main(["reproduce", "--target", "bytes", "--output", str(out_dir), str(payload)])
    assert rc == 0
    assert list(out_dir.glob("test_repro_*.py"))
    assert '"target_name": "bytes"' in capsys.readouterr().out
