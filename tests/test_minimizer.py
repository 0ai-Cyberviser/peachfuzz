from pathlib import Path
import json

from peachfuzz_ai.cli import main
from peachfuzz_ai.minimizer import CrashSignature, DeltaMinimizer, MinimizeRequest, MinimizeResult, write_minimized_result
from peachfuzz_ai.targets import get_target


class TestMinimizeResult:
    """Tests for MinimizeResult class."""

    def test_reduction_percent_zero_original(self):
        result = MinimizeResult(
            target_name="test",
            original_size=0,
            minimized_size=0,
            original_sha256="abc",
            minimized_sha256="abc",
            attempts=0,
            changed=False,
            reproduced=False,
            signature=CrashSignature("Ex", "msg"),
            payload_preview="",
        )
        assert result.reduction_percent == 0.0

    def test_reduction_bytes(self):
        result = MinimizeResult(
            target_name="test",
            original_size=100,
            minimized_size=40,
            original_sha256="abc",
            minimized_sha256="def",
            attempts=5,
            changed=True,
            reproduced=True,
            signature=CrashSignature("Ex", "msg"),
            payload_preview="...",
        )
        assert result.reduction_bytes == 60
        assert result.reduction_percent == 60.0


class TestDeltaMinimizer:
    """Tests for DeltaMinimizer class."""

    def test_minimizer_reduces_bytes_sentinel(self):
        payload = b"PEACHFUZZ_CRASH_SENTINEL trailing data that can be removed"
        minimizer = DeltaMinimizer(get_target("bytes"), "bytes")
        result, minimized = minimizer.minimize(
            MinimizeRequest(
                target_name="bytes",
                payload=payload,
                signature=CrashSignature("ValueError", "synthetic crash sentinel reached"),
            )
        )
        assert result.reproduced
        assert len(minimized) < len(payload)
        assert minimized.startswith(b"PEACHFUZZ_CRASH_SENTINEL")

    def test_minimizer_reduces_graphql_unbalanced(self):
        payload = b"query FindingList { findings { severity title }"
        minimizer = DeltaMinimizer(get_target("graphql"), "graphql")
        result, minimized = minimizer.minimize(
            MinimizeRequest(
                target_name="graphql",
                payload=payload,
                signature=CrashSignature("ValueError", "graphql braces are unbalanced"),
            )
        )
        assert result.reproduced
        assert len(minimized) < len(payload)

    def test_infer_signature(self):
        minimizer = DeltaMinimizer(get_target("bytes"), "bytes")
        sig = minimizer.infer_signature(b"PEACHFUZZ_CRASH_SENTINEL")
        assert sig.exception_type == "ValueError"
        assert "synthetic crash sentinel" in sig.message_substring

    def test_minimizer_non_reproducing_payload(self):
        """Test minimizer when initial payload doesn't reproduce crash."""
        payload = b"this payload does not crash the target"
        minimizer = DeltaMinimizer(get_target("bytes"), "bytes")
        result, minimized = minimizer.minimize(
            MinimizeRequest(
                target_name="bytes",
                payload=payload,
                signature=CrashSignature("ValueError", "synthetic crash sentinel reached"),
            )
        )
        assert result.reproduced is False
        assert result.changed is False
        assert minimized == payload


def test_write_minimized_result(tmp_path: Path):
    payload = b"PEACHFUZZ_CRASH_SENTINEL"
    minimizer = DeltaMinimizer(get_target("bytes"), "bytes")
    result, minimized = minimizer.minimize(MinimizeRequest(target_name="bytes", payload=payload))
    payload_path, json_path = write_minimized_result(result, minimized, tmp_path)
    assert payload_path.exists()
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["reproduced"] is True


def test_cli_minimize(tmp_path: Path, capsys):
    payload = tmp_path / "crash.bin"
    payload.write_bytes(b"PEACHFUZZ_CRASH_SENTINEL trailing data")
    out_dir = tmp_path / "minimized"
    rc = main(["minimize", "--target", "bytes", "--output", str(out_dir), str(payload)])
    assert rc == 0
    assert list(out_dir.glob("bytes-*.bin"))
    assert '"reproduced": true' in capsys.readouterr().out


def test_cli_minimize_reports_bulk(tmp_path: Path, capsys):
    crash_dir = tmp_path / "reports" / "crashes"
    crash_dir.mkdir(parents=True)
    payload = crash_dir / "bytes-example.bin"
    payload.write_bytes(b"PEACHFUZZ_CRASH_SENTINEL trailing data")
    (crash_dir / "bytes-example.json").write_text(
        json.dumps(
            {
                "target_name": "bytes",
                "exception_type": "ValueError",
                "message": "synthetic crash sentinel reached",
            }
        ),
        encoding="utf-8",
    )

    rc = main([
        "minimize-reports",
        "--report-dir",
        str(tmp_path / "reports"),
        "--output",
        str(tmp_path / "minimized"),
        "--reproducer-output",
        str(tmp_path / "regression"),
        "--generate-reproducers",
    ])
    assert rc == 0
    assert list((tmp_path / "minimized").glob("bytes-*.bin"))
    assert list((tmp_path / "regression").glob("test_repro_*.py"))
    assert '"count": 1' in capsys.readouterr().out
