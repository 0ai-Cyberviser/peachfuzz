from pathlib import Path

from peachfuzz_ai.engine import PeachFuzzEngine, load_corpus
from peachfuzz_ai.targets import get_target


def test_engine_records_permission_crash(tmp_path: Path):
    engine = PeachFuzzEngine(get_target("json"), "json", report_dir=tmp_path, seed=1)
    finding = engine.run_one(b'{"endpoint":"/internal/diagnostics","auth":false}', 1)
    assert finding is not None
    assert finding.exception_type == "PermissionError"
    assert (tmp_path / "crashes").exists()


def test_engine_run_writes_summary(tmp_path: Path):
    engine = PeachFuzzEngine(get_target("findings"), "findings", report_dir=tmp_path, seed=2)
    result = engine.run([b"INFORMATIONAL: ok"], runs=5)
    assert result.iterations == 5
    assert (tmp_path / "findings-summary.json").exists()


def test_load_corpus(tmp_path: Path):
    sample = tmp_path / "seed.txt"
    sample.write_bytes(b"seed")
    assert load_corpus([tmp_path]) == [b"seed"]
