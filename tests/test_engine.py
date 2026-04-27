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


def test_load_corpus_empty_file_skipped(tmp_path: Path):
    """Empty files should be skipped in corpus loading."""
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    non_empty = tmp_path / "data.txt"
    non_empty.write_bytes(b"content")
    result = load_corpus([tmp_path])
    assert result == [b"content"]


def test_load_corpus_missing_path_skipped(tmp_path: Path):
    """Missing paths should be silently skipped."""
    valid = tmp_path / "seed.txt"
    valid.write_bytes(b"seed")
    missing = tmp_path / "nonexistent"
    result = load_corpus([valid, missing])
    assert result == [b"seed"]


def test_load_corpus_empty_list():
    """Empty path list should return empty corpus."""
    assert load_corpus([]) == []


def test_load_corpus_nested_directories(tmp_path: Path):
    """Corpus loading should only read direct children, not recurse."""
    (tmp_path / "direct.txt").write_bytes(b"direct")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "child.txt").write_bytes(b"child")
    result = load_corpus([tmp_path])
    # Only direct.txt should be loaded, nested is a directory
    assert result == [b"direct"]

