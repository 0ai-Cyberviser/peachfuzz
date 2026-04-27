"""Tests for the PeachFuzz AI CLI."""
import json
from pathlib import Path

import pytest

from peachfuzz_ai.cli import main


class TestCLIRun:
    """Tests for the 'run' subcommand."""

    def test_cli_run_smoke(self, tmp_path: Path) -> None:
        rc = main(["run", "--target", "findings", "--runs", "3", "--report-dir", str(tmp_path)])
        assert rc == 0

    def test_cli_run_with_fail_on_crash(self, tmp_path: Path) -> None:
        rc = main(["run", "--target", "findings", "--runs", "3", "--report-dir", str(tmp_path), "--fail-on-crash"])
        assert rc == 0

    def test_cli_run_with_custom_seed(self, tmp_path: Path) -> None:
        rc = main(["run", "--target", "findings", "--runs", "3", "--report-dir", str(tmp_path), "--seed", "42"])
        assert rc == 0


class TestCLIPeachtrace:
    """Tests for the 'peachtrace' subcommand."""

    def test_cli_peachtrace_smoke(self, tmp_path: Path) -> None:
        rc = main(["peachtrace", "--target", "findings", "--runs", "3", "--report-dir", str(tmp_path)])
        assert rc == 0


class TestCLIBackends:
    """Tests for the 'backends' subcommand."""

    def test_cli_backends_smoke(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["backends"])
        assert rc == 0
        assert "deterministic" in capsys.readouterr().out

    def test_cli_backends_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["backends", "--format", "json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)

    def test_cli_backends_include_unsafe(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["backends", "--include-unsafe"])
        assert rc == 0


class TestCLIEditions:
    """Tests for the 'editions' subcommand."""

    def test_cli_editions_smoke(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["editions"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "PeachFuzz" in out or "CactusFuzz" in out


class TestCLIRadar:
    """Tests for the 'radar' subcommand."""

    def test_cli_radar_markdown(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["radar"])
        assert rc == 0

    def test_cli_radar_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["radar", "--format", "json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)


class TestCLIRoadmap:
    """Tests for the 'roadmap' subcommand."""

    def test_cli_roadmap_markdown(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["roadmap"])
        assert rc == 0

    def test_cli_roadmap_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["roadmap", "--format", "json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)


class TestCLIRefine:
    """Tests for the 'refine' subcommand."""

    def test_cli_refine_smoke(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output = tmp_path / "PLAN.md"
        rc = main(["refine", "--report-dir", str(tmp_path), "--output", str(output)])
        assert rc == 0
        assert output.exists()


class TestCLISchemas:
    """Tests for the 'schemas' subcommand."""

    def test_cli_schemas_smoke(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_dir = tmp_path / "corpus"
        rc = main(["schemas", "--output", str(output_dir), "--count", "2"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "output_dir" in data


class TestCLIMinimizeReports:
    """Tests for the 'minimize-reports' subcommand."""

    def test_cli_minimize_reports_empty(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["minimize-reports", "--report-dir", str(tmp_path), "--output", str(tmp_path / "min")])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["count"] == 0
        assert "no crash dir found" in data.get("message", "")


class TestCLIMinimize:
    """Tests for the 'minimize' subcommand error handling."""

    def test_cli_minimize_missing_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Minimize should return error code 2 for missing payload file."""
        missing = tmp_path / "nonexistent.bin"
        rc = main(["minimize", "--target", "bytes", "--output", str(tmp_path), str(missing)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "not found" in err.lower() or "error" in err.lower()


class TestCLIReproduce:
    """Tests for the 'reproduce' subcommand error handling."""

    def test_cli_reproduce_missing_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Reproduce should return error code 2 for missing payload file."""
        missing = tmp_path / "nonexistent.bin"
        rc = main(["reproduce", "--target", "bytes", "--output", str(tmp_path), str(missing)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "not found" in err.lower() or "error" in err.lower()


class TestCLICorpusStats:
    """Tests for the 'corpus-stats' subcommand."""

    def test_corpus_stats_empty_dir(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """corpus-stats on empty dir should report zero files."""
        rc = main(["corpus-stats", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["total_files"] == 0
        assert "no corpus files found" in data.get("message", "")

    def test_corpus_stats_with_files(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """corpus-stats should report file statistics."""
        (tmp_path / "json.txt").write_bytes(b'{"endpoint": "/v1/test"}')
        (tmp_path / "graphql.txt").write_bytes(b"query { users { name } }")
        rc = main(["corpus-stats", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["total_files"] == 2
        assert data["total_bytes"] > 0
        assert "content_analysis" in data
