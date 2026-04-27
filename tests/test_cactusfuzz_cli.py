"""Tests for CactusFuzz CLI."""
import json
from pathlib import Path

import pytest

from cactusfuzz.cli import main


class TestCactusFuzzCLI:
    """Tests for cactusfuzz CLI main function."""

    def test_default_run(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test default CLI run produces JSON output."""
        rc = main([])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_agent_guardrails_pack_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test agent-guardrails pack with JSON format."""
        main(["--pack", "agent-guardrails", "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "results" in data
        assert "ok" in data

    def test_agent_guardrails_pack_markdown(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test agent-guardrails pack with markdown format."""
        main(["--pack", "agent-guardrails", "--format", "markdown"])
        captured = capsys.readouterr()
        assert "GuardrailOracle" in captured.out or "##" in captured.out

    def test_output_to_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test writing output to a file."""
        output_file = tmp_path / "output.json"
        rc = main(["--output", str(output_file)])
        assert rc == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert isinstance(data, list)

    def test_agent_guardrails_output_to_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test agent-guardrails pack output to file."""
        output_file = tmp_path / "report.json"
        main(["--pack", "agent-guardrails", "--output", str(output_file)])
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "results" in data
        assert "ok" in data

    def test_custom_scope(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test with custom scope."""
        rc = main(["--scope", "local-lab", "--scope", "test.example.com"])
        assert rc == 0

    def test_custom_operator(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test with custom operator."""
        rc = main(["--operator", "test-operator"])
        assert rc == 0
