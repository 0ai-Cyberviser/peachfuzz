from peachfuzz_ai.cli import main


def test_cli_run_smoke(tmp_path):
    rc = main(["run", "--target", "findings", "--runs", "3", "--report-dir", str(tmp_path)])
    assert rc == 0


def test_cli_backends_smoke(capsys):
    rc = main(["backends"])
    assert rc == 0
    assert "deterministic" in capsys.readouterr().out
