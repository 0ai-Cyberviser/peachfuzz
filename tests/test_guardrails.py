import pytest

from peachfuzz_ai.guardrails import classify_finding_text, validate_local_only_url, validate_target_name


def test_validate_target_name():
    assert validate_target_name("json") == "json"
    with pytest.raises(ValueError):
        validate_target_name("nmap")


def test_classify_finding_text_hancock_routes():
    assert classify_finding_text("VULNERABILITY_CONFIRMED: CVE-2021-44228 on 192.168.1.1") == "human_intervention"
    assert classify_finding_text("VULNERABILITY_CONFIRMED: CVE-2021-44228 on 192.168.1.1", authorized=True) == "executor"
    assert classify_finding_text("VULNERABILITY_CONFIRMED: Fake-Exploit-999") == "reporter"
    assert classify_finding_text("INSUFFICIENT_DATA: Port 80 filtered") == "recon"
    assert classify_finding_text("INFORMATIONAL: Scan completed") == "reporter"


def test_validate_local_only_url():
    assert validate_local_only_url("/tmp/corpus")
    assert validate_local_only_url("file:///tmp/corpus")
    assert not validate_local_only_url("https://example.com/corpus")
