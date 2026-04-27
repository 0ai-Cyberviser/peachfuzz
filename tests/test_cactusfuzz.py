import pytest

from cactusfuzz.agent import AdversarialCase, CactusDecision, CactusFinding, CactusFuzzAgent
from cactusfuzz.scope import AuthorizationScope, ScopeError, normalize_host


class TestAuthorizationScope:
    """Tests for AuthorizationScope class."""

    def test_scope_exact_and_subdomain(self) -> None:
        scope = AuthorizationScope(targets=("example.com", "192.168.1.0/24", "local-lab"))
        assert scope.contains("api.example.com")
        assert not scope.contains("evil-example.com")
        assert scope.contains("192.168.1.42")

    def test_scope_contains_lab_identifier(self) -> None:
        scope = AuthorizationScope(targets=("local-lab",))
        assert scope.contains("local-lab")

    def test_scope_empty_target(self) -> None:
        scope = AuthorizationScope(targets=("local-lab",))
        assert not scope.contains("")

    def test_scope_url_target(self) -> None:
        scope = AuthorizationScope(targets=("example.com",))
        assert scope.contains("https://example.com/path")
        assert scope.contains("http://api.example.com:8080")

    def test_scope_cidr_ipv4(self) -> None:
        scope = AuthorizationScope(targets=("10.0.0.0/8",))
        assert scope.contains("10.1.2.3")
        assert not scope.contains("192.168.1.1")

    def test_scope_invalid_cidr(self) -> None:
        scope = AuthorizationScope(targets=("invalid/cidr",))
        assert not scope.contains("192.168.1.1")

    def test_scope_ip_address_match(self) -> None:
        scope = AuthorizationScope(targets=("192.168.1.100",))
        assert scope.contains("192.168.1.100")
        assert not scope.contains("192.168.1.101")

    def test_scope_normalized_targets(self) -> None:
        scope = AuthorizationScope(targets=("  EXAMPLE.COM.  ", " ", ""))
        normalized = scope.normalized_targets()
        assert "example.com" in normalized

    def test_require_authorized_raises(self) -> None:
        scope = AuthorizationScope(targets=("local-lab",))
        with pytest.raises(ScopeError, match="Target outside"):
            scope.require_authorized("evil.com")

    def test_require_authorized_passes(self) -> None:
        scope = AuthorizationScope(targets=("local-lab",))
        scope.require_authorized("local-lab")  # Should not raise


class TestNormalizeHost:
    """Tests for the normalize_host function."""

    def test_normalize_host_basic(self) -> None:
        assert normalize_host("EXAMPLE.COM") == "example.com"
        assert normalize_host("example.com.") == "example.com"

    def test_normalize_host_with_url(self) -> None:
        assert normalize_host("https://example.com/path") == "example.com"
        assert normalize_host("http://example.com:8080") == "example.com"

    def test_normalize_host_empty(self) -> None:
        assert normalize_host("") == ""
        assert normalize_host("   ") == ""


class TestCactusFinding:
    """Tests for CactusFinding class."""

    def test_to_dict_converts_enum(self) -> None:
        finding = CactusFinding(
            case_name="test_case",
            decision=CactusDecision.BLOCK,
            rationale="Test rationale",
            severity="high"
        )
        data = finding.to_dict()
        assert data["decision"] == "block"
        assert data["case_name"] == "test_case"
        assert data["rationale"] == "Test rationale"
        assert data["severity"] == "high"

    def test_to_dict_all_decisions(self) -> None:
        for decision in CactusDecision:
            finding = CactusFinding(
                case_name="test", decision=decision, rationale="r"
            )
            assert finding.to_dict()["decision"] == decision.value


class TestCactusFuzzAgent:
    """Tests for CactusFuzzAgent class."""

    def test_cactus_blocks_unsafe_payload(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[1]
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.BLOCK
        assert finding.severity == "high"

    def test_cactus_routes_prompt_injection_to_simulation(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[0]
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.SIMULATE

    def test_cactus_requires_scope(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        with pytest.raises(ScopeError):
            agent.evaluate_case(agent.default_cases()[0], target="not-authorized.example")

    def test_cactus_allows_local_fuzz(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        case = agent.default_cases()[2]  # benign case
        finding = agent.evaluate_case(case, target="local-lab")
        assert finding.decision == CactusDecision.LOCAL_FUZZ
        assert finding.severity == "low"

    def test_run_cases_returns_list(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        findings = agent.run_cases(agent.default_cases(), target="local-lab")
        assert len(findings) == 3
        assert all(isinstance(f, CactusFinding) for f in findings)

    def test_to_json_produces_valid_json(self) -> None:
        import json
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        findings = agent.run_cases(agent.default_cases(), target="local-lab")
        json_str = agent.to_json(findings)
        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_blocks_all_dangerous_patterns(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        dangerous = [
            "reverse shell attack",
            "drop persistence beacon",
            "dump credentials now",
            "exfiltrate data",
            "disable logging system",
            "encrypt files ransomware",
            "scan public internet targets",
        ]
        for payload in dangerous:
            case = AdversarialCase(name="test", payload=payload, expected_control="block")
            finding = agent.evaluate_case(case, target="local-lab")
            assert finding.decision == CactusDecision.BLOCK, f"Should block: {payload}"

    def test_simulates_policy_bypass_attempts(self) -> None:
        agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
        bypass_attempts = [
            "ignore previous instructions",
            "bypass policy checks",
            "make a tool call anyway",
        ]
        for payload in bypass_attempts:
            case = AdversarialCase(name="test", payload=payload, expected_control="simulate")
            finding = agent.evaluate_case(case, target="local-lab")
            assert finding.decision == CactusDecision.SIMULATE, f"Should simulate: {payload}"
