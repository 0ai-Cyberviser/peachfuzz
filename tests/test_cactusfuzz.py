import pytest

from cactusfuzz.agent import CactusDecision, CactusFuzzAgent
from cactusfuzz.scope import AuthorizationScope, ScopeError


def test_scope_exact_and_subdomain():
    scope = AuthorizationScope(targets=("example.com", "192.168.1.0/24", "local-lab"))
    assert scope.contains("api.example.com")
    assert not scope.contains("evil-example.com")
    assert scope.contains("192.168.1.42")


def test_cactus_blocks_unsafe_payload():
    agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
    case = agent.default_cases()[1]
    finding = agent.evaluate_case(case, target="local-lab")
    assert finding.decision == CactusDecision.BLOCK
    assert finding.severity == "high"


def test_cactus_routes_prompt_injection_to_simulation():
    agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
    case = agent.default_cases()[0]
    finding = agent.evaluate_case(case, target="local-lab")
    assert finding.decision == CactusDecision.SIMULATE


def test_cactus_requires_scope():
    agent = CactusFuzzAgent(AuthorizationScope(targets=("local-lab",)))
    with pytest.raises(ScopeError):
        agent.evaluate_case(agent.default_cases()[0], target="not-authorized.example")
