"""Tests for the JSON mutator module."""
from __future__ import annotations

import json

from peachfuzz_ai.mutators.json_mutator import (
    ATTACK_PAYLOADS,
    deep_nest,
    mutate_json,
    rand_str,
)


class TestRandStr:
    """Tests for rand_str function."""

    def test_default_length(self) -> None:
        """Default length should be 8 characters."""
        result = rand_str()
        assert len(result) == 8

    def test_custom_length(self) -> None:
        """Custom length should be respected."""
        result = rand_str(length=16)
        assert len(result) == 16

    def test_returns_string(self) -> None:
        """Should return a string."""
        result = rand_str()
        assert isinstance(result, str)


class TestDeepNest:
    """Tests for deep_nest function."""

    def test_default_depth(self) -> None:
        """Default depth should create nested structure."""
        result = deep_nest()
        assert result["endpoint"] == "/v1/workflows"
        assert "body" in result

    def test_custom_depth(self) -> None:
        """Custom depth should create specified nesting."""
        result = deep_nest(depth=3)
        assert result["endpoint"] == "/v1/workflows"
        cur = result
        for i in range(3):
            assert "body" in cur
            assert cur["body"]["level"] == i
            cur = cur["body"]

    def test_valid_endpoint(self) -> None:
        """Should have valid endpoint."""
        result = deep_nest()
        assert result["endpoint"].startswith("/")


# Number of iterations for mutation tests to ensure coverage of random branches
MUTATION_TEST_ITERATIONS = 20


class TestMutateJson:
    """Tests for mutate_json function."""

    def test_returns_valid_json(self) -> None:
        """Output should be valid JSON."""
        payload = json.dumps({"endpoint": "/v1/test"})
        for _ in range(MUTATION_TEST_ITERATIONS // 2):
            result = mutate_json(payload)
            # Should parse without error
            json.loads(result)

    def test_handles_invalid_json_input(self) -> None:
        """Should handle invalid JSON input gracefully."""
        result = mutate_json("not valid json")
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_handles_empty_string(self) -> None:
        """Should handle empty string input."""
        result = mutate_json("")
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_mutates_dict_payload(self) -> None:
        """Should mutate dict payload through multiple random branches."""
        payload = json.dumps({"endpoint": "/test", "value": 123})
        for _ in range(MUTATION_TEST_ITERATIONS):
            result = mutate_json(payload)
            json.loads(result)  # Should be valid JSON

    def test_mutates_list_payload(self) -> None:
        """Should handle list payload."""
        payload = json.dumps([1, 2, 3])
        for _ in range(MUTATION_TEST_ITERATIONS // 2):
            result = mutate_json(payload)
            json.loads(result)


class TestAttackPayloads:
    """Tests for ATTACK_PAYLOADS constant."""

    def test_payloads_exist(self) -> None:
        """Should have attack payloads defined."""
        assert len(ATTACK_PAYLOADS) > 0

    def test_payloads_are_dicts(self) -> None:
        """All payloads should be dicts."""
        for payload in ATTACK_PAYLOADS:
            assert isinstance(payload, dict)

    def test_payloads_have_endpoint(self) -> None:
        """All payloads should have endpoint key."""
        for payload in ATTACK_PAYLOADS:
            assert "endpoint" in payload
