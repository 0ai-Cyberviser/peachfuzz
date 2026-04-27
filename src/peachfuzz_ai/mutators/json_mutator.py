"""JSON mutation utilities for adversarial fuzzing.

This module provides attack payloads and mutation functions for generating
malformed JSON inputs to test parser robustness.
"""
from __future__ import annotations

import json
import random
import string
from typing import Any

ATTACK_PAYLOADS: list[dict[str, Any]] = [
    {"endpoint": "../../etc/passwd"},
    {"endpoint": "//evil.example"},
    {"endpoint": "http://127.0.0.1"},
    {"endpoint": "javascript:alert(1)"},
    {"endpoint": ""},
    {"endpoint": None},
    {"endpoint": 123},
    {"endpoint": True},
    {"endpoint": ["nested", "list"]},
    {"endpoint": {"deep": "object"}},
]


def rand_str(length: int = 8) -> str:
    """Generate a random string of alphanumeric characters and symbols.

    Args:
        length: Length of the random string. Defaults to 8.

    Returns:
        Random string containing letters, digits, and path characters.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits + "/._-", k=length))


def deep_nest(depth: int = 10) -> dict[str, Any]:
    """Create a deeply nested JSON structure for parser stress testing.

    Args:
        depth: Number of nesting levels. Defaults to 10.

    Returns:
        Dictionary with nested body structures to test recursion limits.
    """
    root: dict[str, Any] = {"endpoint": "/v1/workflows"}
    cur = root
    for i in range(depth):
        cur["body"] = {"level": i}
        cur = cur["body"]
    return root


def mutate_json(payload: str) -> str:
    """Apply random mutations to a JSON payload for fuzzing.

    Randomly selects from attack payloads, deep nesting, or
    structural mutations to generate test inputs.

    Args:
        payload: JSON string to mutate.

    Returns:
        Mutated JSON string.
    """
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        data = {"endpoint": payload[:32] or "/v1/workflows"}

    roll = random.random()

    # Inject attack payloads (25% probability)
    if roll < 0.25:
        return json.dumps(random.choice(ATTACK_PAYLOADS))

    # Deep nesting for parser stress (20% probability)
    if roll < 0.45:
        return json.dumps(deep_nest(random.randint(5, 20)))

    # Structured mutation (55% probability)
    if isinstance(data, dict):
        data[rand_str()] = rand_str()

        if "endpoint" in data:
            data["endpoint"] = random.choice([
                rand_str(),
                "",
                None,
                123,
                True,
                ["bad"],
                {"bad": "shape"}
            ])

        for k in list(data.keys()):
            if random.random() < 0.2:
                data[k] = random.choice([rand_str(), None, 0, [], {}, True])

    elif isinstance(data, list):
        data.append(random.choice([rand_str(), None, 0, {}, []]))

    else:
        data = {"endpoint": data}

    return json.dumps(data)


__all__ = [
    "ATTACK_PAYLOADS",
    "deep_nest",
    "mutate_json",
    "rand_str",
]
