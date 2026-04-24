"""Local fuzz target adapters.

Targets are intentionally defensive and offline. They exercise parsing and
routing code paths without network access or exploit execution.
"""
from __future__ import annotations

import json
from typing import Callable

from .guardrails import classify_finding_text


def json_api_target(data: bytes) -> None:
    """Fuzz JSON API-like payload parsing."""
    if len(data) > 1_000_000:
        raise ValueError("input too large")

    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return

    if not isinstance(payload, dict):
        return

    endpoint = str(payload.get("endpoint", ""))
    body = payload.get("body", {})
    if endpoint and not endpoint.startswith("/"):
        raise ValueError("endpoint must be an absolute API path")

    if isinstance(body, dict):
        # Exercise nested serialization boundaries.
        json.dumps(body, sort_keys=True)

    # Regression sentinel: real parser bugs should not crash, but this branch
    # models detection of unsafe schema transitions during tests.
    if payload.get("endpoint") == "/internal/diagnostics" and payload.get("auth") is False:
        raise PermissionError("unauthenticated diagnostics path reached")


def findings_target(data: bytes) -> None:
    """Fuzz Hancock-style critic routing text."""
    text = data.decode("utf-8", errors="replace")
    route = classify_finding_text(text, authorized=False)
    if route == "executor":
        raise PermissionError("unauthorized finding routed to executor")


def bytes_target(data: bytes) -> None:
    """Generic byte target for encoding and boundary coverage."""
    if data.startswith(b"PEACHFUZZ_CRASH_SENTINEL"):
        raise ValueError("synthetic crash sentinel reached")
    data.decode("utf-8", errors="ignore")


_TARGETS: dict[str, Callable[[bytes], None]] = {
    "json": json_api_target,
    "findings": findings_target,
    "bytes": bytes_target,
}


def get_target(name: str) -> Callable[[bytes], None]:
    """Return a target callable by name."""
    try:
        return _TARGETS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown fuzz target: {name}") from exc


def target_names() -> list[str]:
    return sorted(_TARGETS)
