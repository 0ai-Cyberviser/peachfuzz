"""Fuzz targets registry.

Targets are intentionally defensive and offline. They exercise parsing and
routing code paths without network access or exploit execution.
"""
from __future__ import annotations

import json
from typing import Callable

from ..guardrails import classify_finding_text
from .json_loose import json_loose_target


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
        json.dumps(body, sort_keys=True)

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


def openapi_target(data: bytes) -> None:
    """Fuzz OpenAPI JSON document parsing."""
    if len(data) > 2_000_000:
        raise ValueError("input too large")

    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return

    if not isinstance(payload, dict):
        return
    if "openapi" not in payload:
        return

    paths = payload.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("openapi paths must be an object")
    for path, operations in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("openapi path keys must be absolute paths")
        if not isinstance(operations, dict):
            raise ValueError("openapi path item must be an object")


def graphql_target(data: bytes) -> None:
    """Fuzz GraphQL document parsing heuristics without executing queries."""
    text = data.decode("utf-8", errors="replace")
    if len(text) > 1_000_000:
        raise ValueError("input too large")
    stripped = text.strip()
    if not stripped:
        return

    if stripped.count("{") != stripped.count("}"):
        raise ValueError("graphql braces are unbalanced")
    if "__schema" in stripped and "{" not in stripped:
        raise ValueError("graphql introspection token without selection set")


def webhook_target(data: bytes) -> None:
    """Fuzz local webhook envelope parsing."""
    if len(data) > 1_000_000:
        raise ValueError("input too large")

    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return

    if not isinstance(payload, dict):
        return
    event = payload.get("event", "")
    headers = payload.get("headers", {})
    body = payload.get("body", {})

    if event and not isinstance(event, str):
        raise ValueError("webhook event must be a string")
    if headers and not isinstance(headers, dict):
        raise ValueError("webhook headers must be an object")
    if body and not isinstance(body, dict):
        raise ValueError("webhook body must be an object")


_TARGETS: dict[str, Callable[[bytes], None]] = {
    "json": json_api_target,
    "findings": findings_target,
    "bytes": bytes_target,
    "openapi": openapi_target,
    "graphql": graphql_target,
    "webhook": webhook_target,
    "json_loose": json_loose_target,
}


def get_target(name: str) -> Callable[[bytes], None]:
    """Return a target callable by name."""
    try:
        return _TARGETS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown fuzz target: {name}") from exc


def target_names() -> list[str]:
    return sorted(_TARGETS)


__all__ = [
    "bytes_target",
    "findings_target",
    "get_target",
    "graphql_target",
    "json_api_target",
    "json_loose_target",
    "openapi_target",
    "target_names",
    "webhook_target",
]
