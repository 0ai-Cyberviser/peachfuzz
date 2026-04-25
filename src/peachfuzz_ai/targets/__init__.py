"""Fuzz targets registry."""
from __future__ import annotations

from collections.abc import Callable
import json
from typing import Any

from .json_loose import json_loose_target

CRASH_SENTINEL = b"PEACHFUZZ_CRASH_SENTINEL"


def _loads_object(data: bytes) -> dict[str, Any]:
    obj: Any = json.loads(data)
    if not isinstance(obj, dict):
        raise TypeError("top-level JSON must be object")
    return obj


def json_api_target(data: bytes) -> None:
    obj = _loads_object(data)
    endpoint = obj.get("endpoint")
    if endpoint == "/internal/diagnostics" and obj.get("auth") is False:
        raise PermissionError("unauthenticated internal diagnostics are not allowed")
    json_loose_target(data)


def bytes_target(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("target input must be bytes")
    if CRASH_SENTINEL in data:
        raise ValueError("synthetic crash sentinel reached")


def findings_target(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("target input must be bytes")
    text = data.decode("utf-8", errors="replace")
    blocked_markers = ("EXECUTE:", "RUN_SHELL:", "CALLBACK_URL=", "PRIVATE_KEY=")
    if any(marker in text.upper() for marker in blocked_markers):
        raise PermissionError("finding payload attempted unsafe executor routing")


def openapi_target(data: bytes) -> None:
    obj = _loads_object(data)
    if not isinstance(obj.get("openapi"), str):
        raise ValueError("OpenAPI document must include an openapi version string")
    paths = obj.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("OpenAPI document must include paths")
    for path, operations in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("OpenAPI paths must be absolute local paths")
        if not isinstance(operations, dict):
            raise ValueError("OpenAPI path operations must be objects")


def graphql_target(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("GraphQL document cannot be empty")
    if text.count("{") != text.count("}"):
        raise ValueError("GraphQL document has unbalanced braces")
    if not (
        text.startswith("query")
        or text.startswith("mutation")
        or text.startswith("{")
        or text.startswith("fragment")
    ):
        raise ValueError("GraphQL document must start with query, mutation, fragment, or selection set")


def webhook_target(data: bytes) -> None:
    obj = _loads_object(data)
    if not isinstance(obj.get("event"), str) or not obj["event"]:
        raise ValueError("webhook event must be a non-empty string")
    headers = obj.get("headers", {})
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("webhook headers must be an object")


_TARGETS: dict[str, Callable[[bytes], None]] = {
    "json_loose": json_loose_target,
    "json": json_api_target,
    "json_api": json_api_target,
    "bytes": bytes_target,
    "findings": findings_target,
    "openapi": openapi_target,
    "graphql": graphql_target,
    "webhook": webhook_target,
}


def target_names() -> list[str]:
    return sorted(_TARGETS)


def get_target(name: str) -> Callable[[bytes], None]:
    try:
        return _TARGETS[name]
    except KeyError as exc:
        raise ValueError(f"unknown target: {name}") from exc


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
