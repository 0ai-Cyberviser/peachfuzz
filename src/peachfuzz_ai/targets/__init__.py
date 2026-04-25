"""Fuzz targets registry."""
from __future__ import annotations

from collections.abc import Callable
import json

from .json_loose import json_loose_target


def _load_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def json_api_target(data: bytes) -> None:
    parsed = _load_json(data)
    if not isinstance(parsed, dict):
        raise ValueError("JSON API payload must be an object")

    endpoint = str(parsed.get("endpoint", ""))
    auth = parsed.get("auth", True)

    # Empty object is valid no-op corpus.
    if endpoint == "":
        return

    if not endpoint.startswith("/"):
        raise ValueError("JSON API endpoint must be a relative path")

    if endpoint.startswith("/internal/") and auth is False:
        raise PermissionError("unauthenticated internal diagnostics access")


def openapi_target(data: bytes) -> None:
    parsed = _load_json(data)
    if not isinstance(parsed, dict):
        raise ValueError("OpenAPI payload must be an object")
    if "openapi" not in parsed and "swagger" not in parsed:
        raise ValueError("OpenAPI payload must include openapi or swagger")
    if not isinstance(parsed.get("paths"), dict) or not parsed["paths"]:
        raise ValueError("OpenAPI payload must include non-empty object paths")


def webhook_target(data: bytes) -> None:
    parsed = _load_json(data)
    if not isinstance(parsed, dict):
        raise ValueError("webhook payload must be an object")
    if not isinstance(parsed.get("event"), str) or not parsed["event"]:
        raise ValueError("webhook payload must include event")
    if "body" not in parsed or not isinstance(parsed["body"], dict):
        raise ValueError("webhook payload must include object body")


def graphql_target(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore").strip()
    if not text:
        raise ValueError("empty GraphQL document")
    if not (
        text.startswith("query")
        or text.startswith("mutation")
        or text.startswith("fragment")
        or text.startswith("{")
    ):
        raise ValueError("unsupported GraphQL document")
    if "{" not in text or "}" not in text:
        raise ValueError("graphql braces are unbalanced")
    if text.count("{") != text.count("}"):
        raise ValueError("graphql braces are unbalanced")


def bytes_target(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("target input must be bytes")
    if b"PEACHFUZZ_CRASH_SENTINEL" in data:
        raise ValueError("synthetic crash sentinel reached")


def findings_target(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("target input must be bytes")


_TARGETS: dict[str, Callable[[bytes], None]] = {
    "bytes": bytes_target,
    "findings": findings_target,
    "graphql": graphql_target,
    "json": json_api_target,
    "json_api": json_api_target,
    "json_loose": json_loose_target,
    "openapi": openapi_target,
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
