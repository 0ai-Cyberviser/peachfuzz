"""Loose JSON target for deeper fuzz exploration."""
from __future__ import annotations

import json
from typing import Any


def json_loose_target(data: bytes) -> None:
    """Target that exercises more JSON edge cases for fuzz exploration.

    This target validates JSON API payloads with strict endpoint and body
    validation to catch common security issues like path traversal and
    external URL injection.

    Args:
        data: Raw bytes that should contain valid JSON.

    Raises:
        TypeError: If top-level is not object, endpoint has wrong type, or body key is invalid.
        KeyError: If endpoint key is missing.
        OverflowError: If endpoint is numeric.
        ValueError: If endpoint contains unsafe patterns.
        PermissionError: If endpoint references external URLs.
    """
    obj: Any = json.loads(data)

    if not isinstance(obj, dict):
        raise TypeError("top-level JSON must be object")

    endpoint = obj.get("endpoint")
    body = obj.get("body")

    if endpoint is None:
        raise KeyError("endpoint missing")

    if isinstance(endpoint, bool):
        raise TypeError("endpoint cannot be boolean")

    if isinstance(endpoint, int):
        raise OverflowError("endpoint numeric not allowed")

    if isinstance(endpoint, list):
        raise TypeError("endpoint cannot be list")

    if isinstance(endpoint, dict):
        raise TypeError("endpoint cannot be object")

    if isinstance(endpoint, str):
        if endpoint.startswith("javascript:"):
            raise ValueError("script scheme not allowed")

        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            raise PermissionError("external URL not allowed")

        if "../" in endpoint:
            raise ValueError("path traversal detected")

        if not endpoint.startswith("/"):
            raise ValueError("relative path not allowed")

    if isinstance(body, dict):
        for k, v in body.items():
            if not isinstance(k, str):
                raise TypeError("body key invalid")
            str(v)


__all__ = ["json_loose_target"]
