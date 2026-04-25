"""Fuzz targets registry."""
from __future__ import annotations

from collections.abc import Callable

from .json_loose import json_loose_target


def json_api_target(data: bytes) -> None:
    """Compatibility target for JSON/API parser tests."""
    json_loose_target(data)


def bytes_target(data: bytes) -> None:
    """Compatibility target that accepts arbitrary bytes."""
    if not isinstance(data, bytes):
        raise TypeError("target input must be bytes")


def findings_target(data: bytes) -> None:
    """Compatibility target for finding-shaped payloads."""
    json_loose_target(data)


_TARGETS: dict[str, Callable[[bytes], None]] = {
    "json_loose": json_loose_target,
    "json": json_api_target,
    "json_api": json_api_target,
    "bytes": bytes_target,
    "findings": findings_target,
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
    "json_api_target",
    "json_loose_target",
    "target_names",
]
