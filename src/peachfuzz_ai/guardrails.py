"""Defensive guardrails for harness execution."""
from __future__ import annotations

import re
import functools
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@functools.lru_cache(maxsize=1)
def _get_allowed_targets() -> frozenset[str]:
    """Load allowed targets from the registry.

    Uses lru_cache for thread-safe memoization, avoiding explicit global state.
    """
    from .targets import target_names
    return frozenset(target_names())


def validate_target_name(target_name: str) -> str:
    """Allow only local registered targets."""
    cleaned = (target_name or "").strip().lower()
    allowed = _get_allowed_targets()
    if cleaned not in allowed:
        raise ValueError(f"Unknown target '{target_name}'. Valid targets: {sorted(allowed)}")
    return cleaned


def classify_finding_text(text: str, authorized: bool = False) -> str:
    """Route a finding using Hancock-style critic logic.

    This is parser/safety logic only. It never executes exploits or tools.
    """
    text = text or ""
    has_cve = bool(_CVE_RE.search(text))
    has_ip = bool(_IPV4_RE.search(text))
    if "VULNERABILITY_CONFIRMED" in text:
        if has_cve and has_ip:
            return "executor" if authorized else "human_intervention"
        return "reporter"
    if "INSUFFICIENT_DATA" in text:
        return "recon"
    return "reporter"


def validate_local_only_url(url: str) -> bool:
    """Accept only file URLs or local paths for corpus-like resources."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return True
    return parsed.scheme == "file"


__all__ = [
    "classify_finding_text",
    "validate_local_only_url",
    "validate_target_name",
]
