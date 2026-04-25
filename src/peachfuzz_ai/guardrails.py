"""Defensive guardrails for harness execution."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _allowed_targets() -> set[str]:
    """Resolve allowed targets from the runtime registry to avoid drift."""
    from .targets import target_names

    return set(target_names())


def validate_target_name(target_name: str) -> str:
    """Allow only locally registered targets."""
    cleaned = (target_name or "").strip().lower()
    allowed = _allowed_targets()
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
