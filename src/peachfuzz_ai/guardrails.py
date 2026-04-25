"""Defensive guardrails for harness execution."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ALLOWED_TARGETS = {"json", "findings", "bytes", "openapi", "graphql", "webhook", "json_loose"}


def validate_target_name(target_name: str) -> str:
    """Allow only local registered targets."""
    cleaned = (target_name or "").strip().lower()
    if cleaned not in _ALLOWED_TARGETS:
        raise ValueError(f"Unknown target '{target_name}'. Valid targets: {sorted(_ALLOWED_TARGETS)}")
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
