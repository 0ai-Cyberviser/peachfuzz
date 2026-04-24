"""PeachFuzz/CactusFuzz edition taxonomy."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EditionName(str, Enum):
    PEACHFUZZ = "peachfuzz"
    CACTUSFUZZ = "cactusfuzz"


@dataclass(frozen=True)
class EditionProfile:
    """Capability profile for one fuzzing edition."""

    name: EditionName
    display_name: str
    audience: str
    mission: str
    allowed: tuple[str, ...]
    blocked_by_default: tuple[str, ...]
    requires_authorization: bool
    risk_level: str


PEACHFUZZ = EditionProfile(
    name=EditionName.PEACHFUZZ,
    display_name="PeachFuzz",
    audience="Blue teams, SOC, AppSec, parser maintainers, defensive engineering",
    mission=(
        "Defensively fuzz local parsers, API schemas, webhook handlers, agent guardrails, "
        "and reporting paths to find bugs before attackers do."
    ),
    allowed=(
        "local parser fuzzing",
        "local API schema fuzzing",
        "local LLM-agent guardrail regression testing",
        "crash deduplication and remediation advisories",
        "CI artifact generation",
    ),
    blocked_by_default=(
        "network scanning",
        "exploit execution",
        "shell payload execution",
        "third-party callbacks",
        "credential attacks",
    ),
    requires_authorization=False,
    risk_level="low",
)


CACTUSFUZZ = EditionProfile(
    name=EditionName.CACTUSFUZZ,
    display_name="CactusFuzz",
    audience="Authorized red teams, internal pentest teams, AI safety evaluators",
    mission=(
        "Adversarially test owned or explicitly authorized applications, APIs, and AI agents "
        "for robustness, policy bypasses, unsafe tool routing, and abuse-case resilience."
    ),
    allowed=(
        "offline adversarial prompt fuzzing",
        "local lab API fuzzing",
        "owned-target schema fuzzing",
        "authorization-gated tool-routing simulations",
        "reporting of exploitability hypotheses without payload delivery",
    ),
    blocked_by_default=(
        "unauthorized network scanning",
        "real exploit delivery",
        "reverse shells or persistence",
        "credential theft",
        "destructive payloads",
        "unsandboxed shell execution",
        "third-party target contact without explicit scope",
    ),
    requires_authorization=True,
    risk_level="medium-high",
)


EDITIONS = {
    EditionName.PEACHFUZZ.value: PEACHFUZZ,
    EditionName.CACTUSFUZZ.value: CACTUSFUZZ,
}


def get_edition(name: str) -> EditionProfile:
    """Return an edition profile by canonical name."""
    key = (name or "").strip().lower()
    if key not in EDITIONS:
        raise ValueError(f"Unknown edition '{name}'. Valid: {sorted(EDITIONS)}")
    return EDITIONS[key]


def edition_matrix_markdown() -> str:
    """Render a concise markdown comparison table."""
    rows = [
        "| Edition | Audience | Risk | Authorization | Mission |",
        "|---|---|---:|---:|---|",
    ]
    for profile in (PEACHFUZZ, CACTUSFUZZ):
        rows.append(
            f"| {profile.display_name} | {profile.audience} | {profile.risk_level} | "
            f"{'required' if profile.requires_authorization else 'not required for local-only use'} | "
            f"{profile.mission} |"
        )
    return "\n".join(rows)
