"""Shared models for PeachFuzz AI."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class AgentState:
    """LangGraph-inspired state snapshot for fuzzing loops."""

    target_name: str
    iteration: int = 0
    crashes: int = 0
    authorized: bool = False
    authenticated: bool = True
    action_history: tuple[str, ...] = field(default_factory=tuple)
    error: str = ""


@dataclass(frozen=True)
class FuzzFinding:
    """A local crash or bug observation discovered by the harness."""

    target_name: str
    exception_type: str
    message: str
    payload_sha256: str
    payload_preview: str
    iteration: int
    severity: Severity = Severity.MEDIUM
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class FuzzRunResult:
    """Aggregate result for one fuzz run."""

    target_name: str
    iterations: int = 0
    crashes: list[FuzzFinding] = field(default_factory=list)
    corpus_inputs: int = 0

    @property
    def ok(self) -> bool:
        return not self.crashes

    def to_json(self) -> str:
        return json.dumps(
            {
                "target_name": self.target_name,
                "iterations": self.iterations,
                "corpus_inputs": self.corpus_inputs,
                "ok": self.ok,
                "crashes": [finding.to_dict() for finding in self.crashes],
            },
            indent=2,
            sort_keys=True,
        )


def payload_digest(data: bytes) -> str:
    """Return SHA-256 digest for crash de-duplication."""
    return hashlib.sha256(data).hexdigest()


def preview_payload(data: bytes, limit: int = 160) -> str:
    """Return a safe printable preview."""
    text = data[:limit].decode("utf-8", errors="replace")
    return text.replace("\x00", "\\x00")
