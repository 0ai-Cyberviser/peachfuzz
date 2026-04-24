"""PeachFuzz AI engine."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
import json
import random
from typing import BinaryIO

from .models import AgentState, FuzzFinding, FuzzRunResult, Severity, payload_digest, preview_payload


class PeachFuzzEngine:
    """Defensive fuzzing engine with crash triage and self-refinement advisories."""

    def __init__(
        self,
        target: Callable[[bytes], None],
        target_name: str,
        report_dir: str | Path = "reports",
        seed: int = 1337,
    ) -> None:
        self.target = target
        self.target_name = target_name
        self.random = random.Random(seed)
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.learning_log: list[str] = []

    def mutate(self, data: bytes) -> bytes:
        """Small deterministic mutator for CI-safe fallback fuzzing."""
        if not data:
            data = b"{}"
        choice = self.random.choice(["flip", "append", "truncate", "repeat", "jsonish"])
        buf = bytearray(data)

        if choice == "flip" and buf:
            idx = self.random.randrange(len(buf))
            buf[idx] ^= self.random.randrange(1, 255)
        elif choice == "append":
            buf.extend(self.random.choice([b"\x00", b"A" * 32, b'"', b"}", b" PEACHFUZZ"]))
        elif choice == "truncate" and len(buf) > 1:
            del buf[self.random.randrange(len(buf)) :]
        elif choice == "repeat":
            buf.extend(buf[: min(len(buf), 64)])
        elif choice == "jsonish":
            buf = bytearray(b'{"endpoint":"/v1/workflows","body":{"finding":"')
            buf.extend(data[:128])
            buf.extend(b'"}}')
        return bytes(buf)

    def self_refine(self, finding: FuzzFinding) -> str:
        """Generate a safe advisory from crash metadata."""
        advisory = (
            f"SEC-ADVISORY: {finding.target_name} raised {finding.exception_type} "
            f"at iteration {finding.iteration}; payload_sha256={finding.payload_sha256}; "
            "recommend adding parser bounds checks, schema validation, and regression corpus."
        )
        self.learning_log.append(advisory)
        return advisory

    def run_one(self, data: bytes, iteration: int) -> FuzzFinding | None:
        """Run one input. Return finding on crash-like exception."""
        try:
            self.target(data)
            return None
        except Exception as exc:  # noqa: BLE001 - fuzzers intentionally catch all target exceptions.
            severity = Severity.HIGH if isinstance(exc, PermissionError) else Severity.MEDIUM
            finding = FuzzFinding(
                target_name=self.target_name,
                exception_type=type(exc).__name__,
                message=str(exc),
                payload_sha256=payload_digest(data),
                payload_preview=preview_payload(data),
                iteration=iteration,
                severity=severity,
            )
            self.self_refine(finding)
            self.write_crash(finding, data)
            return finding

    def run(self, corpus: Iterable[bytes], runs: int = 1000) -> FuzzRunResult:
        """Run deterministic fuzzing over a seed corpus."""
        seeds = list(corpus) or [b"{}"]
        result = FuzzRunResult(target_name=self.target_name, corpus_inputs=len(seeds))
        for i in range(runs):
            seed = self.random.choice(seeds)
            data = self.mutate(seed)
            finding = self.run_one(data, i)
            result.iterations += 1
            if finding:
                result.crashes.append(finding)
        self.write_summary(result)
        return result

    def write_crash(self, finding: FuzzFinding, data: bytes) -> None:
        crash_dir = self.report_dir / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{finding.target_name}-{finding.payload_sha256[:16]}"
        (crash_dir / f"{stem}.bin").write_bytes(data)
        (crash_dir / f"{stem}.json").write_text(json.dumps(finding.to_dict(), indent=2), encoding="utf-8")

    def write_summary(self, result: FuzzRunResult) -> None:
        (self.report_dir / f"{self.target_name}-summary.json").write_text(result.to_json(), encoding="utf-8")


def load_corpus(paths: list[str | Path]) -> list[bytes]:
    """Load corpus files from paths/directories."""
    corpus: list[bytes] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file():
                    corpus.append(child.read_bytes())
        elif path.is_file():
            corpus.append(path.read_bytes())
    return corpus
