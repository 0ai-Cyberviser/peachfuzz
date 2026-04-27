"""PeachTrace: dependency-free trace-guided fuzzing for Python targets.

PeachTrace is PeachFuzz's native Atheris-inspired backend. It is not libFuzzer
and does not claim native edge coverage. Instead, it uses Python's standard
`sys.settrace` hooks to collect function/line feedback from local Python parser
targets, then keeps mutations that discover new trace points.

Design goals:
- zero runtime dependencies
- deterministic CI behavior
- local-only execution
- crash dedupe compatible with PeachFuzz reports
- useful feedback for Python parser, schema, webhook, and guardrail targets
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import random
import sys
from types import FrameType
from typing import Any

from .models import FuzzFinding, FuzzRunResult, Severity, payload_digest, preview_payload


TracePoint = tuple[str, str, int]


@dataclass(frozen=True)
class TraceRun:
    """Result of tracing one input."""

    coverage: frozenset[TracePoint]
    finding: FuzzFinding | None = None


@dataclass
class PeachTraceStats:
    """Trace-guided run metrics."""

    target_name: str
    iterations: int = 0
    corpus_inputs: int = 0
    coverage_points: int = 0
    interesting_inputs: int = 0
    crashes: int = 0

    def to_dict(self) -> dict[str, int | str]:
        return asdict(self)


@dataclass
class PeachTraceResult:
    """Full trace-guided fuzz result."""

    fuzz_result: FuzzRunResult
    stats: PeachTraceStats
    interesting_payloads: list[bytes] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.fuzz_result.ok

    def to_json(self) -> str:
        return json.dumps(
            {
                "target_name": self.fuzz_result.target_name,
                "iterations": self.fuzz_result.iterations,
                "corpus_inputs": self.fuzz_result.corpus_inputs,
                "ok": self.ok,
                "stats": self.stats.to_dict(),
                "crashes": [finding.to_dict() for finding in self.fuzz_result.crashes],
            },
            indent=2,
            sort_keys=True,
        )


class PeachTraceEngine:
    """Pure-Python trace-guided fuzzing engine."""

    def __init__(
        self,
        target: Callable[[bytes], None],
        target_name: str,
        report_dir: str | Path = "reports",
        seed: int = 1337,
        trace_roots: tuple[str, ...] = ("peachfuzz_ai", "cactusfuzz"),
    ) -> None:
        self.target = target
        self.target_name = target_name
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.random = random.Random(seed)
        self.trace_roots = trace_roots
        self.coverage_seen: set[TracePoint] = set()
        self.crash_seen: set[str] = set()

    def run(self, corpus: Iterable[bytes], runs: int = 1000) -> PeachTraceResult:
        seeds = list(corpus) or [b"{}"]
        working_corpus = list(seeds)
        result = FuzzRunResult(target_name=self.target_name, corpus_inputs=len(seeds))
        interesting: list[bytes] = []

        # Prime coverage with original seeds.
        for idx, seed in enumerate(seeds):
            trace = self.run_one(seed, iteration=idx)
            if self._accept_trace(seed, trace, working_corpus, interesting):
                pass
            if trace.finding:
                result.crashes.append(trace.finding)

        for i in range(runs):
            seed = self.random.choice(working_corpus)
            data = self.mutate(seed)
            trace = self.run_one(data, iteration=i)
            result.iterations += 1

            if self._accept_trace(data, trace, working_corpus, interesting):
                pass
            if trace.finding:
                digest = trace.finding.payload_sha256
                if digest not in self.crash_seen:
                    self.crash_seen.add(digest)
                    result.crashes.append(trace.finding)
                    self.write_crash(trace.finding, data)

        stats = PeachTraceStats(
            target_name=self.target_name,
            iterations=result.iterations,
            corpus_inputs=len(seeds),
            coverage_points=len(self.coverage_seen),
            interesting_inputs=len(interesting),
            crashes=len(result.crashes),
        )
        trace_result = PeachTraceResult(result, stats, interesting)
        self.write_summary(trace_result)
        self.write_interesting(interesting)
        return trace_result

    def run_one(self, data: bytes, iteration: int) -> TraceRun:
        coverage: set[TracePoint] = set()

        def tracer(frame: FrameType, event: str, arg: Any) -> Callable | None:  # noqa: ARG001
            if event not in {"line", "call"}:
                return tracer
            module = frame.f_globals.get("__name__", "")
            if not isinstance(module, str) or not module.startswith(self.trace_roots):
                return tracer
            code = frame.f_code
            coverage.add((module, code.co_name, frame.f_lineno))
            return tracer

        previous = sys.gettrace()
        try:
            sys.settrace(tracer)
            self.target(data)
            return TraceRun(frozenset(coverage))
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
            return TraceRun(frozenset(coverage), finding=finding)
        finally:
            sys.settrace(previous)

    def mutate(self, data: bytes) -> bytes:
        """Trace-oriented deterministic byte mutator."""
        if not data:
            data = b"{}"
        buf = bytearray(data)
        choice = self.random.choice(
            [
                "flip",
                "insert_token",
                "delete_span",
                "duplicate_span",
                "json_key",
                "boundary",
                "splice",
            ]
        )

        if choice == "flip" and buf:
            idx = self.random.randrange(len(buf))
            buf[idx] ^= self.random.randrange(1, 255)
        elif choice == "insert_token":
            token = self.random.choice(
                [
                    b"{}",
                    b"[]",
                    b'","peach":"trace"',
                    b"/internal/diagnostics",
                    b"__schema",
                    b"mutation",
                    b"null",
                    b"true",
                    b"false",
                    b" PEACHTRACE ",
                ]
            )
            idx = self.random.randrange(len(buf) + 1)
            buf[idx:idx] = token
        elif choice == "delete_span" and len(buf) > 1:
            start = self.random.randrange(len(buf))
            stop = min(len(buf), start + self.random.randrange(1, min(32, len(buf)) + 1))
            del buf[start:stop]
        elif choice == "duplicate_span" and buf:
            start = self.random.randrange(len(buf))
            stop = min(len(buf), start + self.random.randrange(1, min(32, len(buf)) + 1))
            buf.extend(buf[start:stop])
        elif choice == "json_key":
            buf = bytearray(b'{"endpoint":"/v1/')
            buf.extend(self._word().encode())
            buf.extend(b'","body":{"mutation":"')
            buf.extend(data[:96].replace(b'"', b"'"))
            buf.extend(b'"}}')
        elif choice == "boundary":
            buf.extend(self.random.choice([b"\x00", b"A" * 128, b"9" * 64, b"}" * 8, b"{" * 8]))
        elif choice == "splice":
            prefix = self.random.choice([b'{"event":"', b"query X { ", b'{"openapi":"3.1.0","paths":{"/'])
            suffix = self.random.choice([b'"}', b" }", b'":{"get":{"responses":{"200":{"description":"ok"}}}}}}'])
            buf = bytearray(prefix + data[:128] + suffix)
        return bytes(buf)

    def _accept_trace(
        self,
        data: bytes,
        trace: TraceRun,
        working_corpus: list[bytes],
        interesting: list[bytes],
    ) -> bool:
        new_points = set(trace.coverage) - self.coverage_seen
        if not new_points:
            return False
        self.coverage_seen.update(new_points)
        working_corpus.append(data)
        interesting.append(data)
        return True

    def write_summary(self, result: PeachTraceResult) -> None:
        (self.report_dir / f"{self.target_name}-peachtrace-summary.json").write_text(
            result.to_json(),
            encoding="utf-8",
        )
        # Also write standard summary for existing self-refinement tooling.
        (self.report_dir / f"{self.target_name}-summary.json").write_text(
            result.fuzz_result.to_json(),
            encoding="utf-8",
        )

    def write_crash(self, finding: FuzzFinding, data: bytes) -> None:
        crash_dir = self.report_dir / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{finding.target_name}-{finding.payload_sha256[:16]}"
        (crash_dir / f"{stem}.bin").write_bytes(data)
        (crash_dir / f"{stem}.json").write_text(json.dumps(finding.to_dict(), indent=2), encoding="utf-8")

    def write_interesting(self, payloads: list[bytes]) -> None:
        out = self.report_dir / "interesting" / self.target_name
        out.mkdir(parents=True, exist_ok=True)
        for idx, payload in enumerate(payloads[:256]):
            digest = payload_digest(payload)[:16]
            (out / f"{idx:04d}-{digest}.bin").write_bytes(payload)

    def _word(self, length: int = 8) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        return "".join(self.random.choice(alphabet) for _ in range(length))


__all__ = [
    "PeachTraceEngine",
    "PeachTraceResult",
    "PeachTraceStats",
    "TracePoint",
    "TraceRun",
]
