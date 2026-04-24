"""Fuzz backend adapter interface for PeachFuzz/CactusFuzz.

The adapter layer keeps fuzz-engine orchestration explicit and reviewable.
Default behavior remains deterministic and local-only. External/native engines
(AFL++, LibAFL, custom shell commands, etc.) are represented as disabled stubs
until a future sandboxed executor path is added.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from .engine import PeachFuzzEngine
from .models import FuzzRunResult


class BackendKind(str, Enum):
    """Known fuzz backend categories."""

    DETERMINISTIC = "deterministic"
    ATHERIS = "atheris"
    EXTERNAL_SANDBOX = "external-sandbox"


@dataclass(frozen=True)
class BackendCapabilities:
    """Static safety and capability metadata for a backend."""

    name: str
    kind: BackendKind
    description: str
    coverage_guided: bool = False
    in_process: bool = True
    network_access: bool = False
    shell_access: bool = False
    requires_sandbox: bool = False
    requires_authorization: bool = False

    @property
    def safe_by_default(self) -> bool:
        return not (
            self.network_access
            or self.shell_access
            or self.requires_sandbox
            or self.requires_authorization
        )

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["safe_by_default"] = self.safe_by_default
        return data


@dataclass(frozen=True)
class BackendRunRequest:
    """Portable run request consumed by backend adapters."""

    target_name: str
    target: Callable[[bytes], None]
    corpus: Iterable[bytes]
    runs: int = 1000
    report_dir: str | Path = "reports"
    seed: int = 1337
    extra_args: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class BackendRunOutcome:
    """Backend-neutral outcome wrapper."""

    backend: str
    result: FuzzRunResult | None
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok" and (self.result is None or self.result.ok)

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "status": self.status,
            "detail": self.detail,
            "ok": self.ok,
            "result": None if self.result is None else {
                "target_name": self.result.target_name,
                "iterations": self.result.iterations,
                "corpus_inputs": self.result.corpus_inputs,
                "ok": self.result.ok,
                "crashes": [finding.to_dict() for finding in self.result.crashes],
            },
        }


class BackendAdapter(Protocol):
    """Protocol implemented by all fuzz backends."""

    capabilities: BackendCapabilities

    def run(self, request: BackendRunRequest) -> BackendRunOutcome:
        """Run fuzzing and return a backend-neutral outcome."""


class DeterministicBackend:
    """CI-safe deterministic backend powered by PeachFuzzEngine."""

    capabilities = BackendCapabilities(
        name="deterministic",
        kind=BackendKind.DETERMINISTIC,
        description="Local deterministic mutation backend for reliable CI smoke fuzzing.",
        coverage_guided=False,
        in_process=True,
    )

    def run(self, request: BackendRunRequest) -> BackendRunOutcome:
        engine = PeachFuzzEngine(
            request.target,
            request.target_name,
            report_dir=request.report_dir,
            seed=request.seed,
        )
        result = engine.run(request.corpus, runs=request.runs)
        return BackendRunOutcome(
            backend=self.capabilities.name,
            result=result,
            status="ok",
        )


class AtherisBackend:
    """Coverage-guided Python backend wrapper.

    Atheris is in-process, but its fuzz loop is intentionally long-running. The
    CLI keeps the existing direct `peachfuzz atheris` command for real sessions;
    this adapter provides capability metadata and an explicit invocation path for
    future orchestration tests.
    """

    capabilities = BackendCapabilities(
        name="atheris",
        kind=BackendKind.ATHERIS,
        description="Optional coverage-guided Python fuzzing backend.",
        coverage_guided=True,
        in_process=True,
    )

    def run(self, request: BackendRunRequest) -> BackendRunOutcome:
        try:
            import atheris  # type: ignore
        except ImportError:
            return BackendRunOutcome(
                backend=self.capabilities.name,
                result=None,
                status="unavailable",
                detail="atheris is not installed; install with: python -m pip install 'peachfuzz-ai[fuzz]'",
            )

        def test_one_input(data: bytes) -> None:
            request.target(data)

        # Atheris does not return a conventional result; this path is provided
        # for explicit coverage-guided sessions, not CI smoke tests.
        args = [str(p) for p in request.extra_args]
        atheris.Setup(args, test_one_input)
        atheris.Fuzz()
        return BackendRunOutcome(
            backend=self.capabilities.name,
            result=None,
            status="ok",
            detail="atheris fuzz loop completed",
        )


class ExternalSandboxBackend:
    """Disabled placeholder for future AFL++/LibAFL/custom native backends."""

    capabilities = BackendCapabilities(
        name="external-sandbox",
        kind=BackendKind.EXTERNAL_SANDBOX,
        description="Future external fuzz-engine adapter; disabled until sandbox integration lands.",
        coverage_guided=True,
        in_process=False,
        shell_access=True,
        requires_sandbox=True,
        requires_authorization=True,
    )

    def run(self, request: BackendRunRequest) -> BackendRunOutcome:
        return BackendRunOutcome(
            backend=self.capabilities.name,
            result=None,
            status="blocked",
            detail=(
                "external fuzz backends are disabled until a sandboxed executor, "
                "explicit authorization scope, and audit logging are implemented"
            ),
        )


_BACKENDS: dict[str, BackendAdapter] = {
    "deterministic": DeterministicBackend(),
    "atheris": AtherisBackend(),
    "external-sandbox": ExternalSandboxBackend(),
}


def backend_names(*, include_unsafe: bool = False) -> list[str]:
    """Return registered backend names."""
    names: list[str] = []
    for name, backend in _BACKENDS.items():
        if include_unsafe or backend.capabilities.safe_by_default:
            names.append(name)
    return sorted(names)


def get_backend(name: str) -> BackendAdapter:
    """Resolve one backend by name."""
    key = (name or "").strip().lower()
    try:
        return _BACKENDS[key]
    except KeyError as exc:
        raise ValueError(f"Unknown backend '{name}'. Valid: {sorted(_BACKENDS)}") from exc


def backend_matrix_markdown(*, include_unsafe: bool = True) -> str:
    """Render backend safety matrix."""
    rows = [
        "| Backend | Kind | Coverage | In-process | Safe by default | Requires sandbox | Description |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for name in sorted(_BACKENDS):
        cap = _BACKENDS[name].capabilities
        if not include_unsafe and not cap.safe_by_default:
            continue
        rows.append(
            f"| {cap.name} | {cap.kind.value} | {cap.coverage_guided} | "
            f"{cap.in_process} | {cap.safe_by_default} | {cap.requires_sandbox} | "
            f"{cap.description} |"
        )
    return "\n".join(rows)


def backend_matrix_json(*, include_unsafe: bool = True) -> list[dict[str, object]]:
    """Return backend safety matrix as JSON-serializable objects."""
    data: list[dict[str, object]] = []
    for name in sorted(_BACKENDS):
        cap = _BACKENDS[name].capabilities
        if include_unsafe or cap.safe_by_default:
            data.append(cap.to_dict())
    return data
