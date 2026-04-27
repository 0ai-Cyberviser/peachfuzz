"""Crash minimization for PeachFuzz/CactusFuzz.

The minimizer is dependency-free and local-only. It repeatedly invokes an
in-process target function and tries to shrink a crash payload while preserving
the expected exception signature.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from .models import payload_digest, preview_payload


@dataclass(frozen=True)
class CrashSignature:
    """Exception signature that must remain reproducible."""

    exception_type: str
    message_substring: str = ""

    def matches(self, exc: BaseException) -> bool:
        if type(exc).__name__ != self.exception_type:
            return False
        if self.message_substring and self.message_substring not in str(exc):
            return False
        return True

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class MinimizeRequest:
    """Request to minimize a crash payload."""

    target_name: str
    payload: bytes
    signature: CrashSignature | None = None
    max_rounds: int = 8


@dataclass(frozen=True)
class MinimizeResult:
    """Result of a minimization run."""

    target_name: str
    original_size: int
    minimized_size: int
    original_sha256: str
    minimized_sha256: str
    attempts: int
    changed: bool
    reproduced: bool
    signature: CrashSignature
    payload_preview: str

    @property
    def reduction_bytes(self) -> int:
        return self.original_size - self.minimized_size

    @property
    def reduction_percent(self) -> float:
        if self.original_size == 0:
            return 0.0
        return round((self.reduction_bytes / self.original_size) * 100, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "original_size": self.original_size,
            "minimized_size": self.minimized_size,
            "original_sha256": self.original_sha256,
            "minimized_sha256": self.minimized_sha256,
            "attempts": self.attempts,
            "changed": self.changed,
            "reproduced": self.reproduced,
            "reduction_bytes": self.reduction_bytes,
            "reduction_percent": self.reduction_percent,
            "signature": self.signature.to_dict(),
            "payload_preview": self.payload_preview,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class DeltaMinimizer:
    """Deterministic delta-style byte minimizer."""

    def __init__(self, target: Callable[[bytes], None], target_name: str) -> None:
        self.target = target
        self.target_name = target_name
        self.attempts = 0

    def infer_signature(self, payload: bytes) -> CrashSignature:
        """Run the payload once and infer the crash signature."""
        try:
            self.target(payload)
        except Exception as exc:  # noqa: BLE001 - fuzz minimizers intentionally catch target exceptions.
            return CrashSignature(type(exc).__name__, str(exc))
        raise ValueError("payload does not reproduce a crash")

    def reproduces(self, payload: bytes, signature: CrashSignature) -> bool:
        """Return true if payload still reproduces the expected signature."""
        self.attempts += 1
        try:
            self.target(payload)
        except Exception as exc:  # noqa: BLE001
            return signature.matches(exc)
        return False

    def minimize(self, request: MinimizeRequest) -> tuple[MinimizeResult, bytes]:
        """Minimize payload while preserving exception type/message substring."""
        original = request.payload
        signature = request.signature or self.infer_signature(original)

        self.attempts = 0
        if not self.reproduces(original, signature):
            result = MinimizeResult(
                target_name=request.target_name,
                original_size=len(original),
                minimized_size=len(original),
                original_sha256=payload_digest(original),
                minimized_sha256=payload_digest(original),
                attempts=self.attempts,
                changed=False,
                reproduced=False,
                signature=signature,
                payload_preview=preview_payload(original),
            )
            return result, original

        current = original
        for _round in range(max(1, request.max_rounds)):
            before = current
            current = self._delete_chunks(current, signature)
            current = self._delete_single_bytes(current, signature)
            current = self._simplify_bytes(current, signature)
            if current == before:
                break

        result = MinimizeResult(
            target_name=request.target_name,
            original_size=len(original),
            minimized_size=len(current),
            original_sha256=payload_digest(original),
            minimized_sha256=payload_digest(current),
            attempts=self.attempts,
            changed=current != original,
            reproduced=self.reproduces(current, signature),
            signature=signature,
            payload_preview=preview_payload(current),
        )
        return result, current

    def _delete_chunks(self, payload: bytes, signature: CrashSignature) -> bytes:
        current = payload
        if len(current) <= 1:
            return current

        granularity = 2
        while granularity <= max(2, len(current)):
            chunk_size = max(1, len(current) // granularity)
            changed = False
            idx = 0
            while idx < len(current):
                candidate = current[:idx] + current[idx + chunk_size :]
                if candidate and candidate != current and self.reproduces(candidate, signature):
                    current = candidate
                    changed = True
                else:
                    idx += chunk_size
            if not changed:
                granularity *= 2
            if chunk_size == 1:
                break
        return current

    def _delete_single_bytes(self, payload: bytes, signature: CrashSignature) -> bytes:
        current = payload
        idx = 0
        while idx < len(current):
            candidate = current[:idx] + current[idx + 1 :]
            if candidate and self.reproduces(candidate, signature):
                current = candidate
            else:
                idx += 1
        return current

    def _simplify_bytes(self, payload: bytes, signature: CrashSignature) -> bytes:
        current = bytearray(payload)
        replacements = (ord("A"), ord("0"), ord(" "), ord("{"), ord("}"), 0)
        for idx, original in enumerate(bytes(current)):
            for value in replacements:
                if value == original:
                    continue
                candidate = bytes(current[:idx] + bytes([value]) + current[idx + 1 :])
                if candidate and self.reproduces(candidate, signature):
                    current[idx] = value
                    break
        return bytes(current)


def write_minimized_result(
    result: MinimizeResult,
    payload: bytes,
    output_dir: str | Path = "reports/minimized",
) -> tuple[Path, Path]:
    """Write minimized payload and JSON metadata."""
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    stem = f"{result.target_name}-{result.minimized_sha256[:16]}"
    payload_path = root / f"{stem}.bin"
    json_path = root / f"{stem}.json"
    payload_path.write_bytes(payload)
    json_path.write_text(result.to_json() + "\n", encoding="utf-8")
    return payload_path, json_path


__all__ = [
    "CrashSignature",
    "DeltaMinimizer",
    "MinimizeRequest",
    "MinimizeResult",
    "write_minimized_result",
]
