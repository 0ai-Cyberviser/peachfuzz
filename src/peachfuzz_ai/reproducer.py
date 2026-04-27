"""Pytest reproducer generation for PeachFuzz/CactusFuzz crashes."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re

from .minimizer import CrashSignature
from .models import payload_digest


@dataclass(frozen=True)
class ReproducerRequest:
    target_name: str
    payload: bytes
    signature: CrashSignature
    test_name: str | None = None


@dataclass(frozen=True)
class ReproducerResult:
    target_name: str
    output_path: str
    payload_sha256: str
    test_name: str
    signature: CrashSignature

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["signature"] = self.signature.to_dict()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def sanitize_identifier(value: str) -> str:
    """Sanitize a string to be a valid Python identifier."""
    cleaned = re.sub(r"[^0-9a-zA-Z_]+", "_", value.strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        cleaned = "payload"
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


def default_test_name(target_name: str, signature: CrashSignature, digest: str) -> str:
    parts = ["test_repro", target_name, signature.exception_type, digest[:8]]
    return sanitize_identifier("_".join(parts))


def render_pytest_reproducer(request: ReproducerRequest) -> str:
    digest = payload_digest(request.payload)
    test_name = request.test_name or default_test_name(request.target_name, request.signature, digest)
    encoded = base64.b64encode(request.payload).decode("ascii")
    expected_type = request.signature.exception_type
    expected_message = request.signature.message_substring

    return f'''"""Auto-generated PeachFuzz regression reproducer.

Generated for target: {request.target_name}
Payload SHA-256: {digest}
"""

from __future__ import annotations

import base64

import pytest

from peachfuzz_ai.targets import get_target


EXCEPTION_TYPES = {{
    "Exception": Exception,
    "ValueError": ValueError,
    "PermissionError": PermissionError,
    "UnicodeDecodeError": UnicodeDecodeError,
}}


def {test_name}() -> None:
    target = get_target({request.target_name!r})
    payload = base64.b64decode({encoded!r})
    expected_exception = EXCEPTION_TYPES.get({expected_type!r}, Exception)

    with pytest.raises(expected_exception, match={expected_message!r}):
        target(payload)
'''


def write_pytest_reproducer(
    request: ReproducerRequest,
    output_dir: str | Path = "tests/regression",
) -> ReproducerResult:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    digest = payload_digest(request.payload)
    test_name = request.test_name or default_test_name(request.target_name, request.signature, digest)
    path = root / f"{test_name}.py"
    path.write_text(render_pytest_reproducer(request), encoding="utf-8")
    return ReproducerResult(
        target_name=request.target_name,
        output_path=str(path),
        payload_sha256=digest,
        test_name=test_name,
        signature=request.signature,
    )


__all__ = [
    "ReproducerRequest",
    "ReproducerResult",
    "default_test_name",
    "render_pytest_reproducer",
    "sanitize_identifier",
    "write_pytest_reproducer",
]
