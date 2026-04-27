"""PeachFuzz AI constants and default configuration values.

This module defines shared constants used across the fuzzing harness,
enabling consistent behavior and easy configuration adjustment.
"""
from __future__ import annotations

# Default random seed for reproducible fuzzing
DEFAULT_SEED: int = 1337

# Default number of fuzzing iterations
DEFAULT_RUNS: int = 1000

# Maximum payload preview size in bytes for crash reports
PAYLOAD_PREVIEW_LIMIT: int = 160

# Default report output directory
DEFAULT_REPORT_DIR: str = "reports"

# Default corpus directory for corpus-stats command
DEFAULT_CORPUS_DIR: str = "corpus"

# Maximum input sizes for targets (in bytes)
MAX_JSON_INPUT_SIZE: int = 1_000_000
MAX_OPENAPI_INPUT_SIZE: int = 2_000_000
MAX_GRAPHQL_INPUT_SIZE: int = 1_000_000
MAX_WEBHOOK_INPUT_SIZE: int = 1_000_000

# Crash sentinel for synthetic crash testing
CRASH_SENTINEL: bytes = b"PEACHFUZZ_CRASH_SENTINEL"

# Default maximum minimization rounds
DEFAULT_MAX_MINIMIZE_ROUNDS: int = 8

# Interesting payload sample limit
INTERESTING_PAYLOAD_LIMIT: int = 256

__all__ = [
    "CRASH_SENTINEL",
    "DEFAULT_CORPUS_DIR",
    "DEFAULT_MAX_MINIMIZE_ROUNDS",
    "DEFAULT_REPORT_DIR",
    "DEFAULT_RUNS",
    "DEFAULT_SEED",
    "INTERESTING_PAYLOAD_LIMIT",
    "MAX_GRAPHQL_INPUT_SIZE",
    "MAX_JSON_INPUT_SIZE",
    "MAX_OPENAPI_INPUT_SIZE",
    "MAX_WEBHOOK_INPUT_SIZE",
    "PAYLOAD_PREVIEW_LIMIT",
]
