"""Tests for the constants module."""
from peachfuzz_ai.constants import (
    CRASH_SENTINEL,
    DEFAULT_CORPUS_DIR,
    DEFAULT_MAX_MINIMIZE_ROUNDS,
    DEFAULT_REPORT_DIR,
    DEFAULT_RUNS,
    DEFAULT_SEED,
    INTERESTING_PAYLOAD_LIMIT,
    MAX_GRAPHQL_INPUT_SIZE,
    MAX_JSON_INPUT_SIZE,
    MAX_OPENAPI_INPUT_SIZE,
    MAX_WEBHOOK_INPUT_SIZE,
    PAYLOAD_PREVIEW_LIMIT,
)


class TestConstants:
    """Tests for PeachFuzz AI constants."""

    def test_default_seed_is_deterministic(self) -> None:
        """Default seed should be 1337 for reproducible fuzzing."""
        assert DEFAULT_SEED == 1337

    def test_default_runs_is_reasonable(self) -> None:
        """Default runs should be 1000."""
        assert DEFAULT_RUNS == 1000

    def test_payload_preview_limit_is_positive(self) -> None:
        """Payload preview limit should be a positive integer."""
        assert PAYLOAD_PREVIEW_LIMIT > 0
        assert isinstance(PAYLOAD_PREVIEW_LIMIT, int)

    def test_crash_sentinel_is_bytes(self) -> None:
        """Crash sentinel should be a bytes object."""
        assert isinstance(CRASH_SENTINEL, bytes)
        assert b"PEACHFUZZ" in CRASH_SENTINEL

    def test_max_input_sizes_are_reasonable(self) -> None:
        """Max input sizes should be at least 1MB."""
        assert MAX_JSON_INPUT_SIZE >= 1_000_000
        assert MAX_OPENAPI_INPUT_SIZE >= 1_000_000
        assert MAX_GRAPHQL_INPUT_SIZE >= 1_000_000
        assert MAX_WEBHOOK_INPUT_SIZE >= 1_000_000

    def test_default_directories_are_strings(self) -> None:
        """Default directory constants should be strings."""
        assert isinstance(DEFAULT_REPORT_DIR, str)
        assert isinstance(DEFAULT_CORPUS_DIR, str)

    def test_minimize_rounds_is_positive(self) -> None:
        """Max minimize rounds should be a positive integer."""
        assert DEFAULT_MAX_MINIMIZE_ROUNDS > 0
        assert isinstance(DEFAULT_MAX_MINIMIZE_ROUNDS, int)

    def test_interesting_payload_limit_is_positive(self) -> None:
        """Interesting payload limit should be a positive integer."""
        assert INTERESTING_PAYLOAD_LIMIT > 0
        assert isinstance(INTERESTING_PAYLOAD_LIMIT, int)
