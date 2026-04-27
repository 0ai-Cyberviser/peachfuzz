import pytest

from peachfuzz_ai.targets import (
    bytes_target,
    findings_target,
    get_target,
    graphql_target,
    json_api_target,
    openapi_target,
    target_names,
    webhook_target,
)


class TestJsonApiTarget:
    """Tests for json_api_target function."""

    def test_rejects_bad_endpoint(self) -> None:
        with pytest.raises(ValueError):
            json_api_target(b'{"endpoint":"v1/ask"}')

    def test_blocks_unauthenticated_diagnostics(self) -> None:
        with pytest.raises(PermissionError):
            json_api_target(b'{"endpoint":"/internal/diagnostics","auth":false}')

    def test_rejects_too_large_input(self) -> None:
        with pytest.raises(ValueError, match="input too large"):
            json_api_target(b"x" * 1_000_001)

    def test_ignores_invalid_json(self) -> None:
        # Should return without error
        json_api_target(b"not json")

    def test_ignores_non_dict(self) -> None:
        json_api_target(b"[1, 2, 3]")

    def test_valid_payload_with_body(self) -> None:
        json_api_target(b'{"endpoint":"/api/test","body":{"key":"value"}}')

    def test_empty_endpoint_does_not_raise(self) -> None:
        """Empty endpoint should be accepted without raising an exception."""
        json_api_target(b'{"endpoint":""}')  # No exception means success


class TestFindingsTarget:
    """Tests for findings_target function."""

    def test_never_routes_unauthorized_to_executor(self) -> None:
        findings_target(b"VULNERABILITY_CONFIRMED: CVE-2021-44228 on 192.168.1.1")

    def test_handles_unicode_errors(self) -> None:
        findings_target(b"\xff\xfe\x00\x00 test")


class TestBytesTarget:
    """Tests for bytes_target function."""

    def test_sentinel(self) -> None:
        with pytest.raises(ValueError):
            bytes_target(b"PEACHFUZZ_CRASH_SENTINEL")

    def test_normal_data(self) -> None:
        bytes_target(b"some normal data")


class TestOpenApiTarget:
    """Tests for openapi_target function."""

    def test_rejects_relative_path(self) -> None:
        with pytest.raises(ValueError):
            openapi_target(b'{"openapi":"3.1.0","paths":{"relative":{"get":{}}}}')

    def test_rejects_too_large_input(self) -> None:
        with pytest.raises(ValueError, match="input too large"):
            openapi_target(b"x" * 2_000_001)

    def test_ignores_invalid_json(self) -> None:
        openapi_target(b"not json")

    def test_ignores_non_dict(self) -> None:
        openapi_target(b"[1, 2, 3]")

    def test_ignores_non_openapi(self) -> None:
        openapi_target(b'{"other":"field"}')

    def test_rejects_non_dict_paths(self) -> None:
        with pytest.raises(ValueError, match="paths must be an object"):
            openapi_target(b'{"openapi":"3.1.0","paths":"not_dict"}')

    def test_rejects_non_dict_path_item(self) -> None:
        with pytest.raises(ValueError, match="path item must be an object"):
            openapi_target(b'{"openapi":"3.1.0","paths":{"/valid":"not_dict"}}')

    def test_valid_openapi(self) -> None:
        openapi_target(b'{"openapi":"3.1.0","paths":{"/users":{"get":{}}}}')


class TestGraphqlTarget:
    """Tests for graphql_target function."""

    def test_unbalanced_braces(self) -> None:
        with pytest.raises(ValueError):
            graphql_target(b"query X { field ")

    def test_rejects_too_large_input(self) -> None:
        with pytest.raises(ValueError, match="input too large"):
            graphql_target(b"x" * 1_000_001)

    def test_ignores_empty(self) -> None:
        graphql_target(b"   ")

    def test_introspection_without_selection(self) -> None:
        with pytest.raises(ValueError, match="introspection token without selection set"):
            graphql_target(b"__schema")

    def test_valid_query(self) -> None:
        graphql_target(b"query { users { name } }")


class TestWebhookTarget:
    """Tests for webhook_target function."""

    def test_rejects_non_string_event(self) -> None:
        with pytest.raises(ValueError):
            webhook_target(b'{"event": 123}')

    def test_rejects_too_large_input(self) -> None:
        with pytest.raises(ValueError, match="input too large"):
            webhook_target(b"x" * 1_000_001)

    def test_ignores_invalid_json(self) -> None:
        webhook_target(b"not json")

    def test_ignores_non_dict(self) -> None:
        webhook_target(b"[1, 2, 3]")

    def test_rejects_non_dict_headers(self) -> None:
        with pytest.raises(ValueError, match="headers must be an object"):
            webhook_target(b'{"event":"test","headers":"not_dict"}')

    def test_rejects_non_dict_body(self) -> None:
        with pytest.raises(ValueError, match="body must be an object"):
            webhook_target(b'{"event":"test","body":"not_dict"}')

    def test_valid_webhook(self) -> None:
        webhook_target(b'{"event":"push","headers":{},"body":{}}')


class TestTargetRegistry:
    """Tests for get_target and target_names functions."""

    def test_get_target_unknown(self) -> None:
        with pytest.raises(ValueError):
            get_target("shell")

    def test_get_target_known(self) -> None:
        target = get_target("json")
        assert callable(target)

    def test_target_names_not_empty(self) -> None:
        names = target_names()
        assert len(names) > 0
        assert "json" in names
        assert "bytes" in names

    def test_target_names_sorted(self) -> None:
        names = target_names()
        assert names == sorted(names)


class TestJsonApiTargetAdditional:
    """Additional edge case tests for json_api_target."""

    def test_unicode_endpoint(self) -> None:
        """Unicode characters in endpoint should be handled."""
        json_api_target(b'{"endpoint":"/v1/\xc3\xa9ndpoint"}')

    def test_nested_empty_body(self) -> None:
        """Empty nested body should be accepted."""
        json_api_target(b'{"endpoint":"/v1/test","body":{"nested":{}}}')

    def test_array_in_body(self) -> None:
        """Array values in body should be accepted."""
        json_api_target(b'{"endpoint":"/v1/test","body":{"items":[1,2,3]}}')


class TestGraphqlTargetAdditional:
    """Additional edge case tests for graphql_target."""

    def test_multiline_query(self) -> None:
        """Multiline query should be handled."""
        graphql_target(b"query {\n  users {\n    name\n  }\n}")

    def test_unicode_in_graphql(self) -> None:
        """Unicode characters in GraphQL should be handled."""
        graphql_target(b"query { users { name\xc3\xa9 } }")


class TestWebhookTargetAdditional:
    """Additional edge case tests for webhook_target."""

    def test_minimal_valid_webhook(self) -> None:
        """Minimal valid webhook with empty values."""
        webhook_target(b'{}')

    def test_null_body_is_ignored(self) -> None:
        """Null body should not raise."""
        webhook_target(b'{"event":"test","body":null}')

