"""Tests for the json_loose target."""
from __future__ import annotations

import json

import pytest

from peachfuzz_ai.targets.json_loose import json_loose_target


class TestJsonLooseTarget:
    """Tests for json_loose_target function."""

    def test_valid_endpoint_slash(self) -> None:
        """Valid endpoint starting with / should not raise."""
        data = json.dumps({"endpoint": "/v1/workflows"}).encode()
        json_loose_target(data)  # Should not raise

    def test_valid_endpoint_with_body(self) -> None:
        """Valid endpoint with body dict should not raise."""
        data = json.dumps({
            "endpoint": "/api/users",
            "body": {"name": "test", "value": 123},
        }).encode()
        json_loose_target(data)

    def test_non_dict_top_level_raises(self) -> None:
        """Non-dict top level JSON should raise TypeError."""
        data = json.dumps([1, 2, 3]).encode()
        with pytest.raises(TypeError, match="top-level JSON must be object"):
            json_loose_target(data)

    def test_missing_endpoint_raises(self) -> None:
        """Missing endpoint key should raise KeyError."""
        data = json.dumps({"other": "data"}).encode()
        with pytest.raises(KeyError, match="endpoint missing"):
            json_loose_target(data)

    def test_boolean_endpoint_raises(self) -> None:
        """Boolean endpoint should raise TypeError."""
        data = json.dumps({"endpoint": True}).encode()
        with pytest.raises(TypeError, match="endpoint cannot be boolean"):
            json_loose_target(data)

    def test_integer_endpoint_raises(self) -> None:
        """Integer endpoint should raise OverflowError."""
        data = json.dumps({"endpoint": 123}).encode()
        with pytest.raises(OverflowError, match="endpoint numeric not allowed"):
            json_loose_target(data)

    def test_list_endpoint_raises(self) -> None:
        """List endpoint should raise TypeError."""
        data = json.dumps({"endpoint": ["path", "parts"]}).encode()
        with pytest.raises(TypeError, match="endpoint cannot be list"):
            json_loose_target(data)

    def test_dict_endpoint_raises(self) -> None:
        """Dict endpoint should raise TypeError."""
        data = json.dumps({"endpoint": {"nested": "object"}}).encode()
        with pytest.raises(TypeError, match="endpoint cannot be object"):
            json_loose_target(data)

    def test_javascript_scheme_raises(self) -> None:
        """JavaScript scheme endpoint should raise ValueError."""
        data = json.dumps({"endpoint": "javascript:alert(1)"}).encode()
        with pytest.raises(ValueError, match="script scheme not allowed"):
            json_loose_target(data)

    def test_http_url_raises(self) -> None:
        """HTTP URL endpoint should raise PermissionError."""
        data = json.dumps({"endpoint": "http://evil.com"}).encode()
        with pytest.raises(PermissionError, match="external URL not allowed"):
            json_loose_target(data)

    def test_https_url_raises(self) -> None:
        """HTTPS URL endpoint should raise PermissionError."""
        data = json.dumps({"endpoint": "https://evil.com"}).encode()
        with pytest.raises(PermissionError, match="external URL not allowed"):
            json_loose_target(data)

    def test_path_traversal_raises(self) -> None:
        """Path traversal endpoint should raise ValueError."""
        data = json.dumps({"endpoint": "/api/../etc/passwd"}).encode()
        with pytest.raises(ValueError, match="path traversal detected"):
            json_loose_target(data)

    def test_relative_path_raises(self) -> None:
        """Relative path endpoint should raise ValueError."""
        data = json.dumps({"endpoint": "relative/path"}).encode()
        with pytest.raises(ValueError, match="relative path not allowed"):
            json_loose_target(data)

    def test_invalid_body_key_raises(self) -> None:
        """Non-string body key would raise in strict mode."""
        # Note: JSON always has string keys, so this tests the iteration
        data = json.dumps({
            "endpoint": "/v1/test",
            "body": {"valid_key": "value"},
        }).encode()
        json_loose_target(data)  # Should work with string keys
