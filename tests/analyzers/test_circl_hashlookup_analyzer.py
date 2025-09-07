"""Tests for CirclHashlookupAnalyzer."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


class DummyHttpClient:
    """Mock HTTP client for testing."""

    def __init__(self, *a, **k):
        pass

    def get(self, url: str, **kwargs) -> MockResponse:
        """Mock GET request."""
        if "/lookup/md5/" in url:
            hash_value = url.split("/lookup/md5/")[1]
            if hash_value == "5d41402abc4b2a76b9719d911017c592":
                return MockResponse(200, {"hashlookup:trust": 100, "MD5": hash_value.upper()})
            return MockResponse(404, {"error": "not_found"})
        if "/lookup/sha1/" in url:
            hash_value = url.split("/lookup/sha1/")[1]
            if hash_value == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d":
                return MockResponse(200, {"hashlookup:trust": 100, "SHA-1": hash_value.upper()})
            return MockResponse(404, {"error": "not_found"})
        if "/lookup/sha256/" in url:
            hash_value = url.split("/lookup/sha256/")[1]
            if hash_value == "2cf24dba4f21a03f4b3d914f42305d25206eaf64a81f73b3e4e5b9bd3e978038":
                return MockResponse(200, {"hashlookup:trust": 100, "SHA-256": hash_value.upper()})
            return MockResponse(404, {"error": "not_found"})
        if "/bulk/md5" in url:
            return MockResponse(200, [{"MD5": "5D41402ABC4B2A76B9719D911017C592"}])
        if "/bulk/sha1" in url:
            return MockResponse(200, [{"SHA-1": "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"}])
        if "/children/" in url or "/parents/" in url:
            return MockResponse(404, {"error": "not_found"})
        if "/info" in url:
            return MockResponse(200, {"version": "1.3", "total": 1000000})
        if "/stats/top" in url:
            return MockResponse(200, {"top_hashes": []})
        if "/session/create/" in url:
            return MockResponse(200, {"session": "test-session"})
        if "/session/get/" in url:
            return MockResponse(200, {"matches": [], "non_matches": []})
        return MockResponse(404, {"error": "not_found"})

    def post(self, url: str, **kwargs) -> MockResponse:
        """Mock POST request."""
        if "/bulk/md5" in url:
            return MockResponse(200, [{"MD5": "5D41402ABC4B2A76B9719D911017C592"}])
        if "/bulk/sha1" in url:
            return MockResponse(200, [{"SHA-1": "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"}])
        return MockResponse(404, {"error": "not_found"})

    def close(self):
        """Mock close method."""


class MockResponse:
    """Mock HTTP response."""

    def __init__(self, status_code: int, data: Any):
        self.status_code = status_code
        self._data = data

    def raise_for_status(self):
        """Mock raise_for_status."""
        if self.status_code >= 400:
            from httpx import HTTPStatusError

            raise HTTPStatusError("Mock error", request=None, response=self)

    def json(self) -> Any:
        """Mock json method."""
        return self._data


def build_analyzer(
    dtype: DataType, data: str, config: WorkerConfig | None = None
) -> CirclHashlookupAnalyzer:
    """Build analyzer with given input."""
    if config is None:
        config = WorkerConfig()
    return CirclHashlookupAnalyzer(WorkerInput(data_type=dtype, data=data, config=config))


def test_md5_hash_analysis_found() -> None:
    """Test MD5 hash analysis when hash is found."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "5d41402abc4b2a76b9719d911017c592")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["source"] == "circl_hashlookup"
        assert rep.full_report["details"]["hash_type"] == "md5"


def test_sha1_hash_analysis_found() -> None:
    """Test SHA1 hash analysis when hash is found."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["details"]["hash_type"] == "sha1"


def test_sha256_hash_analysis_found() -> None:
    """Test SHA256 hash analysis when hash is found."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer(
            "hash", "2cf24dba4f21a03f4b3d914f42305d25206eaf64a81f73b3e4e5b9bd3e978038"
        )
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["details"]["hash_type"] == "sha256"


def test_hash_analysis_not_found() -> None:
    """Test hash analysis when hash is not found."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "deadbeefdeadbeefdeadbeefdeadbeef")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert "error" in rep.full_report["details"]["lookup_result"]


def test_unsupported_hash_type() -> None:
    """Test unsupported hash type."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "invalid_hash")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_unsupported_data_type() -> None:
    """Test unsupported data type."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("ip", "1.2.3.4")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_dynamic_lookup_md5() -> None:
    """Test dynamic MD5 lookup via other data type."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps(
            {"method": "lookup_md5", "params": {"hash": "5d41402abc4b2a76b9719d911017c592"}}
        )
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "lookup_md5"


def test_dynamic_bulk_md5() -> None:
    """Test dynamic bulk MD5 lookup."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps(
            {"method": "bulk_md5", "params": {"hashes": ["5d41402abc4b2a76b9719d911017c592"]}}
        )
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "bulk_md5"


def test_dynamic_get_info() -> None:
    """Test dynamic get_info method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps({"method": "get_info", "params": {}})
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_info"


def test_dynamic_get_children() -> None:
    """Test dynamic get_children method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps(
            {
                "method": "get_children",
                "params": {
                    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                    "count": 5,
                    "cursor": "0",
                },
            }
        )
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_children"


def test_dynamic_get_parents() -> None:
    """Test dynamic get_parents method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps(
            {
                "method": "get_parents",
                "params": {
                    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                    "count": 5,
                    "cursor": "0",
                },
            }
        )
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_parents"


def test_dynamic_create_session() -> None:
    """Test dynamic create_session method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps({"method": "create_session", "params": {"name": "test-session"}})
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "create_session"


def test_dynamic_get_session() -> None:
    """Test dynamic get_session method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps({"method": "get_session", "params": {"name": "test-session"}})
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_session"


def test_dynamic_get_stats_top() -> None:
    """Test dynamic get_stats_top method."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        payload = json.dumps({"method": "get_stats_top", "params": {}})
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_stats_top"


def test_config_method_call() -> None:
    """Test method call via config params."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        config = WorkerConfig(params={"circl": {"method": "get_info", "params": {}}})
        analyzer = build_analyzer("other", "{}", config)
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"
        assert rep.full_report["details"]["method"] == "get_info"


def test_other_payload_invalid_json() -> None:
    """Test invalid JSON payload."""
    analyzer = build_analyzer("other", "not-json")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_other_payload_missing_method() -> None:
    """Test payload missing method."""
    analyzer = build_analyzer("other", json.dumps({"params": {}}))
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_other_payload_invalid_params() -> None:
    """Test payload with invalid params."""
    analyzer = build_analyzer("other", json.dumps({"method": "lookup_md5", "params": "invalid"}))
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_unsupported_method() -> None:
    """Test unsupported method."""
    payload = json.dumps({"method": "unsupported_method", "params": {}})
    analyzer = build_analyzer("other", payload)
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_missing_required_parameter() -> None:
    """Test missing required parameter."""
    payload = json.dumps({"method": "lookup_md5", "params": {}})
    analyzer = build_analyzer("other", payload)
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_config_params_not_mapping() -> None:
    """Test config params not a mapping."""
    config = WorkerConfig(params={"circl": {"method": "lookup_md5", "params": "invalid"}})
    analyzer = build_analyzer("other", "{}", config)
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_run_returns_none() -> None:
    """Test run method returns None."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "5d41402abc4b2a76b9719d911017c592")
        analyzer.run()  # Should not raise any exceptions


def test_hash_detection() -> None:
    """Test hash type detection."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "5d41402abc4b2a76b9719d911017c592")
        assert analyzer._detect_hash_type("5d41402abc4b2a76b9719d911017c592") == "md5"
        assert analyzer._detect_hash_type("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == "sha1"
        assert (
            analyzer._detect_hash_type(
                "2cf24dba4f21a03f4b3d914f42305d25206eaf64a81f73b3e4e5b9bd3e978038"
            )
            == "sha256"
        )
        assert analyzer._detect_hash_type("invalid") == "unknown"


def test_verdict_from_result() -> None:
    """Test verdict determination from result."""
    with patch("sentineliqsdk.analyzers.circl_hashlookup.httpx.Client", DummyHttpClient):
        analyzer = build_analyzer("hash", "5d41402abc4b2a76b9719d911017c592")

        # Test with trust indicator
        result_with_trust = {"hashlookup:trust": 100}
        assert analyzer._verdict_from_result(result_with_trust) == "safe"

        # Test with error
        result_with_error = {"error": "not_found"}
        assert analyzer._verdict_from_result(result_with_error) == "info"

        # Test with other error
        result_with_other_error = {"error": "invalid_format"}
        assert analyzer._verdict_from_result(result_with_other_error) == "info"

        # Test with no indicators
        result_empty: dict[str, Any] = {}
        assert analyzer._verdict_from_result(result_empty) == "info"


def test_metadata() -> None:
    """Test analyzer metadata."""
    assert CirclHashlookupAnalyzer.METADATA.name == "CIRCL Hashlookup Analyzer"
    assert CirclHashlookupAnalyzer.METADATA.pattern == "threat-intel"
    assert CirclHashlookupAnalyzer.METADATA.version_stage == "STABLE"
