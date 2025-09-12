from __future__ import annotations

from typing import Any
from unittest.mock import mock_open, patch

import pytest

from sentineliqsdk.analyzers.emergingthreats import EmergingThreatsAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(self, json_data: dict[str, Any], status_code: int = 200):
        self.json_data = json_data
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self.json_data


class DummyEmergingThreatsSession:
    """Mock requests session for EmergingThreats API testing."""

    def __init__(self):
        self.headers = {}

    def update_headers(self, headers: dict[str, str]) -> None:
        self.headers.update(headers)

    def get(self, url: str) -> MockResponse:
        """Mock GET method that returns different responses based on URL and data."""
        # Extract the observable and feature from URL
        if "domains/" in url:
            if "malicious.com" in url:
                if "reputation" in url:
                    return MockResponse(
                        {
                            "response": [
                                {"category": "CnC", "score": 85},
                                {"category": "Malware", "score": 90},
                            ]
                        }
                    )
                if "events" in url:
                    return MockResponse(
                        {
                            "response": [
                                {"event_id": "123", "signature": "Malware detected"},
                                {"event_id": "456", "signature": "C&C communication"},
                            ]
                        }
                    )
                return MockResponse({"response": {"domain": "malicious.com"}})
            if "suspicious.com" in url:
                if "reputation" in url:
                    return MockResponse({"response": [{"category": "DynDNS", "score": 75}]})
                return MockResponse({"response": {"domain": "suspicious.com"}})
            if "safe.com" in url:
                if "reputation" in url:
                    return MockResponse({"response": [{"category": "Utility", "score": 10}]})
                return MockResponse({"response": {"domain": "safe.com"}})
        elif "ips/" in url:
            if "1.2.3.4" in url:
                if "reputation" in url:
                    return MockResponse({"response": [{"category": "Bot", "score": 95}]})
                return MockResponse({"response": {"ip": "1.2.3.4"}})
        elif "samples/" in url and "abc123" in url:
            if "events" in url:
                return MockResponse(
                    {"response": [{"event_id": "789", "signature": "Malware signature match"}]}
                )
            return MockResponse({"response": {"hash": "abc123"}})

        # Default empty response
        return MockResponse({"response": {}})


def build_analyzer(
    data_type: DataType, data: str, api_key: str = "test_key"
) -> EmergingThreatsAnalyzer:
    """Helper function to build EmergingThreatsAnalyzer with test configuration."""
    secrets = {"emergingthreats": {"api_key": api_key}}
    cfg = WorkerConfig(secrets=secrets)
    return EmergingThreatsAnalyzer(WorkerInput(data_type=data_type, data=data, config=cfg))


def test_domain_analysis_malicious() -> None:
    """Test malicious domain detection."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "malicious.com")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "emergingthreats"
        assert len(rep.full_report["taxonomy"]) > 0


def test_domain_analysis_suspicious() -> None:
    """Test suspicious domain detection."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "suspicious.com")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"  # DynDNS with score 75 is safe
        assert rep.full_report["source"] == "emergingthreats"


def test_domain_analysis_safe() -> None:
    """Test safe domain detection."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "safe.com")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["source"] == "emergingthreats"


def test_ip_analysis_malicious() -> None:
    """Test malicious IP detection."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("ip", "1.2.3.4")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "emergingthreats"


def test_hash_analysis_malicious() -> None:
    """Test malicious hash detection."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("hash", "abc123")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "info"  # No reputation data for hash, only events
        assert rep.full_report["source"] == "emergingthreats"


def test_unsupported_data_type() -> None:
    """Test that unsupported data types raise appropriate errors."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("mail", "test@example.com")
        with pytest.raises(ValueError, match="EmergingThreats supports"):
            analyzer.execute()


def test_missing_api_key() -> None:
    """Test that missing API key raises appropriate error."""
    cfg = WorkerConfig(secrets={})
    with pytest.raises(RuntimeError, match="EmergingThreats API key is required"):
        EmergingThreatsAnalyzer(WorkerInput(data_type="domain", data="test.com", config=cfg))


def test_api_error_handling() -> None:
    """Test handling of API errors."""

    class ErrorSession:
        def __init__(self):
            self.headers = {}

        def update_headers(self, headers: dict[str, str]) -> None:
            self.headers.update(headers)

        def get(self, url: str) -> MockResponse:
            return MockResponse({"error": "Rate limit exceeded"}, 429)

    with patch("requests.Session", return_value=ErrorSession()):
        analyzer = build_analyzer("domain", "test.com")
        rep = analyzer.execute()
        # Should handle errors gracefully and return info verdict
        assert rep.full_report["verdict"] == "info"


def test_run_method() -> None:
    """Test that run method returns the same as execute."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "test.com")
        execute_result = analyzer.execute()
        run_result = analyzer.run()
        assert execute_result.full_report == run_result.full_report


def test_taxonomy_structure() -> None:
    """Test that taxonomy is properly structured."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "malicious.com")
        rep = analyzer.execute()

        taxonomy = rep.full_report["taxonomy"]
        assert len(taxonomy) > 0

        # Check taxonomy structure
        tax_item = taxonomy[0]
        assert "level" in tax_item
        assert "namespace" in tax_item
        assert "predicate" in tax_item
        assert "value" in tax_item

        assert tax_item["namespace"] == "ET"
        assert tax_item["level"] in ["info", "safe", "suspicious", "malicious"]


def test_metadata_inclusion() -> None:
    """Test that metadata is properly included in the report."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "test.com")
        rep = analyzer.execute()

        assert "metadata" in rep.full_report
        metadata = rep.full_report["metadata"]
        assert metadata["Name"] == "EmergingThreats Analyzer"
        assert "VERSION" in metadata


def test_threat_level_determination() -> None:
    """Test threat level determination logic."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("domain", "malicious.com")

        # Test malicious categories with high scores
        level = analyzer._determine_threat_level([{"category": "CnC", "score": 85}])
        assert level == "malicious"

        # Test suspicious categories (need score >= 100 for YELLOW categories)
        level = analyzer._determine_threat_level([{"category": "DynDNS", "score": 100}])
        assert level == "suspicious"

        # Test safe categories
        level = analyzer._determine_threat_level([{"category": "Utility", "score": 10}])
        assert level == "safe"

        # Test empty reputation
        level = analyzer._determine_threat_level([])
        assert level == "info"


def test_hash_extraction() -> None:
    """Test hash extraction from file data types."""
    with patch("requests.Session", return_value=DummyEmergingThreatsSession()):
        analyzer = build_analyzer("hash", "abc123def456")

        # Test file hash calculation (mock file)
        with patch("builtins.open", mock_open(read_data=b"test content")):
            extracted_hash = analyzer._get_object_hash("test_file.exe")
            assert len(extracted_hash) == 32  # MD5 hash length
