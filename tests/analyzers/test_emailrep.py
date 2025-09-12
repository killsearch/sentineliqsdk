from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.emailrep import EmailRepAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


class DummyEmailRepClient:
    """Mock EmailRep client for testing."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def query(self, email: str) -> dict[str, Any]:
        """Mock query method that returns different responses based on email."""
        if email == "malicious@example.com":
            return {
                "email": email,
                "reputation": "low",
                "suspicious": True,
                "references": 10,
                "details": {"blacklisted": True, "malicious_activity": True, "spam": True},
            }
        if email == "suspicious@example.com":
            return {
                "email": email,
                "reputation": "medium",
                "suspicious": True,
                "references": 3,
                "details": {"blacklisted": False, "malicious_activity": False, "spam": True},
            }
        if email == "safe@example.com":
            return {
                "email": email,
                "reputation": "high",
                "suspicious": False,
                "references": 0,
                "details": {"blacklisted": False, "malicious_activity": False, "spam": False},
            }
        # Default safe response
        return {
            "email": email,
            "reputation": "none",
            "suspicious": False,
            "references": 0,
            "details": {},
        }


def build_analyzer(data_type: DataType, data: str, api_key: str | None = None) -> EmailRepAnalyzer:
    """Helper function to build EmailRepAnalyzer with test configuration."""
    secrets = {}
    if api_key:
        secrets["emailrep"] = {"api_key": api_key}

    cfg = WorkerConfig(secrets=secrets)
    return EmailRepAnalyzer(WorkerInput(data_type=data_type, data=data, config=cfg))


def test_email_analysis_malicious() -> None:
    """Test malicious email detection."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "malicious@example.com", "test_key")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "emailrep"
        assert len(rep.full_report["taxonomy"]) > 0


def test_email_analysis_suspicious() -> None:
    """Test suspicious email detection."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "suspicious@example.com", "test_key")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "suspicious"
        assert rep.full_report["source"] == "emailrep"


def test_email_analysis_safe() -> None:
    """Test safe email detection."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "safe@example.com", "test_key")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["source"] == "emailrep"


def test_email_analysis_without_api_key() -> None:
    """Test email analysis without API key (should still work with limited functionality)."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "test@example.com")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] in ["safe", "suspicious", "malicious"]
        assert rep.full_report["source"] == "emailrep"


def test_unsupported_data_type() -> None:
    """Test that unsupported data types raise appropriate errors."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("ip", "1.2.3.4", "test_key")
        with pytest.raises(ValueError, match="EmailRep only supports mail data type"):
            analyzer.execute()


def test_api_error_handling() -> None:
    """Test handling of API errors."""

    class ErrorEmailRepClient:
        def __init__(self, api_key: str | None = None):
            pass

        def query(self, email: str) -> dict[str, Any]:
            raise Exception("API Error: Rate limit exceeded")

    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", ErrorEmailRepClient):
        analyzer = build_analyzer("mail", "test@example.com", "test_key")
        with pytest.raises(Exception, match="API Error.*"):
            analyzer.execute()


def test_run_method() -> None:
    """Test that run method returns the same as execute."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "test@example.com", "test_key")
        execute_result = analyzer.execute()
        run_result = analyzer.run()
        assert execute_result.full_report == run_result.full_report


def test_taxonomy_structure() -> None:
    """Test that taxonomy is properly structured."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "suspicious@example.com", "test_key")
        rep = analyzer.execute()

        taxonomy = rep.full_report["taxonomy"]
        assert len(taxonomy) > 0

        # Check taxonomy structure
        tax_item = taxonomy[0]
        assert "level" in tax_item
        assert "namespace" in tax_item
        assert "predicate" in tax_item
        assert "value" in tax_item

        assert tax_item["namespace"] == "EmailRep"
        assert tax_item["level"] in ["info", "safe", "suspicious", "malicious"]


def test_metadata_inclusion() -> None:
    """Test that metadata is properly included in the report."""
    with patch("sentineliqsdk.analyzers.emailrep.EmailRep", DummyEmailRepClient):
        analyzer = build_analyzer("mail", "test@example.com", "test_key")
        rep = analyzer.execute()

        assert "metadata" in rep.full_report
        metadata = rep.full_report["metadata"]
        assert metadata["Name"] == "EmailRep Analyzer"
        assert "VERSION" in metadata
