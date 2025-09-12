from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock, patch

import pytest

from sentineliqsdk.analyzers.dshield import DShieldAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


def build_analyzer(data: str = "1.2.3.4", data_type: DataType = "ip") -> DShieldAnalyzer:
    """Build a DShieldAnalyzer instance for testing."""
    cfg = WorkerConfig()
    return DShieldAnalyzer(WorkerInput(data_type=data_type, data=data, config=cfg))


def mock_dshield_response_safe() -> dict[str, Any]:
    """Mock DShield API response for a safe IP."""
    return {
        "ip": {
            "number": "1.2.3.4",
            "count": 0,
            "attacks": 0,
            "maxdate": "2024-01-01",
            "mindate": "2024-01-01",
            "updated": "2024-01-01 12:00:00",
            "comment": "No reports",
            "as": "12345",
            "asname": "Example AS",
            "ascountry": "US",
            "asabusecontact": "abuse@example.com",
            "assize": "1024",
            "network": "1.2.3.0/24",
        }
    }


def mock_dshield_response_malicious() -> dict[str, Any]:
    """Mock DShield API response for a malicious IP."""
    return {
        "ip": {
            "number": "192.168.1.100",
            "count": 150,
            "attacks": 1000,
            "maxdate": "2024-01-15",
            "mindate": "2024-01-01",
            "updated": "2024-01-15 18:30:00",
            "comment": "Multiple attack reports",
            "as": "54321",
            "asname": "Malicious AS",
            "ascountry": "XX",
            "asabusecontact": "abuse@malicious.com",
            "assize": "2048",
            "network": "192.168.1.0/24",
            "threatfeeds": [
                {"name": "feed1", "lastseen": "2024-01-15"},
                {"name": "feed2", "lastseen": "2024-01-14"},
            ],
        }
    }


def mock_dshield_response_suspicious() -> dict[str, Any]:
    """Mock DShield API response for a suspicious IP."""
    return {
        "ip": {
            "number": "10.0.0.1",
            "count": 5,
            "attacks": 10,
            "maxdate": "2024-01-10",
            "mindate": "2024-01-05",
            "updated": "2024-01-10 10:15:00",
            "comment": "Few reports",
            "as": "98765",
            "asname": "Suspicious AS",
            "ascountry": "CN",
            "asabusecontact": "abuse@suspicious.com",
            "assize": "512",
            "network": "10.0.0.0/24",
            "threatfeeds": [{"name": "feed3", "lastseen": "2024-01-10"}],
        }
    }


def test_execute_safe_ip() -> None:
    """Test DShield analysis for a safe IP."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_dshield_response_safe()

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")
        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["source"] == "dshield"
        assert len(report.full_report["taxonomy"]) >= 1

        # Check taxonomy
        taxonomies = report.full_report["taxonomy"]
        score_taxonomy = next((t for t in taxonomies if t["predicate"] == "score"), None)
        assert score_taxonomy is not None
        assert score_taxonomy["level"] == "safe"

        # Check values
        values = report.full_report["values"]
        assert values["ip"] == "1.2.3.4"
        assert values["attacks"] == 0
        assert values["reputation"] == "safe"


def test_execute_malicious_ip() -> None:
    """Test DShield analysis for a malicious IP."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_dshield_response_malicious()

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("192.168.1.100")
        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["verdict"] == "malicious"
        assert report.full_report["observable"] == "192.168.1.100"

        # Check taxonomy
        taxonomies = report.full_report["taxonomy"]
        score_taxonomy = next((t for t in taxonomies if t["predicate"] == "score"), None)
        assert score_taxonomy is not None
        assert score_taxonomy["level"] == "malicious"

        # Check for attack taxonomy
        attack_taxonomy = next((t for t in taxonomies if t["predicate"] == "attacks"), None)
        assert attack_taxonomy is not None
        assert attack_taxonomy["level"] == "malicious"

        # Check for threat feeds taxonomy
        feeds_taxonomy = next((t for t in taxonomies if t["predicate"] == "threat-feeds"), None)
        assert feeds_taxonomy is not None
        assert feeds_taxonomy["level"] == "malicious"

        # Check values
        values = report.full_report["values"]
        assert values["attacks"] == 1000
        assert values["threatfeedscount"] == 2
        assert values["reputation"] == "malicious"


def test_execute_suspicious_ip() -> None:
    """Test DShield analysis for a suspicious IP."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_dshield_response_suspicious()

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("10.0.0.1")
        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["verdict"] == "suspicious"
        assert report.full_report["observable"] == "10.0.0.1"

        # Check values
        values = report.full_report["values"]
        assert values["attacks"] == 10
        assert values["threatfeedscount"] == 1
        assert values["reputation"] == "suspicious"


def test_execute_unsupported_data_type() -> None:
    """Test DShield analysis with unsupported data type."""
    analyzer = build_analyzer("example.com", "domain")

    with pytest.raises(RuntimeError, match="Unsupported data type"):
        analyzer.execute()


def test_execute_http_error() -> None:
    """Test DShield analysis with HTTP error."""
    with patch("httpx.Client.get", side_effect=Exception("Network error")):
        analyzer = build_analyzer("1.2.3.4")

        with pytest.raises(RuntimeError, match="HTTP call to DShield failed"):
            analyzer.execute()


def test_execute_api_error_response() -> None:
    """Test DShield analysis with API error response."""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")

        with pytest.raises(RuntimeError, match="Unable to query DShield API"):
            analyzer.execute()


def test_execute_invalid_json_response() -> None:
    """Test DShield analysis with invalid JSON response."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")

        with pytest.raises(RuntimeError, match="Invalid JSON response from DShield"):
            analyzer.execute()


def test_execute_no_data_found() -> None:
    """Test DShield analysis when no data is found for IP."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"error": "No data found"}

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")

        with pytest.raises(RuntimeError, match="No data found for the provided IP"):
            analyzer.execute()


def test_artifacts_extraction() -> None:
    """Test artifact extraction from DShield data."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_dshield_response_safe()

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")
        report = analyzer.execute()

        artifacts = analyzer.artifacts(report.full_report)

        # Should extract AS and abuse contact
        as_artifacts = [a for a in artifacts if a.data_type == "asn"]
        mail_artifacts = [a for a in artifacts if a.data_type == "mail"]

        assert len(as_artifacts) >= 1
        assert len(mail_artifacts) >= 1
        assert as_artifacts[0].data == "12345"
        assert mail_artifacts[0].data == "abuse@example.com"


def test_timeout_configuration() -> None:
    """Test timeout configuration."""
    cfg = WorkerConfig(params={"dshield": {"timeout": 60}})
    analyzer = DShieldAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4", config=cfg))

    assert analyzer._timeout() == 60


def test_run_method() -> None:
    """Test that run method calls execute."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_dshield_response_safe()

    with patch("httpx.Client.get", return_value=mock_response):
        analyzer = build_analyzer("1.2.3.4")
        report = analyzer.run()

        assert report.success is True
        assert report.full_report["verdict"] == "safe"
