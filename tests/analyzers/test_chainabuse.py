"""Tests for ChainAbuse Analyzer."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.chainabuse import ChainAbuseAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


def build_analyzer(dtype: DataType, data: str) -> ChainAbuseAnalyzer:
    """Build a ChainAbuse analyzer with test configuration."""
    cfg = WorkerConfig(secrets={"chainabuse": {"api_key": "test-key"}})
    return ChainAbuseAnalyzer(WorkerInput(data_type=dtype, data=data, config=cfg))


def test_ip_analysis_malicious() -> None:
    """Test IP analysis with malicious reports."""
    mock_reports = {
        "data": [
            {
                "id": "123",
                "address": "1.2.3.4",
                "category": "scam",
                "confidence": 0.9,
                "reportedAt": "2024-01-01T00:00:00Z",
            }
        ],
        "count": 5,
    }
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("ip", "1.2.3.4")
        rep = analyzer.execute()

        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "chainabuse"
        assert rep.full_report["data_type"] == "ip"
        assert rep.full_report["observable"] == "1.2.3.4"
        assert rep.full_report["reports"]["count"] == 5


def test_url_analysis_suspicious() -> None:
    """Test URL analysis with suspicious reports."""
    mock_reports = {
        "data": [
            {
                "id": "456",
                "address": "https://malicious-site.com",
                "category": "phishing",
                "confidence": 0.7,
                "reportedAt": "2024-01-01T00:00:00Z",
            }
        ],
        "count": 2,
    }
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("url", "https://malicious-site.com")
        rep = analyzer.execute()

        assert rep.full_report["verdict"] == "suspicious"
        assert rep.full_report["source"] == "chainabuse"
        assert rep.full_report["data_type"] == "url"


def test_domain_analysis_safe() -> None:
    """Test domain analysis with no reports."""
    mock_reports = {"data": [], "count": 0}
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("domain", "safe-domain.com")
        rep = analyzer.execute()

        assert rep.full_report["verdict"] == "safe"
        assert rep.full_report["source"] == "chainabuse"
        assert rep.full_report["data_type"] == "domain"
        assert rep.full_report["reports"]["count"] == 0


def test_hash_analysis_sanctioned() -> None:
    """Test hash/blockchain address analysis with sanctioned address."""
    mock_reports = {"data": [], "count": 0}
    mock_sanctioned = {
        "sanctioned": True,
        "data": {
            "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "sanctionedAt": "2024-01-01T00:00:00Z",
            "reason": "OFAC sanctions",
        },
    }

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("hash", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        rep = analyzer.execute()

        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "chainabuse"
        assert rep.full_report["data_type"] == "hash"
        assert rep.full_report["sanctioned"]["sanctioned"] is True


def test_taxonomy_entries() -> None:
    """Test that taxonomy entries are properly created."""
    mock_reports = {"data": [], "count": 3}
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("ip", "1.2.3.4")
        rep = analyzer.execute()

        taxonomy = rep.full_report["taxonomy"]
        assert len(taxonomy) >= 3  # report-count, sanctioned, data-type

        # Check report count taxonomy
        report_tax = next(t for t in taxonomy if t["predicate"] == "report-count")
        assert report_tax["value"] == "3"
        assert report_tax["level"] == "suspicious"

        # Check sanctioned taxonomy
        sanctioned_tax = next(t for t in taxonomy if t["predicate"] == "sanctioned")
        assert sanctioned_tax["value"] == "False"
        assert sanctioned_tax["level"] == "safe"

        # Check data type taxonomy
        dtype_tax = next(t for t in taxonomy if t["predicate"] == "data-type")
        assert dtype_tax["value"] == "ip"
        assert dtype_tax["level"] == "info"


def test_metadata_included() -> None:
    """Test that metadata is included in the report."""
    mock_reports = {"data": [], "count": 0}
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("ip", "1.2.3.4")
        rep = analyzer.execute()

        metadata = rep.full_report["metadata"]
        assert metadata["Name"] == "ChainAbuse Analyzer"
        assert (
            metadata["Description"]
            == "Consulta reputação de endereços blockchain e URLs na ChainAbuse"
        )
        assert metadata["pattern"] == "threat-intel"
        assert metadata["VERSION"] == "TESTING"


def test_unsupported_data_type() -> None:
    """Test error handling for unsupported data types."""
    analyzer = build_analyzer("file", "test.txt")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_missing_api_key() -> None:
    """Test error handling for missing API key."""
    cfg = WorkerConfig(secrets={})  # No API key
    analyzer = ChainAbuseAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4", config=cfg))
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_custom_timeout_configuration() -> None:
    """Test custom timeout configuration."""
    cfg = WorkerConfig(
        secrets={"chainabuse": {"api_key": "test-key"}}, params={"chainabuse": {"timeout": 60}}
    )
    analyzer = ChainAbuseAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4", config=cfg))

    # Test that timeout is properly set
    assert analyzer._timeout() == 60.0


def test_default_timeout_configuration() -> None:
    """Test default timeout configuration."""
    analyzer = build_analyzer("ip", "1.2.3.4")
    assert analyzer._timeout() == 30.0


def test_auth_header_generation() -> None:
    """Test HTTP Basic Auth header generation."""
    analyzer = build_analyzer("ip", "1.2.3.4")
    auth_header = analyzer._get_auth_header()

    # Should be Basic auth with base64 encoded credentials
    assert auth_header.startswith("Basic ")

    # Decode and verify
    import base64

    encoded_part = auth_header.split(" ")[1]
    decoded = base64.b64decode(encoded_part).decode()
    assert decoded == "test-key:test-key"


def test_verdict_determination_logic() -> None:
    """Test the verdict determination logic."""
    analyzer = build_analyzer("ip", "1.2.3.4")

    # Test sanctioned = malicious
    reports_data = {"count": 0}
    sanctioned_data = {"sanctioned": True}
    verdict = analyzer._determine_verdict(reports_data, sanctioned_data)
    assert verdict == "malicious"

    # Test high report count = malicious
    reports_data = {"count": 5}
    sanctioned_data = {"sanctioned": False}
    verdict = analyzer._determine_verdict(reports_data, sanctioned_data)
    assert verdict == "malicious"

    # Test low report count = suspicious
    reports_data = {"count": 2}
    sanctioned_data = {"sanctioned": False}
    verdict = analyzer._determine_verdict(reports_data, sanctioned_data)
    assert verdict == "suspicious"

    # Test no reports = safe
    reports_data = {"count": 0}
    sanctioned_data = {"sanctioned": False}
    verdict = analyzer._determine_verdict(reports_data, sanctioned_data)
    assert verdict == "safe"


def test_run_method() -> None:
    """Test that run method executes without errors."""
    mock_reports = {"data": [], "count": 0}
    mock_sanctioned = {"sanctioned": False, "data": None}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(ChainAbuseAnalyzer, "_fetch_sanctioned_address", return_value=mock_sanctioned),
    ):
        analyzer = build_analyzer("ip", "1.2.3.4")
        # Should not raise any exceptions
        analyzer.run()


def test_http_error_handling() -> None:
    """Test HTTP error handling."""
    import httpx

    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = httpx.HTTPError(
            "Network error"
        )

        analyzer = build_analyzer("ip", "1.2.3.4")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_api_error_response() -> None:
    """Test API error response handling."""
    import httpx

    with patch("httpx.Client") as mock_client:
        mock_response = httpx.Response(500, text="Internal Server Error")
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response

        analyzer = build_analyzer("ip", "1.2.3.4")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_json_decode_error() -> None:
    """Test JSON decode error handling."""
    import httpx

    with patch("httpx.Client") as mock_client:
        mock_response = httpx.Response(200, text="Invalid JSON")
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response

        analyzer = build_analyzer("ip", "1.2.3.4")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_sanctioned_address_404_handling() -> None:
    """Test handling of 404 response for sanctioned address check."""
    import httpx

    with patch("httpx.Client") as mock_client:
        # Mock reports endpoint success
        reports_response = httpx.Response(200, json={"data": [], "count": 0})

        # Mock sanctioned endpoint 404
        sanctioned_response = httpx.Response(404, text="Not Found")

        mock_client.return_value.__enter__.return_value.get.side_effect = [
            reports_response,
            sanctioned_response,
        ]

        analyzer = build_analyzer("hash", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        rep = analyzer.execute()

        assert rep.full_report["sanctioned"]["sanctioned"] is False
        assert rep.full_report["verdict"] == "safe"


def test_sanctioned_address_exception_handling() -> None:
    """Test exception handling in sanctioned address check."""
    mock_reports = {"data": [], "count": 0}

    with (
        patch.object(ChainAbuseAnalyzer, "_fetch_reports", return_value=mock_reports),
        patch.object(
            ChainAbuseAnalyzer, "_fetch_sanctioned_address", side_effect=Exception("API Error")
        ),
    ):
        analyzer = build_analyzer("hash", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        rep = analyzer.execute()

        # Should continue with reports only
        assert rep.full_report["sanctioned"]["sanctioned"] is False
        assert rep.full_report["verdict"] == "safe"
