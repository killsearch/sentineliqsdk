"""Tests for CIRCL PassiveSSL Analyzer."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.circl_passivessl import CirclPassivesslAnalyzer


class TestCirclPassivesslAnalyzer:
    """Test cases for CirclPassivesslAnalyzer."""

    @pytest.fixture
    def secrets(self):
        """Return test secrets configuration."""
        return {
            "circl_passivessl": {
                "username": "test_user",
                "password": "test_password",
            }
        }

    @pytest.fixture
    def input_data_ip(self, secrets):
        """Return test input data for IP analysis."""
        return WorkerInput(
            data_type="ip",
            data="1.2.3.4",
            tlp=2,
            pap=2,
            config=WorkerConfig(secrets=secrets),
        )

    @pytest.fixture
    def input_data_hash(self, secrets):
        """Return test input data for hash analysis."""
        return WorkerInput(
            data_type="hash",
            data="a1b2c3d4e5f6789012345678901234567890abcd",
            tlp=2,
            pap=2,
            config=WorkerConfig(secrets=secrets),
        )

    @pytest.fixture
    def mock_ip_response(self):
        """Return mock IP query response."""
        return {
            "1.2.3.4": {
                "certificates": [
                    "a1b2c3d4e5f6789012345678901234567890abcd",
                    "b2c3d4e5f6789012345678901234567890abcde1",
                ],
                "subjects": {
                    "a1b2c3d4e5f6789012345678901234567890abcd": {
                        "values": ["CN=example.com, O=Example Corp"]
                    },
                    "b2c3d4e5f6789012345678901234567890abcde1": {
                        "values": ["CN=test.example.com, O=Test Corp"]
                    },
                },
            }
        }

    @pytest.fixture
    def mock_cert_query_response(self):
        """Return mock certificate query response."""
        return {
            "hits": 5,
            "seen": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
        }

    @pytest.fixture
    def mock_cert_fetch_response(self):
        """Return mock certificate fetch response."""
        return {
            "subject": "CN=example.com, O=Example Corp",
            "issuer": "CN=Example CA, O=Example CA Corp",
            "serial": "1234567890",
            "not_before": "2023-01-01T00:00:00Z",
            "not_after": "2024-01-01T00:00:00Z",
        }

    @patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client")
    def test_ip_analysis_success(self, mock_client, input_data_ip, mock_ip_response):
        """Test successful IP analysis."""
        # Mock HTTP client
        mock_session = Mock()
        mock_response = Mock()
        mock_response.json.return_value = mock_ip_response
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_client.return_value = mock_session

        analyzer = CirclPassivesslAnalyzer(input_data_ip)
        report = analyzer.execute()

        # Verify report structure
        assert report.success is True
        assert "full_report" in report.__dict__

        full_report = report.full_report
        assert full_report["observable"] == "1.2.3.4"
        assert full_report["verdict"] == "safe"  # 2 certificates <= threshold
        assert full_report["data_type"] == "ip"
        assert full_report["source"] == "circl_passivessl"

        # Verify taxonomy
        taxonomy = full_report["taxonomy"]
        assert len(taxonomy) == 1
        assert taxonomy[0]["namespace"] == "CIRCL"
        assert taxonomy[0]["predicate"] == "PassiveSSL"
        assert taxonomy[0]["value"] == "2 records"
        assert taxonomy[0]["level"] == "safe"

        # Verify details
        details = full_report["details"]
        assert details["ip"] == "1.2.3.4"
        assert len(details["certificates"]) == 2
        assert (
            details["certificates"][0]["fingerprint"] == "a1b2c3d4e5f6789012345678901234567890abcd"
        )
        assert details["certificates"][0]["subject"] == "CN=example.com, O=Example Corp"

    @patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client")
    def test_ip_analysis_no_results(self, mock_client, input_data_ip):
        """Test IP analysis with no results."""
        # Mock HTTP client with empty response
        mock_session = Mock()
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_client.return_value = mock_session

        analyzer = CirclPassivesslAnalyzer(input_data_ip)
        report = analyzer.execute()

        full_report = report.full_report
        assert full_report["verdict"] == "info"  # No results
        assert full_report["details"]["certificates"] == []

    @patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client")
    def test_hash_analysis_success(
        self, mock_client, input_data_hash, mock_cert_query_response, mock_cert_fetch_response
    ):
        """Test successful hash analysis."""
        # Mock HTTP client
        mock_session = Mock()

        # First call for query
        mock_query_response = Mock()
        mock_query_response.json.return_value = mock_cert_query_response
        mock_query_response.raise_for_status.return_value = None

        # Second call for fetch
        mock_fetch_response = Mock()
        mock_fetch_response.json.return_value = mock_cert_fetch_response
        mock_fetch_response.raise_for_status.return_value = None

        mock_session.get.side_effect = [mock_query_response, mock_fetch_response]
        mock_client.return_value = mock_session

        analyzer = CirclPassivesslAnalyzer(input_data_hash)
        report = analyzer.execute()

        # Verify report structure
        assert report.success is True
        full_report = report.full_report
        assert full_report["observable"] == "a1b2c3d4e5f6789012345678901234567890abcd"
        assert full_report["verdict"] == "suspicious"  # 5 hits > threshold
        assert full_report["data_type"] == "hash"

        # Verify details
        details = full_report["details"]
        assert details["query"]["hits"] == 5
        assert "1.2.3.4" in details["query"]["seen"]
        assert details["cert"]["subject"] == "CN=example.com, O=Example Corp"

    @patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client")
    def test_hash_analysis_no_results(self, mock_client, input_data_hash):
        """Test hash analysis with no results."""
        # Mock HTTP client with empty responses
        mock_session = Mock()
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_client.return_value = mock_session

        analyzer = CirclPassivesslAnalyzer(input_data_hash)
        report = analyzer.execute()

        full_report = report.full_report
        assert full_report["verdict"] == "info"  # No results
        assert full_report["details"]["query"] == {}
        assert full_report["details"]["cert"] == {}

    def test_invalid_data_type(self, secrets):
        """Test analyzer with invalid data type."""
        input_data = WorkerInput(
            data_type="domain",
            data="example.com",
            tlp=2,
            pap=2,
            config=WorkerConfig(secrets=secrets),
        )

        with patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client"):
            analyzer = CirclPassivesslAnalyzer(input_data)
            with pytest.raises(RuntimeError):
                analyzer.execute()

    def test_invalid_hash_length(self, secrets):
        """Test analyzer with invalid hash length."""
        input_data = WorkerInput(
            data_type="hash",
            data="invalid_hash",
            tlp=2,
            pap=2,
            config=WorkerConfig(secrets=secrets),
        )

        with patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client"):
            analyzer = CirclPassivesslAnalyzer(input_data)
            with pytest.raises(RuntimeError):
                analyzer.execute()

    def test_cidr_not_supported(self, secrets):
        """Test analyzer with CIDR notation."""
        input_data = WorkerInput(
            data_type="ip",
            data="1.2.3.0/24",
            tlp=2,
            pap=2,
            config=WorkerConfig(secrets=secrets),
        )

        with patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client"):
            analyzer = CirclPassivesslAnalyzer(input_data)
            with pytest.raises(RuntimeError):
                analyzer.execute()

    @patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client")
    def test_verdict_levels(self, mock_client, secrets):
        """Test different verdict levels based on result counts."""
        test_cases = [
            (0, "info"),
            (1, "safe"),
            (2, "safe"),
            (3, "safe"),
            (4, "suspicious"),
            (10, "suspicious"),
        ]

        for result_count, expected_verdict in test_cases:
            input_data = WorkerInput(
                data_type="ip",
                data="1.2.3.4",
                tlp=2,
                pap=2,
                config=WorkerConfig(secrets=secrets),
            )

            # Mock response with specific certificate count
            mock_session = Mock()
            mock_response = Mock()
            if result_count == 0:
                mock_response.json.return_value = {}
            else:
                mock_response.json.return_value = {
                    "1.2.3.4": {
                        "certificates": [f"cert{i}" for i in range(result_count)],
                        "subjects": {
                            f"cert{i}": {"values": [f"CN=test{i}.com"]} for i in range(result_count)
                        },
                    }
                }
            mock_response.raise_for_status.return_value = None
            mock_session.get.return_value = mock_response
            mock_client.return_value = mock_session

            analyzer = CirclPassivesslAnalyzer(input_data)
            report = analyzer.execute()

            assert report.full_report["verdict"] == expected_verdict

    def test_metadata_included(self, input_data_ip):
        """Test that metadata is included in the report."""
        with patch("sentineliqsdk.analyzers.circl_passivessl.httpx.Client"):
            analyzer = CirclPassivesslAnalyzer(input_data_ip)
            report = analyzer.execute()

            full_report = report.full_report
            assert "metadata" in full_report
            metadata = full_report["metadata"]
            assert metadata["Name"] == "CIRCL PassiveSSL Analyzer"
            assert (
                metadata["Description"]
                == "Query CIRCL PassiveSSL for certificate and IP relationships"
            )
            assert metadata["pattern"] == "threat-intel"
            assert metadata["VERSION"] == "STABLE"
