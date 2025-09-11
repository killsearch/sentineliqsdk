"""Tests for CrowdSec analyzer."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer
from sentineliqsdk.clients.crowdsec import CrowdSecAPIError, CrowdSecRateLimitError


class TestCrowdSecAnalyzer:
    """Test cases for CrowdSec analyzer."""

    def test_analyzer_metadata(self):
        """Test analyzer metadata is properly configured."""
        analyzer = CrowdSecAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4"))

        assert analyzer.METADATA.name == "CrowdSec CTI Analyzer"
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"

    def test_missing_api_key_error(self):
        """Test error when API key is missing."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=WorkerConfig(secrets={}))

        analyzer = CrowdSecAnalyzer(input_data=input_data)

        with pytest.raises(RuntimeError) as exc_info:
            analyzer.execute()

        # Check that error message contains API key requirement
        assert "Missing CrowdSec API key" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_successful_analysis(self, mock_client_class):
        """Test successful analysis with mock data."""
        # Mock client and response
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.return_value = {
            "reputation": "malicious",
            "as_name": "Evil Corp",
            "ip_range_score": 0.9,
            "attack_details": [{"name": "SSH Brute Force"}, {"name": "Port Scan"}],
            "behaviors": [{"name": "Suspicious Traffic"}],
            "cves": ["CVE-2023-1234", "CVE-2023-5678"],
        }

        # Create input with API key
        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="1.2.3.4", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()

        # Verify client was called correctly
        mock_client_class.assert_called_once_with("test-key")
        mock_client.get_ip_summary.assert_called_once_with("1.2.3.4")

        # Verify report structure
        assert report.success is True
        assert "observable" in report.full_report
        assert report.full_report["observable"] == "1.2.3.4"
        assert "taxonomy" in report.full_report
        assert "metadata" in report.full_report

        # Verify taxonomy entries
        taxonomy = report.full_report["taxonomy"]
        assert len(taxonomy) > 0

        # Check for reputation taxonomy
        reputation_tax = next((t for t in taxonomy if t["predicate"] == "Reputation"), None)
        assert reputation_tax is not None
        assert reputation_tax["level"] == "malicious"
        assert reputation_tax["value"] == "malicious"

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_rate_limit_error(self, mock_client_class):
        """Test handling of rate limit error."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.side_effect = CrowdSecRateLimitError("Rate limit exceeded")

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="1.2.3.4", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)

        with pytest.raises(RuntimeError) as exc_info:
            analyzer.execute()

        assert "CrowdSec rate limit exceeded" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_api_error(self, mock_client_class):
        """Test handling of API error."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.side_effect = CrowdSecAPIError("API error", 500)

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="1.2.3.4", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)

        with pytest.raises(RuntimeError) as exc_info:
            analyzer.execute()

        assert "CrowdSec API error" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_safe_reputation(self, mock_client_class):
        """Test analysis with safe reputation."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.return_value = {"reputation": "safe", "as_name": "Good Corp"}

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="8.8.8.8", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()

        # Check reputation taxonomy
        taxonomy = report.full_report["taxonomy"]
        reputation_tax = next((t for t in taxonomy if t["predicate"] == "Reputation"), None)
        assert reputation_tax is not None
        assert reputation_tax["level"] == "safe"
        assert reputation_tax["value"] == "safe"

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_suspicious_reputation(self, mock_client_class):
        """Test analysis with suspicious reputation."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.return_value = {
            "reputation": "suspicious",
            "behaviors": [{"name": "Unusual Traffic"}],
        }

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="5.6.7.8", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()

        # Check reputation taxonomy
        taxonomy = report.full_report["taxonomy"]
        reputation_tax = next((t for t in taxonomy if t["predicate"] == "Reputation"), None)
        assert reputation_tax is not None
        assert reputation_tax["level"] == "suspicious"
        assert reputation_tax["value"] == "suspicious"

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_not_found_case(self, mock_client_class):
        """Test analysis when no threat data is found."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.return_value = {
            "as_name": "Unknown Corp"
            # No reputation, attack_details, or behaviors
        }

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="9.9.9.9", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()

        # Check for "Not found" taxonomy
        taxonomy = report.full_report["taxonomy"]
        not_found_tax = next((t for t in taxonomy if t["predicate"] == "Threat"), None)
        assert not_found_tax is not None
        assert not_found_tax["level"] == "safe"
        assert not_found_tax["value"] == "Not found"

    def test_get_reputation_level(self):
        """Test reputation level conversion."""
        analyzer = CrowdSecAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4"))

        assert analyzer._get_reputation_level("malicious") == "malicious"
        assert analyzer._get_reputation_level("suspicious") == "suspicious"
        assert analyzer._get_reputation_level("safe") == "safe"
        assert analyzer._get_reputation_level("unknown") == "info"
        assert analyzer._get_reputation_level("MALICIOUS") == "malicious"  # Case insensitive

    @patch("sentineliqsdk.analyzers.crowdsec.CrowdSecClient")
    def test_comprehensive_taxonomy_building(self, mock_client_class):
        """Test building comprehensive taxonomy from all data types."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_ip_summary.return_value = {
            "reputation": "malicious",
            "as_name": "Evil Corp",
            "ip_range_score": 0.95,
            "history": {"last_seen": "2024-01-01T12:00:00Z"},
            "attack_details": [{"name": "SSH Brute Force"}, {"name": "Port Scan"}],
            "behaviors": [{"name": "Suspicious Traffic"}, {"name": "Data Exfiltration"}],
            "mitre_techniques": [{"name": "T1021.001"}, {"name": "T1041"}],
            "cves": ["CVE-2023-1234", "CVE-2023-5678"],
        }

        secrets = {"crowdsec": {"api_key": "test-key"}}
        input_data = WorkerInput(
            data_type="ip", data="1.2.3.4", config=WorkerConfig(secrets=secrets)
        )

        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()

        taxonomy = report.full_report["taxonomy"]

        # Check all expected taxonomy entries exist
        predicates = [t["predicate"] for t in taxonomy]

        assert "Reputation" in predicates
        assert "ASN" in predicates
        assert "Score" in predicates
        assert "LastSeen" in predicates
        assert "Attack" in predicates
        assert "Behavior" in predicates
        assert "Mitre" in predicates
        assert "CVE" in predicates

        # Verify specific values
        reputation_tax = next(t for t in taxonomy if t["predicate"] == "Reputation")
        assert reputation_tax["level"] == "malicious"
        assert reputation_tax["value"] == "malicious"

        asn_tax = next(t for t in taxonomy if t["predicate"] == "ASN")
        assert asn_tax["value"] == "Evil Corp"

        attack_taxes = [t for t in taxonomy if t["predicate"] == "Attack"]
        assert len(attack_taxes) == 2
        assert any(t["value"] == "SSH Brute Force" for t in attack_taxes)
        assert any(t["value"] == "Port Scan" for t in attack_taxes)

    def test_run_method(self):
        """Test that run method calls execute."""
        with (
            patch.object(CrowdSecAnalyzer, "execute") as mock_execute,
            patch("builtins.print") as mock_print,
        ):
            mock_report = Mock()
            mock_report.full_report = {"test": "data"}
            mock_execute.return_value = mock_report

            analyzer = CrowdSecAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4"))
            analyzer.run()

            mock_execute.assert_called_once()
            mock_print.assert_called_once()
