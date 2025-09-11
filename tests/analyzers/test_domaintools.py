"""Tests for DomainToolsAnalyzer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.domaintools import DomainToolsAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestDomainToolsAnalyzer:
    """Test suite for DomainToolsAnalyzer."""

    @pytest.fixture
    def mock_config(self) -> WorkerConfig:
        """Create a mock WorkerConfig with DomainTools credentials."""
        return WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "domaintools": {
                    "username": "test_user",
                    "api_key": "test_key",
                }
            },
        )

    @pytest.fixture
    def domain_input(self, mock_config: WorkerConfig) -> WorkerInput:
        """Create a WorkerInput for domain analysis."""
        return WorkerInput(
            data_type="domain",
            data="example.com",
            tlp=2,
            pap=2,
            config=mock_config,
        )

    @pytest.fixture
    def ip_input(self, mock_config: WorkerConfig) -> WorkerInput:
        """Create a WorkerInput for IP analysis."""
        return WorkerInput(
            data_type="ip",
            data="8.8.8.8",
            tlp=2,
            pap=2,
            config=mock_config,
        )

    @pytest.fixture
    def email_input(self, mock_config: WorkerConfig) -> WorkerInput:
        """Create a WorkerInput for email analysis."""
        return WorkerInput(
            data_type="mail",
            data="admin@example.com",
            tlp=2,
            pap=2,
            config=mock_config,
        )

    @pytest.fixture
    def mock_domaintools_api(self):
        """Mock DomainTools API responses."""
        with patch("sentineliqsdk.analyzers.domaintools.API") as mock_api:
            # Mock API instance
            api_instance = MagicMock()
            mock_api.return_value = api_instance

            # Mock response objects
            mock_response = MagicMock()
            mock_response.response.return_value = {
                "response": {"risk_score": 25},
                "results": [{"domain": "example.com", "risk_score": 25}],
            }

            # Configure method responses
            api_instance.iris_enrich.return_value = mock_response
            api_instance.domain_profile.return_value = mock_response
            api_instance.risk.return_value = mock_response
            api_instance.whois.return_value = mock_response
            api_instance.whois_history.return_value = mock_response
            api_instance.reverse_ip.return_value = mock_response
            api_instance.host_domains.return_value = mock_response
            api_instance.reverse_whois.return_value = mock_response

            yield api_instance

    def test_metadata(self):
        """Test that analyzer has proper metadata."""
        metadata = DomainToolsAnalyzer.METADATA
        assert metadata.name == "DomainTools Analyzer"
        assert "DomainTools" in metadata.description
        assert metadata.pattern == "threat-intel"
        assert metadata.version_stage == "TESTING"

    def test_missing_credentials(self):
        """Test that analyzer fails gracefully without credentials."""
        config = WorkerConfig()
        worker_input = WorkerInput(
            data_type="domain",
            data="example.com",
            tlp=2,
            pap=2,
            config=config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)

        with pytest.raises(RuntimeError, match="Missing DomainTools credentials"):
            analyzer.execute()

    def test_domain_analysis(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test domain analysis functionality."""
        analyzer = DomainToolsAnalyzer(domain_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.success is True
        assert isinstance(report.full_report, dict)

        report_dict = report.full_report
        assert report_dict["observable"] == "example.com"
        assert report_dict["data_type"] == "domain"
        assert report_dict["source"] == "domaintools"
        assert "verdict" in report_dict
        assert "taxonomy" in report_dict
        assert "details" in report_dict

        # Verify API methods were called
        mock_domaintools_api.iris_enrich.assert_called_once_with("example.com")
        mock_domaintools_api.domain_profile.assert_called_once_with("example.com")
        mock_domaintools_api.risk.assert_called_once_with("example.com")

    def test_ip_analysis(self, ip_input: WorkerInput, mock_domaintools_api):
        """Test IP analysis functionality."""
        analyzer = DomainToolsAnalyzer(ip_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        report_dict = report.full_report

        assert report_dict["observable"] == "8.8.8.8"
        assert report_dict["data_type"] == "ip"
        assert report_dict["verdict"] == "info"

        # Verify IP-specific API methods were called
        mock_domaintools_api.reverse_ip.assert_called_once_with("8.8.8.8")
        mock_domaintools_api.host_domains.assert_called_once_with("8.8.8.8")

    def test_email_analysis(self, email_input: WorkerInput, mock_domaintools_api):
        """Test email analysis functionality."""
        analyzer = DomainToolsAnalyzer(email_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        report_dict = report.full_report

        assert report_dict["observable"] == "admin@example.com"
        assert report_dict["data_type"] == "mail"
        assert report_dict["verdict"] == "info"

        # Verify email-specific API methods were called
        mock_domaintools_api.reverse_whois.assert_called_once_with(terms="admin@example.com")

    def test_dynamic_method_call_via_config(self, mock_domaintools_api):
        """Test dynamic method calling via configuration."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "domaintools": {
                    "username": "test_user",
                    "api_key": "test_key",
                }
            },
            params={
                "domaintools": {"method": "iris_enrich", "params": {"domains": ["example.com"]}}
            },
        )

        worker_input = WorkerInput(
            data_type="domain",
            data="example.com",
            tlp=2,
            pap=2,
            config=config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["verdict"] == "info"
        assert "details" in report_dict
        assert report_dict["details"]["method"] == "iris_enrich"

    def test_dynamic_method_call_via_payload(self, mock_config: WorkerConfig, mock_domaintools_api):
        """Test dynamic method calling via JSON payload."""
        payload = {"method": "domain_profile", "params": {"domain": "example.com"}}

        worker_input = WorkerInput(
            data_type="other",
            data=json.dumps(payload),
            tlp=2,
            pap=2,
            config=mock_config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["verdict"] == "info"
        assert report_dict["details"]["method"] == "domain_profile"

    def test_invalid_method(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test that invalid methods are rejected."""
        analyzer = DomainToolsAnalyzer(domain_input)

        with pytest.raises(RuntimeError):
            analyzer._call_dynamic("invalid_method")

    def test_invalid_json_payload(self, mock_config: WorkerConfig):
        """Test that invalid JSON payloads are handled."""
        worker_input = WorkerInput(
            data_type="other",
            data="invalid json",
            tlp=2,
            pap=2,
            config=mock_config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)

        with pytest.raises(RuntimeError):
            analyzer.execute()

    def test_unsupported_data_type(self, mock_config: WorkerConfig, mock_domaintools_api):
        """Test that unsupported data types are handled."""
        worker_input = WorkerInput(
            data_type="other",
            data="test",
            tlp=2,
            pap=2,
            config=mock_config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)

        with pytest.raises(RuntimeError):
            analyzer.execute()

    def test_verdict_determination_malicious(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test verdict determination for malicious domains."""
        # Mock high risk score
        mock_response = MagicMock()
        mock_response.response.return_value = {"risk_score": 85}
        mock_domaintools_api.risk.return_value = mock_response

        analyzer = DomainToolsAnalyzer(domain_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["verdict"] == "malicious"

    def test_verdict_determination_suspicious(
        self, domain_input: WorkerInput, mock_domaintools_api
    ):
        """Test verdict determination for suspicious domains."""
        # Mock medium risk score
        mock_response = MagicMock()
        mock_response.response.return_value = {"risk_score": 55}
        mock_domaintools_api.risk.return_value = mock_response

        analyzer = DomainToolsAnalyzer(domain_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["verdict"] == "suspicious"

    def test_verdict_determination_safe(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test verdict determination for safe domains."""
        # Mock low risk score
        mock_response = MagicMock()
        mock_response.response.return_value = {"risk_score": 15}
        mock_domaintools_api.risk.return_value = mock_response

        analyzer = DomainToolsAnalyzer(domain_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["verdict"] == "safe"

    def test_api_error_handling(self, domain_input: WorkerInput):
        """Test API error handling."""
        with patch("sentineliqsdk.analyzers.domaintools.API") as mock_api:
            mock_api.side_effect = Exception("API connection failed")

            analyzer = DomainToolsAnalyzer(domain_input)

            with pytest.raises(Exception, match="API connection failed"):
                analyzer.execute()

    def test_run_method(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test that run method calls execute."""
        analyzer = DomainToolsAnalyzer(domain_input)

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = MagicMock(spec=AnalyzerReport)

            result = analyzer.run()

            mock_execute.assert_called_once()
            assert result is mock_execute.return_value

    def test_allowed_methods_coverage(self):
        """Test that all allowed methods are properly defined."""
        from sentineliqsdk.analyzers.domaintools import ALLOWED_METHODS

        # Verify key methods are included
        expected_methods = {
            "iris_enrich",
            "domain_profile",
            "risk",
            "whois",
            "whois_history",
            "reverse_ip",
            "reverse_whois",
            "reputation",
        }

        assert expected_methods.issubset(ALLOWED_METHODS)
        assert len(ALLOWED_METHODS) > 10  # Should have many methods

    def test_fqdn_data_type(self, mock_config: WorkerConfig, mock_domaintools_api):
        """Test that FQDN data type is handled like domain."""
        worker_input = WorkerInput(
            data_type="fqdn",
            data="www.example.com",
            tlp=2,
            pap=2,
            config=mock_config,
        )

        analyzer = DomainToolsAnalyzer(worker_input)
        report = analyzer.execute()

        report_dict = report.full_report
        assert report_dict["data_type"] == "fqdn"
        assert "details" in report_dict

        # Verify domain analysis methods were called
        mock_domaintools_api.iris_enrich.assert_called_once_with("www.example.com")

    def test_analyzer_report_structure(self, domain_input: WorkerInput, mock_domaintools_api):
        """Test that analyzer returns proper AnalyzerReport structure."""
        analyzer = DomainToolsAnalyzer(domain_input)
        result = analyzer.run()

        # Test AnalyzerReport structure
        assert hasattr(result, "success")
        assert hasattr(result, "summary")
        assert hasattr(result, "artifacts")
        assert hasattr(result, "operations")
        assert hasattr(result, "full_report")

        # Test that it's a proper AnalyzerReport instance
        assert isinstance(result, AnalyzerReport)
        assert result.success is True
        assert isinstance(result.full_report, dict)
