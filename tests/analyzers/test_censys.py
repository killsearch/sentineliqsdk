"""Tests for Censys Analyzer."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.censys import ALLOWED_METHODS, CensysAnalyzer


class TestCensysAnalyzer:
    """Test cases for CensysAnalyzer."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.secrets = {
            "censys": {
                "personal_access_token": "test_token",
                "organization_id": "test_org_id",
            }
        }
        self.config = WorkerConfig(secrets=self.secrets)

    def _setup_mock_sdk(self, mock_sdk_class, mock_sdk=None):
        """Helper to set up mock SDK with context manager support."""
        if mock_sdk is None:
            mock_sdk = MagicMock()
        mock_sdk_class.return_value.__enter__ = MagicMock(return_value=mock_sdk)
        mock_sdk_class.return_value.__exit__ = MagicMock(return_value=None)
        return mock_sdk

    def test_metadata(self) -> None:
        """Test analyzer metadata."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        assert analyzer.METADATA.name == "Censys Analyzer"
        assert (
            analyzer.METADATA.description
            == "Comprehensive Censys Platform API analyzer with full method coverage"
        )
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "STABLE"

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_client_initialization(self, mock_sdk_class) -> None:
        """Test client initialization."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with analyzer._client() as client:
            assert client == mock_sdk
            mock_sdk_class.assert_called_once_with(
                personal_access_token="test_token", organization_id="test_org_id"
            )

    def test_missing_token_error(self) -> None:
        """Test error when personal access token is missing."""
        config = WorkerConfig(secrets={})
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._client()

    def test_missing_organization_id_error(self) -> None:
        """Test error when organization ID is missing."""
        secrets = {"censys": {"personal_access_token": "test_token"}}
        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._client()

    def test_allowed_methods(self) -> None:
        """Test that all expected methods are in the allowlist."""
        expected_collections_methods = {
            "collections_list",
            "collections_create",
            "collections_delete",
            "collections_get",
            "collections_update",
            "collections_list_events",
            "collections_aggregate",
            "collections_search",
        }

        expected_global_data_methods = {
            "global_data_get_certificates",
            "global_data_get_certificate",
            "global_data_get_hosts",
            "global_data_get_host",
            "global_data_get_host_timeline",
            "global_data_get_web_properties",
            "global_data_get_web_property",
            "global_data_aggregate",
            "global_data_search",
        }

        assert expected_collections_methods.issubset(ALLOWED_METHODS)
        assert expected_global_data_methods.issubset(ALLOWED_METHODS)

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_call_dynamic_collections_method(self, mock_sdk_class) -> None:
        """Test dynamic call to collections method."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.collections.list.return_value = {"collections": []}

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        result = analyzer._call_dynamic("collections_list", {"page_size": 10})

        mock_sdk.collections.list.assert_called_once_with(page_size=10)
        assert result == {"collections": []}

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_call_dynamic_global_data_method(self, mock_sdk_class) -> None:
        """Test dynamic call to global data method."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        result = analyzer._call_dynamic("global_data_search", {"query": "test"})

        mock_sdk.global_data.search.assert_called_once_with(query="test")
        assert result == {"hits": []}

    def test_call_dynamic_unsupported_method(self) -> None:
        """Test error when calling unsupported method."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._call_dynamic("unsupported_method")

    def test_call_dynamic_invalid_params(self) -> None:
        """Test error when params is not a mapping."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._call_dynamic("collections_list", "invalid_params")  # type: ignore

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_ip(self, mock_sdk_class) -> None:
        """Test IP analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.get_host.return_value = {"ip": "1.2.3.4", "services": []}
        mock_sdk.global_data.get_host_timeline.return_value = {"timeline": []}
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        result = analyzer._analyze_ip("1.2.3.4")

        assert "host" in result
        assert "timeline" in result
        assert "search_results" in result
        mock_sdk.global_data.get_host.assert_called_once_with(ip="1.2.3.4")
        mock_sdk.global_data.get_host_timeline.assert_called_once_with(ip="1.2.3.4")

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_domain(self, mock_sdk_class) -> None:
        """Test domain analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.search.return_value = {"hits": []}
        mock_sdk.global_data.get_web_property.return_value = {"web_property": {}}

        input_data = WorkerInput(data_type="domain", data="example.com", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        result = analyzer._analyze_domain("example.com")

        assert "domain" in result
        assert "web_search_results" in result
        assert "certificate_search_results" in result
        assert "web_properties" in result

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_certificate(self, mock_sdk_class) -> None:
        """Test certificate analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.get_certificate.return_value = {"certificate": {}}
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="hash", data="test_hash", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        result = analyzer._analyze_certificate("test_hash")

        assert "certificate" in result
        assert "search_results" in result
        mock_sdk.global_data.get_certificate.assert_called_once_with(fingerprint="test_hash")

    def test_verdict_from_censys_safe(self) -> None:
        """Test verdict determination for safe data."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        payload: dict[str, Any] = {"host": {"services": []}}
        verdict = analyzer._verdict_from_censys(payload)

        assert verdict == "safe"

    def test_verdict_from_censys_suspicious(self) -> None:
        """Test verdict determination for suspicious data."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        payload = {"host": {"services": [{"port": 22}]}}
        verdict = analyzer._verdict_from_censys(payload)

        assert verdict == "suspicious"

    def test_verdict_from_censys_malicious(self) -> None:
        """Test verdict determination for malicious data."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        payload = {"host": {"services": [{"banner": "malware detected"}]}}
        verdict = analyzer._verdict_from_censys(payload)

        assert verdict == "malicious"

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_execute_ip_analysis(self, mock_sdk_class) -> None:
        """Test execute method for IP analysis."""
        mock_sdk = MagicMock()
        mock_sdk_class.return_value = mock_sdk
        mock_sdk.global_data.get_host.return_value = {"ip": "1.2.3.4", "services": []}
        mock_sdk.global_data.get_host_timeline.return_value = {"timeline": []}
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "censys"
        assert report.full_report["data_type"] == "ip"
        assert "metadata" in report.full_report

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_execute_domain_analysis(self, mock_sdk_class) -> None:
        """Test execute method for domain analysis."""
        mock_sdk = MagicMock()
        mock_sdk_class.return_value = mock_sdk
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="domain", data="example.com", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "example.com"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "censys"
        assert report.full_report["data_type"] == "domain"

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_execute_certificate_analysis(self, mock_sdk_class) -> None:
        """Test execute method for certificate analysis."""
        mock_sdk = MagicMock()
        mock_sdk_class.return_value = mock_sdk
        mock_sdk.global_data.get_certificate.return_value = {"certificate": {}}
        mock_sdk.global_data.search.return_value = {"hits": []}

        input_data = WorkerInput(data_type="hash", data="test_hash", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "test_hash"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "censys"
        assert report.full_report["data_type"] == "hash"

    def test_execute_unsupported_data_type(self) -> None:
        """Test error for unsupported data type."""
        input_data = WorkerInput(data_type="url", data="https://example.com", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer.execute()

    def test_execute_config_method(self) -> None:
        """Test execute with configuration method."""
        config = WorkerConfig(
            secrets=self.secrets, params={"censys": {"method": "collections_list"}}
        )
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = CensysAnalyzer(input_data)

        with patch.object(analyzer, "_call_dynamic") as mock_call:
            mock_call.return_value = {"collections": []}
            report = analyzer.execute()

            assert report.success is True
            assert report.full_report["verdict"] == "info"
            assert report.full_report["details"]["method"] == "collections_list"
            mock_call.assert_called_once_with("collections_list", {})

    def test_execute_other_dtype_valid_json(self) -> None:
        """Test execute with other data type and valid JSON."""
        input_data = WorkerInput(
            data_type="other",
            data=json.dumps({"method": "collections_list", "params": {"page_size": 10}}),
            config=self.config,
        )
        analyzer = CensysAnalyzer(input_data)

        with patch.object(analyzer, "_call_dynamic") as mock_call:
            mock_call.return_value = {"collections": []}
            report = analyzer.execute()

            assert report.success is True
            assert report.full_report["verdict"] == "info"
            assert report.full_report["details"]["method"] == "collections_list"
            assert report.full_report["details"]["params"] == {"page_size": 10}
            mock_call.assert_called_once_with("collections_list", {"page_size": 10})

    def test_execute_other_dtype_invalid_json(self) -> None:
        """Test error with invalid JSON in other data type."""
        input_data = WorkerInput(data_type="other", data="invalid json", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer.execute()

    def test_execute_other_dtype_missing_method(self) -> None:
        """Test error when method is missing in other data type."""
        input_data = WorkerInput(
            data_type="other", data=json.dumps({"params": {"page_size": 10}}), config=self.config
        )
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer.execute()

    def test_run_method(self) -> None:
        """Test run method calls execute."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with patch.object(analyzer, "execute") as mock_execute:
            analyzer.run()
            mock_execute.assert_called_once()

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_ip_exception_handling(self, mock_sdk_class) -> None:
        """Test exception handling in IP analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.get_host.side_effect = Exception("API Error")

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._analyze_ip("1.2.3.4")

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_domain_exception_handling(self, mock_sdk_class) -> None:
        """Test exception handling in domain analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.search.side_effect = Exception("API Error")

        input_data = WorkerInput(data_type="domain", data="example.com", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._analyze_domain("example.com")

    @patch("sentineliqsdk.analyzers.censys.SDK")
    def test_analyze_certificate_exception_handling(self, mock_sdk_class) -> None:
        """Test exception handling in certificate analysis."""
        mock_sdk = self._setup_mock_sdk(mock_sdk_class)
        mock_sdk.global_data.get_certificate.side_effect = Exception("API Error")

        input_data = WorkerInput(data_type="hash", data="test_hash", config=self.config)
        analyzer = CensysAnalyzer(input_data)

        with pytest.raises(RuntimeError):
            analyzer._analyze_certificate("test_hash")
