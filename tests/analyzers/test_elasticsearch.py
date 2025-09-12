"""Tests for ElasticsearchAnalyzer."""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.elasticsearch import ElasticsearchAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestElasticsearchAnalyzer:
    """Test cases for ElasticsearchAnalyzer."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "elasticsearch": {
                    "host": "https://localhost:9200",
                    "username": "test_user",
                    "password": "test_pass",
                }
            },
            params={
                "elasticsearch": {
                    "index": "test-*",
                    "max_results": 50,
                    "timeout": 10,
                }
            },
        )

    def test_metadata(self) -> None:
        """Test analyzer metadata."""
        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        assert analyzer.METADATA.name == "Elasticsearch Analyzer"
        assert "Elasticsearch" in analyzer.METADATA.description
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_search_ip_safe(self, mock_client: Mock) -> None:
        """Test IP search with safe verdict."""
        # Mock Elasticsearch response
        mock_response = Mock()
        mock_response.json.return_value = {
            "hits": {
                "total": {"value": 0},
                "hits": [],
            }
        }
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["observable"] == "192.168.1.1"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "elasticsearch"
        assert len(report.full_report["taxonomy"]) == 1
        assert report.full_report["taxonomy"][0]["level"] == "safe"
        assert report.full_report["taxonomy"][0]["namespace"] == "elasticsearch"
        assert report.full_report["taxonomy"][0]["predicate"] == "search"

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_search_domain_malicious(self, mock_client: Mock) -> None:
        """Test domain search with malicious verdict."""
        # Mock Elasticsearch response with malware indicators
        mock_response = Mock()
        mock_response.json.return_value = {
            "hits": {
                "total": {"value": 5},
                "hits": [
                    {
                        "_source": {
                            "message": "malware detected from evil.com",
                            "@timestamp": "2024-01-01T00:00:00Z",
                        }
                    },
                    {
                        "_source": {
                            "message": "trojan activity observed",
                            "@timestamp": "2024-01-01T00:01:00Z",
                        }
                    },
                ],
            }
        }
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        input_data = WorkerInput(
            data_type="domain",
            data="evil.com",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["observable"] == "evil.com"
        assert report.full_report["verdict"] == "malicious"
        assert report.full_report["source"] == "elasticsearch"
        assert len(report.full_report["taxonomy"]) == 1
        assert report.full_report["taxonomy"][0]["level"] == "malicious"

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_search_suspicious(self, mock_client: Mock) -> None:
        """Test search with suspicious verdict."""
        # Mock Elasticsearch response with suspicious indicators
        mock_response = Mock()
        mock_response.json.return_value = {
            "hits": {
                "total": {"value": 10},
                "hits": [
                    {
                        "_source": {
                            "message": "suspicious activity detected",
                            "@timestamp": "2024-01-01T00:00:00Z",
                        }
                    },
                    {
                        "_source": {
                            "message": "anomaly in network traffic",
                            "@timestamp": "2024-01-01T00:01:00Z",
                        }
                    },
                    {
                        "_source": {
                            "message": "suspicious process execution",
                            "@timestamp": "2024-01-01T00:02:00Z",
                        }
                    },
                    {
                        "_source": {
                            "message": "suspicious file access",
                            "@timestamp": "2024-01-01T00:03:00Z",
                        }
                    },
                ],
            }
        }
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        input_data = WorkerInput(
            data_type="ip",
            data="10.0.0.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["observable"] == "10.0.0.1"
        assert report.full_report["verdict"] == "suspicious"
        assert report.full_report["source"] == "elasticsearch"

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_config_method_call(self, mock_client: Mock) -> None:
        """Test dynamic API call via config method."""
        # Mock Elasticsearch response
        mock_response = Mock()
        mock_response.json.return_value = {
            "cluster_name": "test-cluster",
            "status": "green",
            "number_of_nodes": 3,
        }
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        config_with_method = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets=self.config.secrets,
            params={
                "elasticsearch": {
                    "method": "_cluster/health",
                    "params": {"level": "cluster"},
                }
            },
        )

        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=config_with_method,
        )
        analyzer = ElasticsearchAnalyzer(input_data)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["verdict"] == "info"
        assert report.full_report["taxonomy"][0]["predicate"] == "api-call"
        assert "method" in report.full_report["details"]
        assert report.full_report["details"]["method"] == "_cluster/health"

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_other_data_type_json_payload(self, mock_client: Mock) -> None:
        """Test dynamic call via JSON payload when data_type == other."""
        # Mock Elasticsearch response
        mock_response = Mock()
        mock_response.json.return_value = {
            "indices": {
                "test-index": {"health": "green"},
            }
        }
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        payload = {
            "endpoint": "_cat/indices",
            "method": "GET",
            "params": {"format": "json"},
        }

        input_data = WorkerInput(
            data_type="other",
            data=json.dumps(payload),
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["verdict"] == "info"
        assert report.full_report["taxonomy"][0]["predicate"] == "api-call"
        assert "endpoint" in report.full_report["details"]
        assert report.full_report["details"]["endpoint"] == "_cat/indices"

    def test_invalid_other_data_type(self) -> None:
        """Test error handling for invalid 'other' data type format."""
        input_data = WorkerInput(
            data_type="other",
            data="test",  # Invalid format, should be JSON
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "data must be a JSON string" in str(exc_info.value)

    def test_invalid_json_payload(self) -> None:
        """Test error handling for invalid JSON payload."""
        input_data = WorkerInput(
            data_type="other",
            data="invalid json",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "JSON string" in str(exc_info.value)

    def test_missing_endpoint_in_payload(self) -> None:
        """Test error handling for missing endpoint in JSON payload."""
        payload = {"method": "GET"}

        input_data = WorkerInput(
            data_type="other",
            data=json.dumps(payload),
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "Missing 'endpoint'" in str(exc_info.value)

    def test_unsupported_endpoint(self) -> None:
        """Test error handling for unsupported endpoints."""
        payload = {
            "endpoint": "_dangerous/delete",
            "method": "DELETE",
        }

        input_data = WorkerInput(
            data_type="other",
            data=json.dumps(payload),
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "Unsupported Elasticsearch endpoint" in str(exc_info.value)

    def test_missing_host_configuration(self) -> None:
        """Test error handling for missing host configuration."""
        config_no_host = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={"elasticsearch": {}},  # No host
        )

        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=config_no_host,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "Missing Elasticsearch host" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_api_key_authentication(self, mock_client: Mock) -> None:
        """Test API key authentication."""
        # Mock Elasticsearch response
        mock_response = Mock()
        mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_response.raise_for_status.return_value = None

        mock_client_instance = Mock()
        mock_client_instance.request.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance

        config_api_key = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "elasticsearch": {
                    "host": "https://localhost:9200",
                    "api_key": "test_api_key",
                }
            },
        )

        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=config_api_key,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        # Get client config to verify API key is used
        client_config = analyzer._get_client_config()
        assert "headers" in client_config
        assert "Authorization" in client_config["headers"]
        assert "ApiKey test_api_key" in client_config["headers"]["Authorization"]

    def test_run_method(self) -> None:
        """Test that run() method calls execute()."""
        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = Mock(spec=AnalyzerReport)
            result = analyzer.run()

            mock_execute.assert_called_once()
            assert result == mock_execute.return_value

    @patch("sentineliqsdk.analyzers.elasticsearch.httpx.Client")
    def test_http_error_handling(self, mock_client: Mock) -> None:
        """Test HTTP error handling."""
        import httpx

        mock_client_instance = Mock()
        mock_client_instance.request.side_effect = httpx.HTTPError("Connection failed")
        mock_client.return_value.__enter__.return_value = mock_client_instance

        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "Elasticsearch API request failed" in str(exc_info.value)

    def test_security_indicators_analysis(self) -> None:
        """Test security indicators analysis logic."""
        input_data = WorkerInput(
            data_type="ip",
            data="192.168.1.1",
            config=self.config,
        )
        analyzer = ElasticsearchAnalyzer(input_data)

        # Test malicious indicators
        malicious_results = {
            "hits": {
                "total": {"value": 3},
                "hits": [
                    {"_source": {"message": "malware detected"}},
                    {"_source": {"message": "virus found"}},
                    {"_source": {"message": "trojan activity"}},
                ],
            }
        }

        analysis = analyzer._analyze_search_results(malicious_results)
        verdict = analyzer._determine_verdict(analysis)

        assert analysis["security_indicators"]["malware_signatures"] == 3
        assert verdict == "malicious"

        # Test suspicious indicators
        suspicious_results = {
            "hits": {
                "total": {"value": 5},
                "hits": [
                    {"_source": {"message": "suspicious activity"}},
                    {"_source": {"message": "suspicious behavior"}},
                    {"_source": {"message": "suspicious process"}},
                    {"_source": {"message": "suspicious network"}},
                ],
            }
        }

        analysis = analyzer._analyze_search_results(suspicious_results)
        verdict = analyzer._determine_verdict(analysis)

        assert analysis["security_indicators"]["suspicious_processes"] == 4
        assert verdict == "suspicious"
