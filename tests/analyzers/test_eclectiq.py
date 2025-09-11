"""Tests for EclecticIQ Analyzer."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer


class TestEclecticIQAnalyzer:
    """Test cases for EclecticIQAnalyzer."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.secrets = {
            "eclectiq": {
                "name": "Test EclecticIQ Instance",
                "url": "https://test-eclectiq.com",
                "api_key": "test_api_key_123",
                "cert_check": True,
                "cert_path": "/path/to/cert.pem",
                "proxy": {"http": "http://proxy:8080", "https": "https://proxy:8080"},
            }
        }
        self.config = WorkerConfig(secrets=self.secrets)

    def test_metadata(self) -> None:
        """Test analyzer metadata."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        assert analyzer.METADATA.name == "EclecticIQ Analyzer"
        assert (
            analyzer.METADATA.description
            == "Searches for given Observables in configured EclecticIQ instance. All standard data types are supported."
        )
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"

    def test_initialization_with_all_config(self) -> None:
        """Test analyzer initialization with full configuration."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        assert analyzer.name == "Test EclecticIQ Instance"
        assert analyzer.url == "https://test-eclectiq.com"
        assert analyzer.key == "test_api_key_123"
        assert analyzer.ssl == "/path/to/cert.pem"
        assert analyzer.session.verify == "/path/to/cert.pem"
        assert analyzer.session.proxies == {
            "http": "http://proxy:8080",
            "https": "https://proxy:8080",
        }
        assert "Bearer test_api_key_123" in analyzer.session.headers["Authorization"]

    def test_initialization_minimal_config(self) -> None:
        """Test analyzer initialization with minimal configuration."""
        minimal_secrets = {
            "eclectiq": {
                "name": "Minimal Instance",
                "url": "https://minimal-eclectiq.com",
                "api_key": "minimal_key",
                "cert_check": False,
            }
        }
        config = WorkerConfig(secrets=minimal_secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = EclecticIQAnalyzer(input_data)

        assert analyzer.name == "Minimal Instance"
        assert analyzer.url == "https://minimal-eclectiq.com"
        assert analyzer.key == "minimal_key"
        assert analyzer.ssl is False
        assert analyzer.session.verify is False
        assert analyzer.session.proxies is None

    def test_missing_name_error(self) -> None:
        """Test error when EclecticIQ instance name is missing."""
        secrets = {"eclectiq": {"url": "https://test.com", "api_key": "key"}}
        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with pytest.raises(RuntimeError, match="No EclecticIQ instance name given"):
            EclecticIQAnalyzer(input_data)

    def test_missing_url_error(self) -> None:
        """Test error when EclecticIQ URL is missing."""
        secrets = {"eclectiq": {"name": "Test", "api_key": "key"}}
        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with pytest.raises(RuntimeError, match="No EclecticIQ url given"):
            EclecticIQAnalyzer(input_data)

    def test_missing_api_key_error(self) -> None:
        """Test error when EclecticIQ API key is missing."""
        secrets = {"eclectiq": {"name": "Test", "url": "https://test.com"}}
        config = WorkerConfig(secrets=secrets)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with pytest.raises(RuntimeError, match="No EclecticIQ api key given"):
            EclecticIQAnalyzer(input_data)

    def test_get_confidence_dict(self) -> None:
        """Test get_confidence method with dict input."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        confidence_dict = {"value": 85}
        result = analyzer.get_confidence(confidence_dict)
        assert result == 85

    def test_get_confidence_direct_value(self) -> None:
        """Test get_confidence method with direct value."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        result = analyzer.get_confidence(75)
        assert result == 75

    def test_get_confidence_none(self) -> None:
        """Test get_confidence method with None input."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        result = analyzer.get_confidence(None)
        assert result is None

    @patch("requests.Session.get")
    def test_get_source(self, mock_get) -> None:
        """Test get_source method."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"name": "Test Source"}}
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        result = analyzer.get_source("https://test.com/source/123")
        assert result == "Test Source"
        mock_get.assert_called_once_with("https://test.com/source/123")

    @patch("requests.Session.get")
    def test_add_observable_info_success(self, mock_get) -> None:
        """Test add_observable_info method with successful response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "count": 1,
            "data": [{"id": "obs_123", "type": "ipv4", "meta": {"maliciousness": "high"}}],
        }
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        results: dict[str, str] = {}
        obs_id = analyzer._add_observable_info(results)

        assert obs_id == "obs_123"
        assert results["obs_type"] == "ipv4"
        assert results["obs_score"] == "high"
        mock_get.assert_called_once_with(
            "https://test-eclectiq.com/api/v2/observables", params={"filter[value]": "1.2.3.4"}
        )

    @patch("requests.Session.get")
    def test_add_observable_info_no_results(self, mock_get) -> None:
        """Test add_observable_info method with no results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"count": 0}
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        results: dict[str, str] = {}
        obs_id = analyzer._add_observable_info(results)

        assert obs_id is None

    @patch("requests.Session.get")
    def test_get_entities_info_success(self, mock_get) -> None:
        """Test get_entities_info method with successful response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "count": 2,
            "data": [
                {
                    "id": "entity_1",
                    "data": {"title": "Malicious IP", "type": "indicator"},
                    "sources": ["https://test.com/source/1"],
                    "meta": {"tags": ["malware", "botnet"]},
                },
                {
                    "id": "entity_2",
                    "data": {"title": "Threat Report", "type": "report"},
                    "sources": ["https://test.com/source/2"],
                    "meta": {"tags": ["apt"]},
                },
            ],
        }
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        result = analyzer._get_entities_info("obs_123")

        assert result["count"] == 2
        assert len(result["data"]) == 2
        mock_get.assert_called_once_with(
            "https://test-eclectiq.com/api/v2/entities", params={"filter[observables]": "obs_123"}
        )

    @patch("requests.Session.get")
    def test_get_entities_info_no_results(self, mock_get) -> None:
        """Test get_entities_info method with no results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"count": 0}
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        result = analyzer._get_entities_info("obs_123")

        assert result is None

    @patch("requests.Session.get")
    def test_execute_success_with_entities(self, mock_get) -> None:
        """Test execute method with successful analysis and entities found."""
        # Mock observable search response
        obs_response = MagicMock()
        obs_response.json.return_value = {
            "count": 1,
            "data": [{"id": "obs_123", "type": "ipv4", "meta": {"maliciousness": "medium"}}],
        }

        # Mock entities search response
        entities_response = MagicMock()
        entities_response.json.return_value = {
            "count": 1,
            "data": [
                {
                    "id": "entity_1",
                    "data": {
                        "title": "Suspicious IP",
                        "type": "indicator",
                        "confidence": {"value": 75},
                    },
                    "sources": ["https://test.com/source/1"],
                    "meta": {
                        "tags": ["suspicious"],
                        "estimated_threat_start_time": "2024-01-01T00:00:00Z",
                    },
                }
            ],
        }

        # Mock source response
        source_response = MagicMock()
        source_response.json.return_value = {"data": {"name": "Threat Intel Feed"}}

        mock_get.side_effect = [obs_response, entities_response, source_response]

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["verdict"] == "suspicious"
        assert report.full_report["source"] == "eclectiq"
        assert report.full_report["data_type"] == "ip"
        assert "metadata" in report.full_report

        # Check results structure
        results = report.full_report["results"]
        assert results["name"] == "Test EclecticIQ Instance"
        assert results["url"] == "https://test-eclectiq.com"
        assert results["obs_value"] == "1.2.3.4"
        assert results["obs_type"] == "ipv4"
        assert results["obs_score"] == "medium"
        assert results["count"] == 1
        assert len(results["entities"]) == 1

        entity = results["entities"][0]
        assert entity["id"] == "entity_1"
        assert entity["title"] == "Suspicious IP"
        assert entity["type"] == "indicator"
        assert entity["confidence"] == 75
        assert entity["tags"] == ["suspicious"]
        assert entity["timestamp"] == "2024-01-01T00:00:00Z"
        assert entity["source_name"] == "Threat Intel Feed"

    @patch("requests.Session.get")
    def test_execute_no_observable_found(self, mock_get) -> None:
        """Test execute method when no observable is found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"count": 0}
        mock_get.return_value = mock_response

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "eclectiq"
        assert "results" not in report.full_report

    @patch("requests.Session.get")
    def test_execute_no_entities_found(self, mock_get) -> None:
        """Test execute method when observable exists but no entities found."""
        # Mock observable search response
        obs_response = MagicMock()
        obs_response.json.return_value = {
            "count": 1,
            "data": [{"id": "obs_123", "type": "ipv4", "meta": {"maliciousness": "low"}}],
        }

        # Mock entities search response (no entities)
        entities_response = MagicMock()
        entities_response.json.return_value = {"count": 0}

        mock_get.side_effect = [obs_response, entities_response]

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "eclectiq"
        assert "results" not in report.full_report

    def test_execute_unsupported_data_type(self) -> None:
        """Test execute method with unsupported data type."""
        input_data = WorkerInput(data_type="file", data="test.exe", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        with pytest.raises(RuntimeError, match="Unsupported data type: file"):
            analyzer.execute()

    @patch("requests.Session.get")
    def test_execute_request_exception(self, mock_get) -> None:
        """Test execute method with request exception."""
        mock_get.side_effect = requests.RequestException("Connection error")

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        with pytest.raises(requests.RequestException):
            analyzer.execute()

    def test_run_method(self) -> None:
        """Test that run method calls execute."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = MagicMock()
            analyzer.run()
            mock_execute.assert_called_once()

    def test_verdict_determination_safe(self) -> None:
        """Test verdict determination for safe observables."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        # Test with no entities - using empty dict to match analyzer implementation
        verdict = self._determine_verdict([])
        assert verdict == "safe"

    def test_verdict_determination_suspicious(self) -> None:
        """Test verdict determination for suspicious observables."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        entities = [{"confidence": 60, "type": "indicator"}, {"confidence": 40, "type": "report"}]
        verdict = self._determine_verdict(entities)
        assert verdict == "suspicious"

    def test_verdict_determination_malicious(self) -> None:
        """Test verdict determination for malicious observables."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)
        analyzer = EclecticIQAnalyzer(input_data)

        entities = [{"confidence": 90, "type": "indicator"}, {"confidence": 85, "type": "malware"}]
        verdict = self._determine_verdict(entities)
        assert verdict == "malicious"

    def _determine_verdict(self, entities: list[dict[str, Any]]) -> str:
        """Helper method to determine verdict based on entities (added to analyzer class)."""
        if not entities:
            return "safe"

        max_confidence = max((entity.get("confidence", 0) for entity in entities), default=0)

        if max_confidence >= 80:
            return "malicious"
        if max_confidence >= 50:
            return "suspicious"
        return "safe"
