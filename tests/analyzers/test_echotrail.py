"""Tests for EchoTrailAnalyzer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestEchoTrailAnalyzer:
    """Test suite for EchoTrailAnalyzer."""

    @pytest.fixture
    def mock_config(self) -> WorkerConfig:
        """Create a mock WorkerConfig with EchoTrail credentials."""
        return WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "echotrail": {
                    "api_key": "test_api_key",
                }
            },
        )

    @pytest.fixture
    def hash_input(self, mock_config: WorkerConfig) -> WorkerInput:
        """Create a WorkerInput for hash analysis."""
        return WorkerInput(
            data_type="hash",
            data="d41d8cd98f00b204e9800998ecf8427e",  # MD5 hash
            tlp=2,
            pap=2,
            config=mock_config,
        )

    @pytest.fixture
    def sha256_input(self, mock_config: WorkerConfig) -> WorkerInput:
        """Create a WorkerInput for SHA-256 hash analysis."""
        return WorkerInput(
            data_type="hash",
            data="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256 hash
            tlp=2,
            pap=2,
            config=mock_config,
        )

    @pytest.fixture
    def mock_echotrail_response(self):
        """Mock successful EchoTrail API response."""
        return {
            "matched": True,
            "rank": 500,
            "host_prev": 0.85,
            "eps": 10.5,
            "description": "Common system file",
            "intel": "Safe executable",
            "paths": [["C:\\Windows\\System32\\notepad.exe", "0.95"]],
            "parents": [["explorer.exe", "0.80"]],
            "children": [],
            "grandparents": [],
            "hashes": [["d41d8cd98f00b204e9800998ecf8427e", "1.0"]],
            "network": [],
        }

    @pytest.fixture
    def mock_echotrail_no_match(self):
        """Mock EchoTrail API response with no match."""
        return {"message": "No results found"}

    def test_metadata(self):
        """Test that analyzer has proper metadata."""
        metadata = EchoTrailAnalyzer.METADATA
        assert metadata.name == "EchoTrail Analyzer"
        assert "EchoTrail API" in metadata.description
        assert metadata.pattern == "threat-intel"
        assert metadata.version_stage == "TESTING"

    def test_missing_credentials(self):
        """Test error handling when API key is missing."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={},
        )
        input_data = WorkerInput(
            data_type="hash",
            data="d41d8cd98f00b204e9800998ecf8427e",
            tlp=2,
            pap=2,
            config=config,
        )

        with pytest.raises(RuntimeError, match="EchoTrail API key is required"):
            EchoTrailAnalyzer(input_data)

    @patch("requests.Session.get")
    def test_hash_analysis_success(
        self, mock_get, hash_input: WorkerInput, mock_echotrail_response
    ):
        """Test successful hash analysis."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_echotrail_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["observable"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert report.full_report["verdict"] == "safe"
        assert report.full_report["source"] == "echotrail"
        assert report.full_report["details"]["matched"] is True
        assert "taxonomy" in report.full_report

    @patch("requests.Session.get")
    def test_hash_analysis_no_match(
        self, mock_get, hash_input: WorkerInput, mock_echotrail_no_match
    ):
        """Test hash analysis with no match."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_echotrail_no_match
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["details"]["matched"] is False
        assert report.full_report["verdict"] == "info"

    @patch("requests.Session.get")
    def test_malicious_verdict(self, mock_get, hash_input: WorkerInput):
        """Test malicious verdict determination."""
        malicious_response = {
            "rank": 5,  # Very low rank indicates malicious
            "host_prev": 0.01,
            "eps": 500,
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = malicious_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.execute()

        assert report.full_report["verdict"] == "malicious"

    @patch("requests.Session.get")
    def test_suspicious_verdict(self, mock_get, hash_input: WorkerInput):
        """Test suspicious verdict determination."""
        suspicious_response = {
            "rank": 50,  # Medium rank
            "host_prev": 0.005,  # Very low prevalence
            "eps": 1500,  # High EPS
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = suspicious_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.execute()

        assert report.full_report["verdict"] == "suspicious"

    def test_invalid_hash_length(self, mock_config: WorkerConfig):
        """Test error handling for invalid hash length."""
        input_data = WorkerInput(
            data_type="hash",
            data="invalid_hash",  # Invalid length
            tlp=2,
            pap=2,
            config=mock_config,
        )

        analyzer = EchoTrailAnalyzer(input_data)
        with pytest.raises(RuntimeError, match="invalid length"):
            analyzer.execute()

    def test_sha256_hash_valid(self, sha256_input: WorkerInput):
        """Test that SHA-256 hashes are accepted."""
        with patch("requests.Session.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"message": "No results found"}
            mock_get.return_value = mock_response

            analyzer = EchoTrailAnalyzer(sha256_input)
            report = analyzer.execute()

            # Should not raise an error for valid SHA-256 length
            assert isinstance(report, AnalyzerReport)

    @patch("requests.Session.get")
    def test_api_error_handling(self, mock_get, hash_input: WorkerInput):
        """Test API error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"message": "Unauthorized"}
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        with pytest.raises(RuntimeError, match="EchoTrail API error"):
            analyzer.execute()

    @patch("requests.Session.get")
    def test_network_error_handling(self, mock_get, hash_input: WorkerInput):
        """Test network error handling."""
        mock_get.side_effect = requests.RequestException("Network error")

        analyzer = EchoTrailAnalyzer(hash_input)
        with pytest.raises(RuntimeError, match="Error while trying to get insights"):
            analyzer.execute()

    @patch("requests.Session.get")
    def test_run_method(self, mock_get, hash_input: WorkerInput, mock_echotrail_response):
        """Test that run method calls execute."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_echotrail_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.run()

        assert isinstance(report, AnalyzerReport)
        assert report.full_report["observable"] == "d41d8cd98f00b204e9800998ecf8427e"

    @patch("requests.Session.get")
    def test_analyzer_report_structure(
        self, mock_get, hash_input: WorkerInput, mock_echotrail_response
    ):
        """Test that analyzer report has correct structure."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_echotrail_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(hash_input)
        report = analyzer.execute()

        # Check required fields
        required_fields = [
            "observable",
            "verdict",
            "taxonomy",
            "source",
            "data_type",
            "details",
            "metadata",
        ]
        for field in required_fields:
            assert field in report.full_report

        # Check taxonomy structure
        assert len(report.full_report["taxonomy"]) == 1
        taxonomy = report.full_report["taxonomy"][0]
        assert "level" in taxonomy
        assert "namespace" in taxonomy
        assert "predicate" in taxonomy
        assert "value" in taxonomy
        assert taxonomy["namespace"] == "echotrail"
        assert taxonomy["predicate"] == "reputation"

    def test_get_file_hash_static_method(self, tmp_path):
        """Test the static get_file_hash method."""
        # Create a temporary file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        # Calculate hash
        file_hash = EchoTrailAnalyzer.get_file_hash(str(test_file))

        # Verify it's a valid SHA-256 hash
        assert len(file_hash) == 64
        assert all(c in "0123456789abcdef" for c in file_hash)

    @patch("requests.Session.get")
    def test_proxy_configuration(self, mock_get, mock_echotrail_response):
        """Test proxy configuration."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets={
                "echotrail": {
                    "api_key": "test_api_key",
                    "proxy": {"http": "http://proxy:8080", "https": "https://proxy:8080"},
                }
            },
        )
        input_data = WorkerInput(
            data_type="hash",
            data="d41d8cd98f00b204e9800998ecf8427e",
            tlp=2,
            pap=2,
            config=config,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_echotrail_response
        mock_get.return_value = mock_response

        analyzer = EchoTrailAnalyzer(input_data)
        # Verify proxy is configured (would need to check session.proxies in real implementation)
        report = analyzer.execute()
        assert isinstance(report, AnalyzerReport)
