from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.mcap import MCAPAnalyzer


class TestMCAPAnalyzer:
    """Test cases for MCAP Analyzer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.secrets = {"mcap": {"api_key": "test_api_key"}}

        self.config = WorkerConfig(
            check_tlp=False,
            check_pap=False,
            auto_extract=False,
            params={
                "mcap_private_samples": False,
                "mcap_minimum_confidence": 80,
                "mcap_minimum_severity": 80,
                "mcap_polling_interval": 60,
                "mcap_max_sample_result_wait": 1000,
            },
            secrets=self.secrets,
        )

    def test_analyzer_initialization(self):
        """Test analyzer initialization with proper configuration."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        assert analyzer.api_key == "test_api_key"
        assert analyzer.private_samples is False
        assert analyzer.minimum_confidence == 80
        assert analyzer.minimum_severity == 80
        assert analyzer.polling_interval == 60
        assert analyzer.max_sample_result_wait == 1000
        assert analyzer.api_root == "https://mcap.cisecurity.org/api"

    def test_get_file_hash(self):
        """Test file hash calculation."""
        # Create a temporary file for testing
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            temp_file = f.name

        try:
            hash_result = MCAPAnalyzer.get_file_hash(temp_file)
            assert len(hash_result) == 64  # SHA256 hash length
            assert isinstance(hash_result, str)
        finally:
            os.unlink(temp_file)

    @patch("requests.Session")
    def test_check_feed_ip(self, mock_session_class):
        """Test checking IP feed."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"ip": "1.2.3.4", "confidence": 90, "severity": 85}]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        iocs = analyzer.check_feed("ip", "1.2.3.4")

        assert len(iocs) == 1
        assert iocs[0]["ip"] == "1.2.3.4"
        assert iocs[0]["confidence"] == 90

    @patch("requests.Session")
    def test_check_feed_domain(self, mock_session_class):
        """Test checking domain feed."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"domain": "example.com", "confidence": 95, "severity": 90}
        ]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="domain", data="example.com", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        iocs = analyzer.check_feed("domain", "example.com")

        assert len(iocs) == 1
        assert iocs[0]["domain"] == "example.com"

    @patch("requests.Session")
    def test_check_feed_url(self, mock_session_class):
        """Test checking URL feed."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"url": "https://example.com/malware", "confidence": 88, "severity": 92}
        ]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(
            data_type="url", data="https://example.com/malware", config=self.config
        )

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        iocs = analyzer.check_feed("url", "https://example.com/malware")

        assert len(iocs) == 1
        assert iocs[0]["url"] == "https://example.com/malware"

    @patch("requests.Session")
    def test_check_feed_hash(self, mock_session_class):
        """Test checking hash feed."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"sha256": "a" * 64, "confidence": 100, "severity": 100}]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="hash", data="a" * 64, config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        iocs = analyzer.check_feed("hash", "a" * 64)

        assert len(iocs) == 1
        assert iocs[0]["sha256"] == "a" * 64

    def test_check_feed_invalid_hash_length(self):
        """Test checking feed with invalid hash length."""
        input_data = WorkerInput(data_type="hash", data="invalid_hash", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        with pytest.raises(SystemExit):  # analyzer.error() calls sys.exit(1)
            analyzer.check_feed("hash", "invalid_hash")

    def test_check_feed_unsupported_data_type(self):
        """Test checking feed with unsupported data type."""
        input_data = WorkerInput(data_type="other", data="some_data", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        with pytest.raises(SystemExit):  # analyzer.error() calls sys.exit(1)
            analyzer.check_feed("other", "some_data")

    @patch("requests.Session")
    def test_get_sample_status_by_sha256(self, mock_session_class):
        """Test getting sample status by SHA256."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "test_id", "sha256": "a" * 64, "state": "succ", "status": "Analysis completed"}
        ]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="file", data="test_file.txt", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        status = analyzer.get_sample_status(sha256="a" * 64)

        assert status is not None
        assert status["id"] == "test_id"
        assert status["state"] == "succ"

    @patch("requests.Session")
    def test_get_sample_status_by_mcap_id(self, mock_session_class):
        """Test getting sample status by MCAP ID."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "test_id", "mcap_id": "12345", "state": "succ", "status": "Analysis completed"}
        ]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="file", data="test_file.txt", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        status = analyzer.get_sample_status(mcap_id="12345")

        assert status is not None
        assert status["id"] == "test_id"
        assert status["mcap_id"] == "12345"

    @patch("requests.Session")
    def test_get_sample_status_not_found(self, mock_session_class):
        """Test getting sample status when not found."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="file", data="test_file.txt", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        status = analyzer.get_sample_status(sha256="a" * 64)

        assert status is None

    @patch("requests.Session")
    def test_submit_file(self, mock_session_class):
        """Test file submission."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": "File submitted successfully",
            "sample": {
                "mcap_id": "12345",
                "filename": "test_file.txt",
                "created_at": "2023-01-01T00:00:00Z",
                "private": False,
                "source": 6,
                "note": "",
                "user": "test_user",
            },
        }

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="file", data="test_file.txt", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        # Create a temporary file for testing
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            temp_file = f.name

        try:
            response = analyzer.submit_file(temp_file)

            assert response["message"] == "File submitted successfully"
            assert response["sample"]["mcap_id"] == "12345"
            assert response["sample"]["filename"] == "test_file.txt"
        finally:
            os.unlink(temp_file)

    @patch("requests.Session")
    def test_execute_ip_analysis(self, mock_session_class):
        """Test executing IP analysis."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"ip": "1.2.3.4", "confidence": 90, "severity": 85}]

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "1.2.3.4"
        assert report.full_report["data_type"] == "ip"
        assert len(report.full_report["iocs"]) == 1
        assert report.full_report["ioc_count"] == 1
        assert len(report.full_report["taxonomy"]) == 1
        assert report.full_report["taxonomy"][0]["level"] == "malicious"
        assert "metadata" in report.full_report

    @patch("requests.Session")
    def test_execute_domain_analysis_no_iocs(self, mock_session_class):
        """Test executing domain analysis with no IOCs found."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        input_data = WorkerInput(data_type="domain", data="example.com", config=self.config)

        analyzer = MCAPAnalyzer(input_data)
        analyzer.session = mock_session

        report = analyzer.execute()

        assert report.success is True
        assert report.full_report["observable"] == "example.com"
        assert report.full_report["data_type"] == "domain"
        assert len(report.full_report["iocs"]) == 0
        assert report.full_report["ioc_count"] == 0
        assert len(report.full_report["taxonomy"]) == 1
        assert report.full_report["taxonomy"][0]["level"] == "safe"

    def test_execute_unsupported_data_type(self):
        """Test executing with unsupported data type."""
        input_data = WorkerInput(data_type="other", data="some_data", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        with pytest.raises(SystemExit):  # analyzer.error() calls sys.exit(1)
            analyzer.execute()

    def test_summary(self):
        """Test summary method."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        raw_data = {
            "iocs": [{"ip": "1.2.3.4", "confidence": 90}, {"ip": "5.6.7.8", "confidence": 85}]
        }

        summary = analyzer.summary(raw_data)

        assert summary["ioc_count"] == 2

    def test_metadata(self):
        """Test metadata attribute."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.config)

        analyzer = MCAPAnalyzer(input_data)

        assert analyzer.METADATA.name == "MCAP Analyzer"
        assert (
            analyzer.METADATA.description
            == "Analyzes observables using MCAP (Malware Configuration and Analysis Platform) by CIS Security"
        )
        assert analyzer.METADATA.pattern == "threat-intel"
        assert analyzer.METADATA.version_stage == "TESTING"
