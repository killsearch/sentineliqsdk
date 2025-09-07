"""
Tests for ClamAV Analyzer
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.clamav import ClamavAnalyzer


class TestClamavAnalyzer:
    """Test cases for ClamavAnalyzer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.test_config = WorkerConfig(
            check_tlp=False,
            check_pap=False,
            auto_extract=False,
            params={"clamav.socket_path": "/tmp/test_clamd.ctl", "clamav.timeout": 5},
        )

    def test_metadata(self):
        """Test analyzer metadata."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket"):
            analyzer = ClamavAnalyzer(input_data)

            assert analyzer.METADATA.name == "ClamAV Analyzer"
            assert (
                analyzer.METADATA.description
                == "Scans files for malware using ClamAV antivirus engine"
            )
            assert "SentinelIQ Team" in analyzer.METADATA.author[0]
            assert analyzer.METADATA.pattern == "antivirus"
            assert analyzer.METADATA.version_stage == "TESTING"

    def test_init_with_default_config(self):
        """Test analyzer initialization with default configuration."""
        input_data = WorkerInput(
            data_type="file", data="test", config=WorkerConfig(check_tlp=False, check_pap=False)
        )

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True

            analyzer = ClamavAnalyzer(input_data)

            assert analyzer.socket_path == "/var/run/clamav/clamd.ctl"
            assert analyzer.timeout == 30
            mock_clamd.assert_called_once_with(path="/var/run/clamav/clamd.ctl")

    def test_init_with_custom_config(self):
        """Test analyzer initialization with custom configuration."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True

            analyzer = ClamavAnalyzer(input_data)

            assert analyzer.socket_path == "/tmp/test_clamd.ctl"
            assert analyzer.timeout == 5
            mock_clamd.assert_called_once_with(path="/tmp/test_clamd.ctl")

    def test_init_connection_failure(self):
        """Test analyzer initialization with connection failure."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.side_effect = Exception("Connection failed")

            with pytest.raises(SystemExit):
                ClamavAnalyzer(input_data)

    def test_check_file_clean(self):
        """Test checking a clean file."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_file.return_value = None

            analyzer = ClamavAnalyzer(input_data)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"clean content")
                temp_file = f.name

            try:
                result = analyzer.check_file(temp_file)
                assert result is None
            finally:
                os.unlink(temp_file)

    def test_check_file_malicious(self):
        """Test checking a malicious file."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True

            analyzer = ClamavAnalyzer(input_data)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"malicious content")
                temp_file = f.name

            # Mock the scan_file to return result for the actual temp file path
            mock_clamd.return_value.scan_file.return_value = {
                temp_file: ("FOUND", "EICAR-Test-File")
            }

            try:
                result = analyzer.check_file(temp_file)
                assert result == "EICAR-Test-File"
            finally:
                os.unlink(temp_file)

    def test_check_file_not_found(self):
        """Test checking a non-existent file."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True

            analyzer = ClamavAnalyzer(input_data)

            with pytest.raises(SystemExit):
                analyzer.check_file("/non/existent/file")

    def test_check_data_clean(self):
        """Test checking clean data."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = None

            analyzer = ClamavAnalyzer(input_data)

            result = analyzer.check_data(b"clean content")
            assert result is None

    def test_check_data_malicious(self):
        """Test checking malicious data."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = {
                "stream": ("FOUND", "EICAR-Test-File")
            }

            analyzer = ClamavAnalyzer(input_data)

            result = analyzer.check_data(b"malicious content")
            assert result == "EICAR-Test-File"

    def test_execute_file_path_clean(self):
        """Test execute with clean file path."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"clean content")
            temp_file = f.name

        try:
            input_data = WorkerInput(
                data_type="file", data="test", filename=temp_file, config=self.test_config
            )

            with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
                mock_clamd.return_value.ping.return_value = True
                mock_clamd.return_value.scan_file.return_value = None

                analyzer = ClamavAnalyzer(input_data)
                report = analyzer.execute()

                assert report.success is True
                assert report.full_report["verdict"] == "safe"
                assert report.full_report["malware_name"] is None
                assert len(report.full_report["taxonomy"]) == 1
                assert report.full_report["taxonomy"][0]["level"] == "safe"
                assert report.full_report["taxonomy"][0]["namespace"] == "ClamAV"
        finally:
            os.unlink(temp_file)

    def test_execute_file_path_malicious(self):
        """Test execute with malicious file path."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"malicious content")
            temp_file = f.name

        try:
            input_data = WorkerInput(
                data_type="file", data="test", filename=temp_file, config=self.test_config
            )

            with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
                mock_clamd.return_value.ping.return_value = True
                mock_clamd.return_value.scan_file.return_value = {
                    temp_file: ("FOUND", "EICAR-Test-File")
                }

                analyzer = ClamavAnalyzer(input_data)
                report = analyzer.execute()

                assert report.success is True
                assert report.full_report["verdict"] == "malicious"
                assert report.full_report["malware_name"] == "EICAR-Test-File"
                assert len(report.full_report["taxonomy"]) == 1
                assert report.full_report["taxonomy"][0]["level"] == "malicious"
                assert report.full_report["taxonomy"][0]["value"] == "EICAR-Test-File"
        finally:
            os.unlink(temp_file)

    def test_execute_file_data_clean(self):
        """Test execute with clean file data."""
        input_data = WorkerInput(
            data_type="file",
            data="clean content",
            filename=None,  # No filename - should use data
            config=self.test_config,
        )

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = None

            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.execute()

            assert report.success is True
            assert report.full_report["verdict"] == "safe"
            assert report.full_report["malware_name"] is None
            assert len(report.full_report["taxonomy"]) == 1
            assert report.full_report["taxonomy"][0]["level"] == "safe"

    def test_execute_file_data_malicious(self):
        """Test execute with malicious file data."""
        input_data = WorkerInput(
            data_type="file",
            data="malicious content",
            filename=None,  # No filename - should use data
            config=self.test_config,
        )

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = {
                "stream": ("FOUND", "EICAR-Test-File")
            }

            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.execute()

            assert report.success is True
            assert report.full_report["verdict"] == "malicious"
            assert report.full_report["malware_name"] == "EICAR-Test-File"
            assert len(report.full_report["taxonomy"]) == 1
            assert report.full_report["taxonomy"][0]["level"] == "malicious"
            assert report.full_report["taxonomy"][0]["value"] == "EICAR-Test-File"

    def test_execute_wrong_data_type(self):
        """Test execute with wrong data type."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True

            analyzer = ClamavAnalyzer(input_data)

            with pytest.raises(SystemExit):
                analyzer.execute()

    def test_run_method(self):
        """Test run method returns execute result."""
        input_data = WorkerInput(
            data_type="file",
            data="test",
            filename=None,  # No filename - should use data
            config=self.test_config,
        )

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = None

            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.run()

            assert report.success is True
            assert report.full_report["verdict"] == "safe"

    def test_metadata_in_report(self):
        """Test that metadata is included in the report."""
        input_data = WorkerInput(
            data_type="file",
            data="test",
            filename=None,  # No filename - should use data
            config=self.test_config,
        )

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.return_value = None

            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.execute()

            assert "metadata" in report.full_report
            metadata = report.full_report["metadata"]
            assert metadata["Name"] == "ClamAV Analyzer"
            assert metadata["pattern"] == "antivirus"
            assert metadata["VERSION"] == "TESTING"

    def test_scan_error_handling(self):
        """Test error handling during scan operations."""
        input_data = WorkerInput(data_type="file", data="test", config=self.test_config)

        with patch("sentineliqsdk.analyzers.clamav.pyclamd.ClamdUnixSocket") as mock_clamd:
            mock_clamd.return_value.ping.return_value = True
            mock_clamd.return_value.scan_stream.side_effect = Exception("Scan error")

            analyzer = ClamavAnalyzer(input_data)

            with pytest.raises(SystemExit):
                analyzer.execute()
