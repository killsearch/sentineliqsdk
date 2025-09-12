"""Tests for EmlParserAnalyzer."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.eml_parser import EmlParserAnalyzer
from sentineliqsdk.models import AnalyzerReport


class TestEmlParserAnalyzer:
    """Test cases for EmlParserAnalyzer."""

    @pytest.fixture
    def sample_eml_content(self) -> str:
        """Sample EML content for testing."""
        return """Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [192.168.1.100])
    by mx.recipient.com (Postfix) with ESMTP id 12345
    for <recipient@recipient.com>; Mon, 1 Jan 2024 12:00:00 +0000 (UTC)
Received-SPF: pass (recipient.com: domain of sender@example.com designates 192.168.1.100 as permitted sender)
Authentication-Results: mx.recipient.com;
    spf=pass smtp.mailfrom=sender@example.com;
    dkim=pass header.i=@example.com;
    dmarc=pass (p=quarantine sp=none dis=none) header.from=example.com
Message-ID: <20240101120000.12345@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
From: Sender Name <sender@example.com>
To: Recipient Name <recipient@recipient.com>
Subject: Test Email for Analysis
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

This is a test email for EML parsing analysis.

Please visit our website: https://example.com
For urgent matters, click here: https://urgent.example.com/verify

Best regards,
Test Team
"""

    @pytest.fixture
    def suspicious_eml_content(self) -> str:
        """Suspicious EML content for testing."""
        return """Return-Path: <phisher@malicious.com>
Received: from suspicious.com (suspicious.com [1.2.3.4])
    by mx.victim.com (Postfix) with ESMTP id 67890
    for <victim@victim.com>; Mon, 1 Jan 2024 12:00:00 +0000 (UTC)
Received-SPF: fail (victim.com: domain of phisher@malicious.com does not designate 1.2.3.4 as permitted sender)
Authentication-Results: mx.victim.com;
    spf=fail smtp.mailfrom=phisher@malicious.com;
    dkim=fail header.i=@malicious.com;
    dmarc=fail (p=reject sp=none dis=none) header.from=malicious.com
Message-ID: <20240101120000.67890@malicious.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
From: Bank Security <security@yourbank.com>
To: Account Holder <victim@victim.com>
Subject: URGENT: Verify Your Account Immediately
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary456"

--boundary456
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your account has been suspended! Click here immediately:</p>
<a href="https://phishing.com/verify">Verify Account</a>
<a href="https://malicious.com/login">Login Here</a>
<a href="https://fake-bank.com/urgent">Urgent Action Required</a>
<a href="https://scam.com/verify">Verify Now</a>
<a href="https://evil.com/click">Click Here</a>
<a href="https://bad.com/action">Take Action</a>
</body></html>

--boundary456
Content-Type: application/octet-stream; name="update.exe"
Content-Disposition: attachment; filename="security_update.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

--boundary456--
"""

    @pytest.fixture
    def temp_eml_file(self, sample_eml_content: str) -> str:
        """Create a temporary EML file for testing."""
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, "test_sample.eml")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(sample_eml_content)
        yield temp_path
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def _create_test_eml_file(self, filename: str, content: str) -> str:
        """Create a temporary EML file for testing."""
        import os

        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, filename)
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
        return temp_path

    @pytest.fixture
    def suspicious_temp_eml_file(self, suspicious_eml_content: str) -> str:
        """Create a temporary suspicious EML file for testing."""
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, "test_suspicious.eml")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(suspicious_eml_content)
        yield temp_path
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def worker_input(self, temp_eml_file: str) -> WorkerInput:
        """Create WorkerInput for testing."""
        return WorkerInput(
            data_type="file",
            data=temp_eml_file,
            filename=os.path.basename(temp_eml_file),
            tlp=2,
            pap=2,
            config=WorkerConfig(),
        )

    @pytest.fixture
    def suspicious_worker_input(self, suspicious_temp_eml_file: str) -> WorkerInput:
        """Create WorkerInput for suspicious email testing."""
        return WorkerInput(
            data_type="file",
            data=suspicious_temp_eml_file,
            filename=os.path.basename(suspicious_temp_eml_file),
            tlp=2,
            pap=2,
            config=WorkerConfig(),
        )

    def test_metadata(self) -> None:
        """Test analyzer metadata."""
        metadata = EmlParserAnalyzer.METADATA
        assert metadata.name == "EML Parser Analyzer"
        assert "parse and analyze EML email files" in metadata.description.lower()
        assert metadata.pattern == "threat-intel"
        assert metadata.version_stage == "TESTING"
        assert "SentinelIQ Team" in metadata.author[0]

    def test_unsupported_data_type(self) -> None:
        """Test error handling for unsupported data types."""
        worker_input = WorkerInput(
            data_type="ip",
            data="1.2.3.4",
            config=WorkerConfig(),
        )

        analyzer = EmlParserAnalyzer(worker_input)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "only supports file data type" in str(exc_info.value)

    def test_missing_file(self) -> None:
        """Test error handling for missing files."""
        worker_input = WorkerInput(
            data_type="file",
            data="/nonexistent/file.eml",
            config=WorkerConfig(),
        )

        analyzer = EmlParserAnalyzer(worker_input)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "EML file not found" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_missing_eml_parser_dependency(self, mock_eml_parser: Mock) -> None:
        """Test error handling when eml_parser library is not available."""
        mock_eml_parser = None

        with patch("sentineliqsdk.analyzers.eml_parser.eml_parser", None):
            worker_input = WorkerInput(
                data_type="file",
                data="test.eml",
                config=WorkerConfig(),
            )

            analyzer = EmlParserAnalyzer(worker_input)

            with pytest.raises(Exception) as exc_info:
                analyzer.execute()

            assert "eml_parser library is not installed" in str(exc_info.value)

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_successful_analysis_safe_email(
        self, mock_eml_parser: Mock, worker_input: WorkerInput
    ) -> None:
        """Test successful analysis of a safe email."""
        # Mock eml_parser response
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        mock_parsed_email = {
            "header": {
                "from": "sender@example.com",
                "to": "recipient@recipient.com",
                "subject": "Test Email for Analysis",
                "date": "Mon, 1 Jan 2024 12:00:00 +0000",
                "authentication-results": [
                    "spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.i=@example.com; dmarc=pass"
                ],
            },
            "body": [{"content": "This is a test email. Visit https://example.com"}],
        }

        mock_ep_instance.decode_email_bytes.return_value = mock_parsed_email

        analyzer = EmlParserAnalyzer(worker_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.verdict in ["safe", "info"]
        assert report.data_type == "file"
        assert len(report.taxonomy) > 0

        # Check that authentication taxonomy is present
        auth_taxonomies = [t for t in report.taxonomy if "auth_" in t.get("predicate", "")]
        assert len(auth_taxonomies) > 0

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_successful_analysis_suspicious_email(
        self, mock_eml_parser: Mock, suspicious_worker_input: WorkerInput
    ) -> None:
        """Test successful analysis of a suspicious email."""
        # Mock eml_parser response for suspicious email
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        mock_parsed_email = {
            "header": {
                "from": "phisher@malicious.com",
                "to": "victim@victim.com",
                "subject": "URGENT: Verify Your Account Immediately",
                "date": "Mon, 1 Jan 2024 12:00:00 +0000",
                "authentication-results": [
                    "spf=fail smtp.mailfrom=phisher@malicious.com; dkim=fail header.i=@malicious.com; dmarc=fail"
                ],
            },
            "body": [
                {
                    "content": "Click here: https://phishing.com/verify https://malicious.com/login https://fake-bank.com/urgent https://scam.com/verify https://evil.com/click https://bad.com/action"
                }
            ],
            "attachment": [
                {
                    "filename": "security_update.exe",
                    "content_type": "application/octet-stream",
                    "raw": b"fake_executable_content",
                    "hash": {"md5": "fake_hash"},
                }
            ],
        }

        mock_ep_instance.decode_email_bytes.return_value = mock_parsed_email

        analyzer = EmlParserAnalyzer(suspicious_worker_input)
        report = analyzer.execute()

        assert isinstance(report, AnalyzerReport)
        assert report.verdict in ["suspicious", "malicious"]
        assert report.data_type == "file"
        assert len(report.taxonomy) > 0

        # Check for suspicious indicators in taxonomies
        suspicious_taxonomies = [
            t for t in report.taxonomy if t.get("level") in ["suspicious", "malicious"]
        ]
        assert len(suspicious_taxonomies) > 0

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_url_extraction(self, mock_eml_parser: Mock, worker_input: WorkerInput) -> None:
        """Test URL extraction functionality."""
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        mock_parsed_email = {
            "header": {"from": "sender@example.com", "subject": "Test Email"},
            "body": [{"content": "Visit https://example.com and http://test.com for more info"}],
        }

        mock_ep_instance.decode_email_bytes.return_value = mock_parsed_email

        analyzer = EmlParserAnalyzer(worker_input)
        report = analyzer.execute()

        # Check if URLs were extracted in details
        assert hasattr(report, "details")
        assert "extracted_urls" in report.details
        urls = report.details["extracted_urls"]
        assert len(urls) >= 2
        assert any("example.com" in url for url in urls)
        assert any("test.com" in url for url in urls)

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_attachment_analysis(self, mock_eml_parser: Mock, worker_input: WorkerInput) -> None:
        """Test attachment analysis functionality."""
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        mock_parsed_email = {
            "header": {"from": "sender@example.com", "subject": "Test Email with Attachment"},
            "attachment": [
                {
                    "filename": "document.pdf",
                    "content_type": "application/pdf",
                    "raw": b"fake_pdf_content",
                    "hash": {"md5": "fake_pdf_hash"},
                },
                {
                    "filename": "malware.exe",
                    "content_type": "application/octet-stream",
                    "raw": b"fake_exe_content",
                    "hash": {"md5": "fake_exe_hash"},
                },
            ],
        }

        mock_ep_instance.decode_email_bytes.return_value = mock_parsed_email

        analyzer = EmlParserAnalyzer(worker_input)
        report = analyzer.execute()

        # Check if attachments were analyzed
        assert hasattr(report, "details")
        assert "attachments_info" in report.details
        attachments = report.details["attachments_info"]
        assert len(attachments) == 2

        # Check for executable attachment detection (should make it suspicious)
        assert report.verdict in ["suspicious", "malicious"]

        # Check attachment taxonomy
        att_taxonomies = [t for t in report.taxonomy if "attachments" in t.get("predicate", "")]
        assert len(att_taxonomies) > 0

    def test_run_method(self, worker_input: WorkerInput) -> None:
        """Test that run() method calls execute()."""
        analyzer = EmlParserAnalyzer(worker_input)

        with patch.object(analyzer, "execute") as mock_execute:
            mock_execute.return_value = Mock(spec=AnalyzerReport)
            result = analyzer.run()
            mock_execute.assert_called_once()
            assert result == mock_execute.return_value

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_authentication_analysis(
        self, mock_eml_parser: Mock, worker_input: WorkerInput
    ) -> None:
        """Test email authentication analysis."""
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        mock_parsed_email = {
            "header": {
                "from": "sender@example.com",
                "subject": "Test Email",
                "authentication-results": [
                    "spf=pass smtp.mailfrom=sender@example.com",
                    "dkim=pass header.i=@example.com",
                    "dmarc=pass (p=quarantine sp=none dis=none) header.from=example.com",
                ],
                "received-spf": "pass (example.com: domain of sender@example.com designates 192.168.1.1 as permitted sender)",
            }
        }

        mock_ep_instance.decode_email_bytes.return_value = mock_parsed_email

        analyzer = EmlParserAnalyzer(worker_input)
        report = analyzer.execute()

        # Check authentication info in details
        assert hasattr(report, "details")
        assert "authentication_info" in report.details
        auth_info = report.details["authentication_info"]

        # Should have detected passing authentication
        assert auth_info.get("spf") == "pass"
        assert auth_info.get("dkim") == "pass"
        assert auth_info.get("dmarc") == "pass"

        # Check for authentication taxonomies
        auth_taxonomies = [t for t in report.taxonomy if t.get("predicate", "").startswith("auth_")]
        assert len(auth_taxonomies) >= 3  # SPF, DKIM, DMARC

    @patch("sentineliqsdk.analyzers.eml_parser.eml_parser")
    def test_error_handling_parse_failure(
        self, mock_eml_parser: Mock, worker_input: WorkerInput
    ) -> None:
        """Test error handling when EML parsing fails."""
        mock_ep_instance = Mock()
        mock_eml_parser.EmlParser.return_value = mock_ep_instance

        # Make parsing fail
        mock_ep_instance.decode_email_bytes.side_effect = Exception("Parse error")

        analyzer = EmlParserAnalyzer(worker_input)

        with pytest.raises(Exception) as exc_info:
            analyzer.execute()

        assert "Failed to parse EML file" in str(exc_info.value)
