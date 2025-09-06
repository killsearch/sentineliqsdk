"""Tests for sentineliqsdk.analyzers module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentineliqsdk.analyzers import Analyzer
from sentineliqsdk.models import (
    Artifact,
    ProxyConfig,
    TaxonomyEntry,
    WorkerConfig,
    WorkerInput,
)


class ConcreteAnalyzer(Analyzer):
    """Concrete implementation of Analyzer for testing."""

    def run(self) -> None:
        """Test implementation of run method."""


class TestAnalyzer:
    """Test Analyzer base class."""

    def test_init_with_auto_extract_enabled(self):
        """Test Analyzer initialization with auto_extract enabled."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = ConcreteAnalyzer(input_data)

        assert analyzer.auto_extract is True

    def test_init_with_auto_extract_disabled(self):
        """Test Analyzer initialization with auto_extract disabled."""
        config = WorkerConfig(auto_extract=False)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = ConcreteAnalyzer(input_data)

        assert analyzer.auto_extract is False

    def test_get_data_for_ip(self):
        """Test get_data method for IP data type."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        assert analyzer.get_data() == "1.2.3.4"

    def test_get_data_for_file_with_filename(self):
        """Test get_data method for file data type with filename."""
        input_data = WorkerInput(data_type="file", data="malware.exe", filename="malware.exe")
        analyzer = ConcreteAnalyzer(input_data)

        assert analyzer.get_data() == "malware.exe"

    def test_get_data_for_file_without_filename(self):
        """Test get_data method for file data type without filename."""
        input_data = WorkerInput(data_type="file", data="malware.exe")
        analyzer = ConcreteAnalyzer(input_data)

        with pytest.raises(SystemExit):
            analyzer.get_data()

    def test_build_taxonomy_valid_levels(self):
        """Test build_taxonomy method with valid levels."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        for level in ["info", "safe", "suspicious", "malicious"]:
            taxonomy = analyzer.build_taxonomy(level, "test", "predicate", "value")
            assert isinstance(taxonomy, TaxonomyEntry)
            assert taxonomy.level == level
            assert taxonomy.namespace == "test"
            assert taxonomy.predicate == "predicate"
            assert taxonomy.value == "value"

    def test_build_taxonomy_invalid_level(self):
        """Test build_taxonomy method with invalid level defaults to info."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        taxonomy = analyzer.build_taxonomy("invalid", "test", "predicate", "value")
        assert taxonomy.level == "info"

    def test_summary_default(self):
        """Test default summary method returns empty dict."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        assert analyzer.summary({"test": "data"}) == {}

    def test_artifacts_with_auto_extract_enabled(self):
        """Test artifacts method with auto_extract enabled."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = ConcreteAnalyzer(input_data)

        # Mock the Extractor to avoid actual extraction logic
        with patch("sentineliqsdk.analyzers.base.Extractor") as mock_extractor_class:
            mock_extractor = MagicMock()
            mock_extractor_class.return_value = mock_extractor
            mock_extractor.check_iterable.return_value = [
                MagicMock(data_type="ip", data="8.8.8.8"),
                MagicMock(data_type="url", data="https://example.com"),
            ]

            full_report = {"observable": "1.2.3.4", "related_ips": ["8.8.8.8"]}
            artifacts = analyzer.artifacts(full_report)

            assert len(artifacts) == 2
            assert all(isinstance(artifact, Artifact) for artifact in artifacts)
            assert artifacts[0].data_type == "ip"
            assert artifacts[0].data == "8.8.8.8"
            assert artifacts[1].data_type == "url"
            assert artifacts[1].data == "https://example.com"

    def test_artifacts_with_auto_extract_disabled(self):
        """Test artifacts method with auto_extract disabled."""
        config = WorkerConfig(auto_extract=False)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = ConcreteAnalyzer(input_data)

        full_report = {"observable": "1.2.3.4", "related_ips": ["8.8.8.8"]}
        artifacts = analyzer.artifacts(full_report)

        assert artifacts == []

    def test_build_artifact_for_file(self):
        """Test build_artifact method for file type."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        artifact = analyzer.build_artifact("file", "/path/to/file.exe", tlp=2, pap=2)

        assert isinstance(artifact, Artifact)
        assert artifact.data_type == "file"
        assert artifact.data == "/path/to/file.exe"
        assert artifact.filename == "/path/to/file.exe"
        assert artifact.extra == {"tlp": 2, "pap": 2}

    def test_build_artifact_for_non_file(self):
        """Test build_artifact method for non-file type."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        artifact = analyzer.build_artifact("ip", "1.2.3.4", confidence=0.9)

        assert isinstance(artifact, Artifact)
        assert artifact.data_type == "ip"
        assert artifact.data == "1.2.3.4"
        assert artifact.filename is None
        assert artifact.extra == {"confidence": 0.9}

    def test_build_artifact_with_non_string_data(self):
        """Test build_artifact method with non-string data."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        artifact = analyzer.build_artifact("ip", 12345)

        assert artifact.data == "12345"

    def test_build_envelope_success(self):
        """Test _build_envelope method with successful summary and operations."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        # Override methods to return specific values
        analyzer.summary = lambda x: {"verdict": "malicious"}
        analyzer.operations = lambda x: [MagicMock(operation_type="hunt", parameters={})]
        analyzer.artifacts = lambda x: [Artifact(data_type="ip", data="8.8.8.8")]

        full_report = {"observable": "1.2.3.4"}
        envelope = analyzer._build_envelope(full_report)

        assert envelope.success is True
        assert envelope.summary == {"verdict": "malicious"}
        assert len(envelope.artifacts) == 1
        assert len(envelope.operations) == 1
        assert envelope.full_report == full_report

    def test_build_envelope_with_exceptions(self):
        """Test _build_envelope method handles exceptions in summary and operations."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        # Override methods to raise exceptions
        analyzer.summary = lambda x: (_ for _ in ()).throw(Exception("Summary error"))
        analyzer.operations = lambda x: (_ for _ in ()).throw(Exception("Operations error"))
        analyzer.artifacts = lambda x: [Artifact(data_type="ip", data="8.8.8.8")]

        full_report = {"observable": "1.2.3.4"}
        envelope = analyzer._build_envelope(full_report)

        # Should handle exceptions gracefully
        assert envelope.success is True
        assert envelope.summary == {}
        assert envelope.operations == []
        assert len(envelope.artifacts) == 1
        assert envelope.full_report == full_report

    def test_report_returns_analyzer_report(self):
        """Test report method returns AnalyzerReport."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        full_report = {"observable": "1.2.3.4"}
        result = analyzer.report(full_report)

        assert hasattr(result, "success")
        assert hasattr(result, "summary")
        assert hasattr(result, "artifacts")
        assert hasattr(result, "operations")
        assert hasattr(result, "full_report")

    def test_run_abstract(self):
        """Test that run method is abstract and must be overridden."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = ConcreteAnalyzer(input_data)

        # Should not raise any exception since it's implemented in ConcreteAnalyzer
        analyzer.run()

    def test_artifacts_calls_extractor_with_ignore(self):
        """Test that artifacts method calls Extractor with correct ignore parameter."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = ConcreteAnalyzer(input_data)

        with patch("sentineliqsdk.analyzers.base.Extractor") as mock_extractor_class:
            mock_extractor = MagicMock()
            mock_extractor_class.return_value = mock_extractor
            mock_extractor.check_iterable.return_value = []

            full_report = {"observable": "1.2.3.4"}
            analyzer.artifacts(full_report)

            # Verify Extractor was called with the correct ignore parameter
            mock_extractor_class.assert_called_once_with(ignore="1.2.3.4")
            mock_extractor.check_iterable.assert_called_once_with(full_report)

    def test_artifacts_with_file_datatype(self):
        """Test artifacts method with file datatype uses filename as ignore."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(
            data_type="file", data="malware.exe", filename="malware.exe", config=config
        )
        analyzer = ConcreteAnalyzer(input_data)

        with patch("sentineliqsdk.analyzers.base.Extractor") as mock_extractor_class:
            mock_extractor = MagicMock()
            mock_extractor_class.return_value = mock_extractor
            mock_extractor.check_iterable.return_value = []

            full_report = {"observable": "malware.exe"}
            analyzer.artifacts(full_report)

            # Verify Extractor was called with filename as ignore parameter
            mock_extractor_class.assert_called_once_with(ignore="malware.exe")
