"""Tests for sentineliqsdk.models module."""

from __future__ import annotations

import pytest

from sentineliqsdk.models import (
    AnalyzerReport,
    Artifact,
    ExtractorResult,
    ExtractorResults,
    Operation,
    ProxyConfig,
    ResponderReport,
    TaxonomyEntry,
    WorkerConfig,
    WorkerError,
    WorkerInput,
)


class TestProxyConfig:
    """Test ProxyConfig dataclass."""

    def test_default_values(self):
        """Test default values for ProxyConfig."""
        config = ProxyConfig()
        assert config.http is None
        assert config.https is None

    def test_custom_values(self):
        """Test custom values for ProxyConfig."""
        config = ProxyConfig(http="http://proxy:8080", https="https://proxy:8080")
        assert config.http == "http://proxy:8080"
        assert config.https == "https://proxy:8080"

    def test_immutable(self):
        """Test that ProxyConfig is immutable."""
        config = ProxyConfig()
        with pytest.raises(AttributeError):
            config.http = "http://new:8080"


class TestWorkerConfig:
    """Test WorkerConfig dataclass."""

    def test_default_values(self):
        """Test default values for WorkerConfig."""
        config = WorkerConfig()
        assert config.check_tlp is False
        assert config.max_tlp == 2
        assert config.check_pap is False
        assert config.max_pap == 2
        assert config.auto_extract is True
        assert isinstance(config.proxy, ProxyConfig)

    def test_custom_values(self):
        """Test custom values for WorkerConfig."""
        proxy = ProxyConfig(http="http://proxy:8080")
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=3,
            check_pap=True,
            max_pap=3,
            auto_extract=False,
            proxy=proxy,
        )
        assert config.check_tlp is True
        assert config.max_tlp == 3
        assert config.check_pap is True
        assert config.max_pap == 3
        assert config.auto_extract is False
        assert config.proxy == proxy


class TestWorkerInput:
    """Test WorkerInput dataclass."""

    def test_default_values(self):
        """Test default values for WorkerInput."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        assert input_data.data_type == "ip"
        assert input_data.data == "1.2.3.4"
        assert input_data.filename is None
        assert input_data.tlp == 2
        assert input_data.pap == 2
        assert isinstance(input_data.config, WorkerConfig)

    def test_custom_values(self):
        """Test custom values for WorkerInput."""
        config = WorkerConfig(check_tlp=True, max_tlp=3)
        input_data = WorkerInput(
            data_type="file",
            data="malware.exe",
            filename="malware.exe",
            tlp=3,
            pap=3,
            config=config,
        )
        assert input_data.data_type == "file"
        assert input_data.data == "malware.exe"
        assert input_data.filename == "malware.exe"
        assert input_data.tlp == 3
        assert input_data.pap == 3
        assert input_data.config == config


class TestTaxonomyEntry:
    """Test TaxonomyEntry dataclass."""

    def test_valid_levels(self):
        """Test valid taxonomy levels."""
        for level in ["info", "safe", "suspicious", "malicious"]:
            entry = TaxonomyEntry(level=level, namespace="test", predicate="test", value="test")
            assert entry.level == level
            assert entry.namespace == "test"
            assert entry.predicate == "test"
            assert entry.value == "test"

    def test_immutable(self):
        """Test that TaxonomyEntry is immutable."""
        entry = TaxonomyEntry(level="info", namespace="test", predicate="test", value="test")
        with pytest.raises(AttributeError):
            entry.level = "malicious"


class TestArtifact:
    """Test Artifact dataclass."""

    def test_minimal_artifact(self):
        """Test minimal artifact creation."""
        artifact = Artifact(data_type="ip", data="1.2.3.4")
        assert artifact.data_type == "ip"
        assert artifact.data == "1.2.3.4"
        assert artifact.filename is None
        assert artifact.tlp is None
        assert artifact.pap is None
        assert artifact.extra == {}

    def test_full_artifact(self):
        """Test full artifact creation."""
        artifact = Artifact(
            data_type="file",
            data="malware.exe",
            filename="malware.exe",
            tlp=2,
            pap=2,
            extra={"confidence": 0.9, "source": "test"},
        )
        assert artifact.data_type == "file"
        assert artifact.data == "malware.exe"
        assert artifact.filename == "malware.exe"
        assert artifact.tlp == 2
        assert artifact.pap == 2
        assert artifact.extra == {"confidence": 0.9, "source": "test"}

    def test_immutable(self):
        """Test that Artifact is immutable."""
        artifact = Artifact(data_type="ip", data="1.2.3.4")
        with pytest.raises(AttributeError):
            artifact.data_type = "url"


class TestOperation:
    """Test Operation dataclass."""

    def test_minimal_operation(self):
        """Test minimal operation creation."""
        operation = Operation(operation_type="hunt")
        assert operation.operation_type == "hunt"
        assert operation.parameters == {}

    def test_operation_with_parameters(self):
        """Test operation with parameters."""
        operation = Operation(
            operation_type="block", parameters={"target": "1.2.3.4", "duration": "24h"}
        )
        assert operation.operation_type == "block"
        assert operation.parameters == {"target": "1.2.3.4", "duration": "24h"}

    def test_immutable(self):
        """Test that Operation is immutable."""
        operation = Operation(operation_type="hunt")
        with pytest.raises(AttributeError):
            operation.operation_type = "block"


class TestWorkerError:
    """Test WorkerError dataclass."""

    def test_default_values(self):
        """Test default values for WorkerError."""
        error = WorkerError()
        assert error.success is False
        assert error.error_message == ""
        assert error.input_data is None

    def test_custom_values(self):
        """Test custom values for WorkerError."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        error = WorkerError(success=False, error_message="Test error", input_data=input_data)
        assert error.success is False
        assert error.error_message == "Test error"
        assert error.input_data == input_data


class TestAnalyzerReport:
    """Test AnalyzerReport dataclass."""

    def test_default_values(self):
        """Test default values for AnalyzerReport."""
        report = AnalyzerReport()
        assert report.success is True
        assert report.summary == {}
        assert report.artifacts == []
        assert report.operations == []
        assert report.full_report == {}

    def test_custom_values(self):
        """Test custom values for AnalyzerReport."""
        artifact = Artifact(data_type="ip", data="1.2.3.4")
        operation = Operation(operation_type="hunt")
        report = AnalyzerReport(
            success=True,
            summary={"verdict": "malicious"},
            artifacts=[artifact],
            operations=[operation],
            full_report={"observable": "1.2.3.4"},
        )
        assert report.success is True
        assert report.summary == {"verdict": "malicious"}
        assert report.artifacts == [artifact]
        assert report.operations == [operation]
        assert report.full_report == {"observable": "1.2.3.4"}


class TestResponderReport:
    """Test ResponderReport dataclass."""

    def test_default_values(self):
        """Test default values for ResponderReport."""
        report = ResponderReport()
        assert report.success is True
        assert report.full_report == {}
        assert report.operations == []

    def test_custom_values(self):
        """Test custom values for ResponderReport."""
        operation = Operation(operation_type="block")
        report = ResponderReport(
            success=True,
            full_report={"action": "blocked"},
            operations=[operation],
        )
        assert report.success is True
        assert report.full_report == {"action": "blocked"}
        assert report.operations == [operation]


class TestExtractorResult:
    """Test ExtractorResult dataclass."""

    def test_creation(self):
        """Test ExtractorResult creation."""
        result = ExtractorResult(data_type="ip", data="1.2.3.4")
        assert result.data_type == "ip"
        assert result.data == "1.2.3.4"

    def test_immutable(self):
        """Test that ExtractorResult is immutable."""
        result = ExtractorResult(data_type="ip", data="1.2.3.4")
        with pytest.raises(AttributeError):
            result.data_type = "url"


class TestExtractorResults:
    """Test ExtractorResults dataclass."""

    def test_default_values(self):
        """Test default values for ExtractorResults."""
        results = ExtractorResults()
        assert results.results == []

    def test_add_result(self):
        """Test adding results."""
        results = ExtractorResults()
        results.add_result("ip", "1.2.3.4")
        results.add_result("url", "https://example.com")

        assert len(results.results) == 2
        assert results.results[0].data_type == "ip"
        assert results.results[0].data == "1.2.3.4"
        assert results.results[1].data_type == "url"
        assert results.results[1].data == "https://example.com"

    def test_deduplicate(self):
        """Test deduplication of results."""
        results = ExtractorResults()
        results.add_result("ip", "1.2.3.4")
        results.add_result("ip", "1.2.3.4")  # Duplicate
        results.add_result("url", "https://example.com")
        results.add_result("ip", "1.2.3.4")  # Another duplicate

        deduped = results.deduplicate()
        assert len(deduped.results) == 2
        assert deduped.results[0].data_type == "ip"
        assert deduped.results[0].data == "1.2.3.4"
        assert deduped.results[1].data_type == "url"
        assert deduped.results[1].data == "https://example.com"

    def test_deduplicate_empty(self):
        """Test deduplication of empty results."""
        results = ExtractorResults()
        deduped = results.deduplicate()
        assert len(deduped.results) == 0

    def test_deduplicate_no_duplicates(self):
        """Test deduplication when no duplicates exist."""
        results = ExtractorResults()
        results.add_result("ip", "1.2.3.4")
        results.add_result("url", "https://example.com")

        deduped = results.deduplicate()
        assert len(deduped.results) == 2
