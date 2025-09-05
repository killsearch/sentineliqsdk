"""Tests for SentinelIQ SDK dataclasses."""

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


def test_worker_input_creates_with_required_fields():
    """Test WorkerInput dataclass creation with required fields."""
    # Basic creation
    input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)

    assert input_data.data_type == "ip"
    assert input_data.data == "1.2.3.4"
    assert input_data.tlp == 2
    assert input_data.pap == 2
    assert input_data.filename is None
    assert isinstance(input_data.config, WorkerConfig)


def test_taxonomy_entry_creates_with_all_fields():
    """Test TaxonomyEntry dataclass creation with all fields."""
    taxonomy = TaxonomyEntry(
        level="malicious", namespace="reputation", predicate="static", value="1.2.3.4"
    )

    assert taxonomy.level == "malicious"
    assert taxonomy.namespace == "reputation"
    assert taxonomy.predicate == "static"
    assert taxonomy.value == "1.2.3.4"


def test_artifact_creates_with_extra_fields():
    """Test Artifact dataclass creation with extra fields."""
    artifact = Artifact(
        data_type="ip", data="8.8.8.8", tlp=2, pap=2, extra={"confidence": 0.9, "source": "dns"}
    )

    assert artifact.data_type == "ip"
    assert artifact.data == "8.8.8.8"
    assert artifact.tlp == 2
    assert artifact.pap == 2
    assert artifact.extra["confidence"] == 0.9
    assert artifact.extra["source"] == "dns"


def test_operation_creates_with_parameters():
    """Test Operation dataclass creation with parameters."""
    operation = Operation(
        operation_type="hunt", parameters={"target": "1.2.3.4", "priority": "high"}
    )

    assert operation.operation_type == "hunt"
    assert operation.parameters["target"] == "1.2.3.4"
    assert operation.parameters["priority"] == "high"


def test_analyzer_report_creates_complete_report():
    """Test AnalyzerReport dataclass creation with complete data."""
    taxonomy = TaxonomyEntry("malicious", "reputation", "static", "1.2.3.4")
    artifact = Artifact("ip", "8.8.8.8")
    operation = Operation("hunt", {"target": "1.2.3.4"})

    report = AnalyzerReport(
        success=True,
        summary={"verdict": "malicious"},
        artifacts=[artifact],
        operations=[operation],
        full_report={"observable": "1.2.3.4", "taxonomy": [taxonomy]},
    )

    assert report.success is True
    assert report.summary["verdict"] == "malicious"
    assert len(report.artifacts) == 1
    assert len(report.operations) == 1
    assert report.full_report["observable"] == "1.2.3.4"


def test_responder_report_creates_with_operations():
    """Test ResponderReport dataclass creation with operations."""
    operation = Operation("block", {"target": "1.2.3.4"})

    report = ResponderReport(
        success=True, full_report={"action": "block", "target": "1.2.3.4"}, operations=[operation]
    )

    assert report.success is True
    assert report.full_report["action"] == "block"
    assert len(report.operations) == 1


def test_extractor_result_creates_simple_result():
    """Test ExtractorResult dataclass creation."""
    result = ExtractorResult(data_type="ip", data="1.2.3.4")

    assert result.data_type == "ip"
    assert result.data == "1.2.3.4"


def test_extractor_results_handles_deduplication():
    """Test ExtractorResults dataclass handles deduplication correctly."""
    results = ExtractorResults()

    # Add some results
    results.add_result("ip", "1.2.3.4")
    results.add_result("domain", "example.com")
    results.add_result("ip", "1.2.3.4")  # Duplicate

    assert len(results.results) == 3

    # Test deduplication
    deduped = results.deduplicate()
    assert len(deduped.results) == 2

    # Check that deduplication worked correctly
    data_types = [r.data_type for r in deduped.results]
    data_values = [r.data for r in deduped.results]
    assert "ip" in data_types
    assert "domain" in data_types
    assert "1.2.3.4" in data_values
    assert "example.com" in data_values


def test_worker_error_creates_with_input_data():
    """Test WorkerError dataclass creation with input data."""
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")

    error = WorkerError(success=False, error_message="Test error", input_data=input_data)

    assert error.success is False
    assert error.error_message == "Test error"
    assert error.input_data is not None
    assert error.input_data.data_type == "ip"
    assert error.input_data.data == "1.2.3.4"


def test_dataclasses_are_immutable():
    """Test that all dataclasses are immutable (frozen=True)."""
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")

    # Should not be able to modify frozen dataclass
    with pytest.raises(AttributeError):
        input_data.data_type = "url"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        input_data.data = "8.8.8.8"  # type: ignore[misc]


def test_proxy_config_creates_with_http_https():
    """Test ProxyConfig dataclass creation with HTTP/HTTPS settings."""
    proxy = ProxyConfig(http="http://proxy:8080", https="https://proxy:8080")

    assert proxy.http == "http://proxy:8080"
    assert proxy.https == "https://proxy:8080"

    # Test with None values
    proxy_none = ProxyConfig()
    assert proxy_none.http is None
    assert proxy_none.https is None


def test_worker_config_creates_with_all_settings():
    """Test WorkerConfig dataclass creation with all configuration settings."""
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=3,
        check_pap=True,
        max_pap=3,
        auto_extract=False,
        proxy=ProxyConfig(http="http://proxy:8080"),
    )

    assert config.check_tlp is True
    assert config.max_tlp == 3
    assert config.check_pap is True
    assert config.max_pap == 3
    assert config.auto_extract is False
    assert config.proxy.http == "http://proxy:8080"
    assert config.proxy.https is None
