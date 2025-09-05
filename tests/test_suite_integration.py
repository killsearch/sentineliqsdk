"""Integration tests for Analyzer + Extractor behavior using dataclasses."""

from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput


def test_analyzer_auto_extracts_iocs_from_report() -> None:
    """Test analyzer automatically extracts IOCs from report using Extractor."""
    input_data = WorkerInput(data_type="ip", data="8.8.8.8")
    analyzer = Analyzer(input_data)
    result = analyzer.report({"result": "1.2.3.4"})

    # Original observable should not be in the result string
    assert analyzer.get_data() not in str(result)
    # Should extract the IP from the report
    assert result.artifacts[0].data == "1.2.3.4"
    assert result.artifacts[0].data_type == "ip"


def test_analyzer_returns_empty_artifacts_when_no_iocs() -> None:
    """Test analyzer returns empty artifacts when no IOCs are found in report."""
    input_data = WorkerInput(data_type="ip", data="8.8.8.8")
    analyzer = Analyzer(input_data)
    result = analyzer.report({"message": "8.8.8.8 was not found in database."})

    assert result.artifacts == []
