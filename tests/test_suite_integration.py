"""Integration tests for Analyzer + Extractor behavior with pytest."""

from __future__ import annotations

from sentineliqsdk import Analyzer


def test_output() -> None:
    input_data = {"data": "8.8.8.8", "dataType": "ip"}
    analyzer = Analyzer(input_data)
    result = analyzer.report({"result": "1.2.3.4"})

    assert analyzer.get_data() not in str(result)
    assert result["artifacts"][0]["data"] == "1.2.3.4"
    assert result["artifacts"][0]["dataType"] == "ip"


def test_output_no_result() -> None:
    input_data = {"data": "8.8.8.8", "dataType": "ip"}
    analyzer = Analyzer(input_data)
    result = analyzer.report({"message": "8.8.8.8 was not found in database."})

    assert result["artifacts"] == []
