"""Integration tests for Analyzer + Extractor behavior with pytest."""

from __future__ import annotations

import json
import sys
from io import StringIO

import pytest

from sentineliqsdk import Analyzer


def test_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", StringIO(json.dumps({"data": "8.8.8.8", "dataType": "ip"})))
    analyzer = Analyzer()
    analyzer.report({"result": "1.2.3.4"})

    output = capsys.readouterr().out.strip()
    json_output = json.loads(output)
    assert analyzer.get_data() not in output
    assert json_output["artifacts"][0]["data"] == "1.2.3.4"
    assert json_output["artifacts"][0]["dataType"] == "ip"


def test_output_no_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", StringIO(json.dumps({"data": "8.8.8.8", "dataType": "ip"})))
    analyzer = Analyzer()
    analyzer.report({"message": "8.8.8.8 was not found in database."})

    output = capsys.readouterr().out.strip()
    json_output = json.loads(output)
    assert json_output["artifacts"] == []
