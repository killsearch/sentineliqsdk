from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.axur import AxurAnalyzer
from sentineliqsdk.models import DataType, WorkerInput


class DummyAxurClient:
    def __init__(self, *a, **k):
        pass

    def customers(self) -> dict[str, Any]:
        return {"customers": [{"key": "ACME"}]}

    def call(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        return {"dry_run": kwargs.get("dry_run", False), "url": f"/api/{path}"}


def build_analyzer(data: str = "payload", data_type: DataType = "other") -> AxurAnalyzer:
    os.environ["AXUR_API_TOKEN"] = "tok"
    return AxurAnalyzer(WorkerInput(data_type=data_type, data=data))


def test_execute_with_env_method(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    monkeypatch.setenv("AXUR_METHOD", "customers")
    monkeypatch.delenv("AXUR_PARAMS", raising=False)

    with patch("sentineliqsdk.analyzers.axur.AxurClient", DummyAxurClient):
        analyzer = build_analyzer(data_type="ip", data="1.2.3.4")
        rep = analyzer.execute()
        assert rep.success is True
        assert rep.full_report["details"]["method"] == "customers"
        assert rep.full_report["taxonomy"][0]["namespace"] == "axur"


def test_execute_with_payload_call_dry_run(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {
        "method": "call",
        "params": {"http_method": "GET", "path": "tickets-api/tickets", "dry_run": True},
    }
    with patch("sentineliqsdk.analyzers.axur.AxurClient", DummyAxurClient):
        analyzer = build_analyzer(json.dumps(payload), data_type="other")
        rep = analyzer.execute()
        details = rep.full_report["details"]
        assert details["result"]["dry_run"] is True
        assert "tickets-api/tickets" in details["result"]["url"]


def test_execute_invalid_params_json(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    monkeypatch.setenv("AXUR_METHOD", "customers")
    monkeypatch.setenv("AXUR_PARAMS", "not-json")
    analyzer = build_analyzer(data_type="ip", data="1.2.3.4")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_execute_payload_missing_method(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {"no_method": True}
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_execute_payload_params_not_mapping(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {"method": "customers", "params": [1, 2, 3]}  # invalid params type
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_execute_call_missing_path(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {"method": "call", "params": {"http_method": "GET"}}  # missing path
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_execute_unsupported_method(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {"method": "not_allowed", "params": {}}
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_run_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("AXUR_API_TOKEN", "tok")
    payload = {"method": "call", "params": {"path": "x"}}
    with patch("sentineliqsdk.analyzers.axur.AxurClient", DummyAxurClient):
        analyzer = build_analyzer(json.dumps(payload), data_type="other")
        analyzer.run()
