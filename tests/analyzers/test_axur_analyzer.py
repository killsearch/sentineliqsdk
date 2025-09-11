from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.axur import AxurAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


class DummyAxurClient:
    def __init__(self, *a, **k):
        pass

    def customers(self) -> dict[str, Any]:
        return {"customers": [{"key": "ACME"}]}

    def call(self, method: str, path: str, options=None, **kwargs) -> dict[str, Any]:
        dry_run = False
        if options and hasattr(options, "dry_run"):
            dry_run = options.dry_run
        elif kwargs:
            dry_run = kwargs.get("dry_run", False)
        return {"dry_run": dry_run, "url": f"/api/{path}"}


def build_analyzer(data: str = "payload", data_type: DataType = "other") -> AxurAnalyzer:
    cfg = WorkerConfig(secrets={"axur": {"api_token": "tok"}})
    return AxurAnalyzer(WorkerInput(data_type=data_type, data=data, config=cfg))


def test_execute_with_config_method() -> None:
    cfg = WorkerConfig(
        secrets={"axur": {"api_token": "tok"}},
        params={"axur": {"method": "customers", "params": {}}},
    )
    with patch("sentineliqsdk.analyzers.axur.AxurClient", DummyAxurClient):
        analyzer = AxurAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4", config=cfg))
        rep = analyzer.execute()
        assert rep.success is True
        assert rep.full_report["details"]["method"] == "customers"
        assert rep.full_report["taxonomy"][0]["namespace"] == "axur"


def test_execute_with_payload_call_dry_run(monkeypatch) -> None:
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


def test_execute_config_params_not_mapping() -> None:
    cfg = WorkerConfig(
        secrets={"axur": {"api_token": "tok"}},
        params={"axur": {"method": "customers", "params": [1, 2]}},
    )
    analyzer = AxurAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4", config=cfg))
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_execute_payload_missing_method(monkeypatch) -> None:
    payload = {"no_method": True}
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_execute_payload_params_not_mapping(monkeypatch) -> None:
    payload = {"method": "customers", "params": [1, 2, 3]}  # invalid params type
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_execute_call_missing_path(monkeypatch) -> None:
    payload = {"method": "call", "params": {"http_method": "GET"}}  # missing path
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_execute_unsupported_method(monkeypatch) -> None:
    payload = {"method": "not_allowed", "params": {}}
    analyzer = build_analyzer(json.dumps(payload), data_type="other")
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_run_returns_none(monkeypatch) -> None:
    payload = {"method": "call", "params": {"path": "x"}}
    with patch("sentineliqsdk.analyzers.axur.AxurClient", DummyAxurClient):
        analyzer = build_analyzer(json.dumps(payload), data_type="other")
        analyzer.run()
