from __future__ import annotations

from typing import Any

import httpx
import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder


def test_rabbitmq_dry_run_url(monkeypatch: pytest.MonkeyPatch) -> None:
    # vhost must be percent-encoded in URL
    input_data = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "rabbitmq": {
                    "api_url": "http://localhost:15672",
                    "vhost": "/prod",
                    "exchange": "ex",
                    "routing_key": "rk",
                    "message": "hello",
                },
                "execute": False,
                "include_dangerous": False,
            }
        ),
    )
    report = RabbitMqResponder(input_data).execute()
    url = report.full_report["url"]
    assert url.endswith("/api/exchanges/%2Fprod/ex/publish")
    assert report.full_report["dry_run"] is True


def test_rabbitmq_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_request(self, method, url, **kwargs):
        captured["url"] = url
        captured["headers"] = dict(kwargs.get("headers") or {})
        # httpx json kwarg arrives as dict
        captured["data"] = kwargs.get("json")
        return httpx.Response(status_code=200)

    monkeypatch.setattr(httpx.Client, "request", _fake_request)

    input_data = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "rabbitmq": {
                    "api_url": "http://localhost:15672",
                    "vhost": "/",
                    "exchange": "ex",
                    "routing_key": "rk",
                    "message": "hello",
                    "properties": {"delivery_mode": 2},
                },
                "execute": True,
                "include_dangerous": True,
            },
            secrets={"rabbitmq": {"username": "guest", "password": "guest"}},
        ),
    )
    report = RabbitMqResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "published"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert captured["data"]["routing_key"] == "rk"
    assert captured["data"]["payload"] == "hello"


def test_rabbitmq_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx.Client, "request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    input_data = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "rabbitmq": {"api_url": "http://localhost:15672", "exchange": "ex"},
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    with pytest.raises(RuntimeError) as exc_info:
        RabbitMqResponder(input_data).execute()
    assert "RabbitMQ publish failed" in str(exc_info.value)


def test_rabbitmq_invalid_properties_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx.Client, "request", lambda *a, **k: httpx.Response(200))

    input_data = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "rabbitmq": {
                    "api_url": "http://localhost:15672",
                    "exchange": "ex",
                    "properties": {},
                },
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    RabbitMqResponder(input_data).run()
