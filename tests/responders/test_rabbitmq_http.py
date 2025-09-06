from __future__ import annotations

import json

import pytest

from sentineliqsdk.models import WorkerInput
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder


def test_rabbitmq_dry_run_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "0")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "0")
    monkeypatch.setenv("RABBITMQ_API_URL", "http://localhost:15672")
    monkeypatch.setenv("RABBITMQ_VHOST", "/prod")
    monkeypatch.setenv("RABBITMQ_EXCHANGE", "ex")
    monkeypatch.setenv("RABBITMQ_ROUTING_KEY", "rk")
    monkeypatch.setenv("RABBITMQ_MESSAGE", "hello")

    # vhost must be percent-encoded in URL
    input_data = WorkerInput(data_type="other", data="hello")
    report = RabbitMqResponder(input_data).execute()
    url = report.full_report["url"]
    assert url.endswith("/api/exchanges/%2Fprod/ex/publish")
    assert report.full_report["dry_run"] is True


def test_rabbitmq_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("RABBITMQ_API_URL", "http://localhost:15672")
    monkeypatch.setenv("RABBITMQ_VHOST", "/")
    monkeypatch.setenv("RABBITMQ_EXCHANGE", "ex")
    monkeypatch.setenv("RABBITMQ_ROUTING_KEY", "rk")
    monkeypatch.setenv("RABBITMQ_USERNAME", "guest")
    monkeypatch.setenv("RABBITMQ_PASSWORD", "guest")
    monkeypatch.setenv("RABBITMQ_PROPERTIES", json.dumps({"delivery_mode": 2}))
    monkeypatch.setenv("RABBITMQ_MESSAGE", "hello")

    import urllib.request as _r

    captured = {}

    class DummyResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    def _fake_urlopen(req, data=None, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["data"] = json.loads(data.decode("utf-8"))
        return DummyResp()

    monkeypatch.setattr(_r, "urlopen", _fake_urlopen)

    input_data = WorkerInput(data_type="other", data="hello")
    report = RabbitMqResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "published"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert captured["data"]["routing_key"] == "rk"
    assert captured["data"]["payload"] == "hello"


def test_rabbitmq_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("RABBITMQ_API_URL", "http://localhost:15672")
    monkeypatch.setenv("RABBITMQ_EXCHANGE", "ex")

    import urllib.request as _r

    monkeypatch.setattr(_r, "urlopen", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    input_data = WorkerInput(data_type="other", data="hello")
    with pytest.raises(SystemExit):
        RabbitMqResponder(input_data).execute()


def test_rabbitmq_invalid_properties_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("RABBITMQ_API_URL", "http://localhost:15672")
    monkeypatch.setenv("RABBITMQ_EXCHANGE", "ex")
    monkeypatch.setenv("RABBITMQ_PROPERTIES", "not-json")

    import urllib.request as _r

    class DummyResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(_r, "urlopen", lambda *a, **k: DummyResp())

    input_data = WorkerInput(data_type="other", data="hello")
    RabbitMqResponder(input_data).run()
