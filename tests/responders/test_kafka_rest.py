from __future__ import annotations

import httpx
import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.kafka_rest import KafkaResponder


def test_kafka_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guard network
    monkeypatch.setattr(
        httpx.Client,
        "request",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError),
    )

    input_data = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "kafka": {"base_url": "http://localhost:8082", "topic": "demo", "value": "hello"},
                "execute": False,
                "include_dangerous": False,
            }
        ),
    )
    report = KafkaResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["url"].endswith("/topics/demo")


def test_kafka_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from typing import Any

    captured: dict[str, Any] = {}

    def _fake_request(self, method, url, **kwargs):
        captured["url"] = url
        captured["headers"] = dict(kwargs.get("headers") or {})
        captured["data"] = kwargs.get("json")
        return httpx.Response(status_code=200)

    monkeypatch.setattr(httpx.Client, "request", _fake_request)

    input_data = WorkerInput(
        data_type="other",
        data="payload",
        config=WorkerConfig(
            params={
                "kafka": {
                    "base_url": "http://localhost:8082",
                    "topic": "events",
                    "value": "x",
                    "headers": {"X-Trace": "1"},
                },
                "execute": True,
                "include_dangerous": True,
            },
            secrets={"kafka": {"basic_auth": "user:pass"}},
        ),
    )
    report = KafkaResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "published"
    assert captured["url"].endswith("/topics/events")
    # Expect content-type header set and Authorization present
    hdrs = {k.lower(): v for k, v in (captured["headers"] or {}).items()}
    assert hdrs["content-type"] == "application/json"
    assert any(k.lower() == "authorization" for k in (captured["headers"] or {}))
    assert captured["data"] == {"records": [{"value": "x"}]}


def test_kafka_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx.Client, "request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    input_data = WorkerInput(
        data_type="other",
        data="payload",
        config=WorkerConfig(
            params={
                "kafka": {"base_url": "http://localhost:8082", "topic": "demo"},
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    with pytest.raises(SystemExit):
        KafkaResponder(input_data).execute()


def test_kafka_invalid_headers_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx.Client, "request", lambda *a, **k: httpx.Response(200))

    input_data = WorkerInput(
        data_type="other",
        data="msg",
        config=WorkerConfig(
            params={
                "kafka": {"base_url": "http://localhost:8082", "topic": "demo", "headers": {}},
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    KafkaResponder(input_data).run()
