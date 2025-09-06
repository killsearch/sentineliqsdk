from __future__ import annotations

import json

import pytest

from sentineliqsdk.models import WorkerInput
from sentineliqsdk.responders.kafka_rest import KafkaResponder


def test_kafka_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "0")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "0")
    monkeypatch.setenv("KAFKA_REST_URL", "http://localhost:8082")
    monkeypatch.setenv("KAFKA_TOPIC", "demo")
    monkeypatch.setenv("KAFKA_VALUE", "hello")

    # Guard network
    import urllib.request as _r

    monkeypatch.setattr(_r, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError))

    input_data = WorkerInput(data_type="other", data="hello")
    report = KafkaResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["url"].endswith("/topics/demo")


def test_kafka_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("KAFKA_REST_URL", "http://localhost:8082")
    monkeypatch.setenv("KAFKA_TOPIC", "events")
    monkeypatch.setenv("KAFKA_VALUE", "x")
    monkeypatch.setenv("KAFKA_HEADERS", json.dumps({"X-Trace": "1"}))
    monkeypatch.setenv("KAFKA_REST_AUTH", "user:pass")

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

    input_data = WorkerInput(data_type="other", data="payload")
    report = KafkaResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "published"
    assert captured["url"].endswith("/topics/events")
    # Expect content-type header set and Authorization present
    hdrs = {k.lower(): v for k, v in captured["headers"].items()}
    assert hdrs["content-type"] == "application/json"
    assert any(k.lower() == "authorization" for k in captured["headers"].keys())
    assert captured["data"] == {"records": [{"value": "x"}]}


def test_kafka_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("KAFKA_REST_URL", "http://localhost:8082")
    monkeypatch.setenv("KAFKA_TOPIC", "demo")

    import urllib.request as _r

    monkeypatch.setattr(_r, "urlopen", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    input_data = WorkerInput(data_type="other", data="payload")
    with pytest.raises(SystemExit):
        KafkaResponder(input_data).execute()


def test_kafka_invalid_headers_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("KAFKA_REST_URL", "http://localhost:8082")
    monkeypatch.setenv("KAFKA_TOPIC", "demo")
    monkeypatch.setenv("KAFKA_HEADERS", "not-json")

    import urllib.request as _r

    class DummyResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(_r, "urlopen", lambda *a, **k: DummyResp())

    input_data = WorkerInput(data_type="other", data="msg")
    KafkaResponder(input_data).run()
