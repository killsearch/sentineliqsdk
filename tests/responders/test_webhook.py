from __future__ import annotations

import json

import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.webhook import WebhookResponder


def test_webhook_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"urlopen": False}

    import urllib.request as _r

    def _no_call(*a, **k):
        called["urlopen"] = True
        raise AssertionError("network should not be called in dry-run")

    monkeypatch.setattr(_r, "urlopen", _no_call)

    input_data = WorkerInput(
        data_type="url",
        data="https://example.com/webhook",
        config=WorkerConfig(
            params={
                "webhook": {"method": "GET", "headers": {"X-Test": "1"}},
                "execute": False,
                "include_dangerous": False,
            }
        ),
    )
    report = WebhookResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["method"] == "GET"
    assert called["urlopen"] is False


def test_webhook_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
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
        captured["data"] = data
        return DummyResp()

    monkeypatch.setattr(_r, "urlopen", _fake_urlopen)

    input_data = WorkerInput(
        data_type="url",
        data="https://httpbin.org/post",
        config=WorkerConfig(
            params={
                "webhook": {
                    "method": "POST",
                    "headers": {"X-Token": "abc"},
                    "body": {"ok": True},
                },
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    report = WebhookResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "delivered"
    assert captured["url"] == "https://httpbin.org/post"
    # Header keys can be normalized differently by urllib; compare case-insensitively
    hdrs = {k.lower(): v for k, v in captured["headers"].items()}
    assert hdrs["content-type"] == "application/json"
    assert json.loads(captured["data"].decode("utf-8")) == {"ok": True}


def test_webhook_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request as _r

    def _boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(_r, "urlopen", _boom)

    input_data = WorkerInput(
        data_type="url",
        data="https://example.com",
        config=WorkerConfig(params={"execute": True, "include_dangerous": True}),
    )
    with pytest.raises(SystemExit):
        WebhookResponder(input_data).execute()


def test_webhook_plain_text_and_invalid_headers_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Execute with plain-text body; also call run()

    import urllib.request as _r

    captured = {}

    class DummyResp:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    def _fake_urlopen(req, data=None, timeout=None):
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["data"] = data
        return DummyResp()

    monkeypatch.setattr(_r, "urlopen", _fake_urlopen)

    input_data = WorkerInput(
        data_type="url",
        data="https://example.com/hook",
        config=WorkerConfig(
            params={
                "webhook": {"headers": {}, "body": "plain text"},
                "execute": True,
                "include_dangerous": True,
            }
        ),
    )
    WebhookResponder(input_data).run()
    assert captured["headers"]["content-type"] == "text/plain"
    assert captured["data"].decode("utf-8") == "plain text"
