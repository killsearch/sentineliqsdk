from __future__ import annotations

import json

import httpx
import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.webhook import WebhookResponder


def test_webhook_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"request": False}

    def _no_call(self, method, url, **kwargs):
        called["request"] = True
        raise AssertionError("network should not be called in dry-run")

    monkeypatch.setattr(httpx.Client, "request", _no_call)

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
    assert called["request"] is False


def test_webhook_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from typing import Any

    captured: dict[str, Any] = {}

    def _fake_request(self, method, url, **kwargs):
        captured["url"] = url
        captured["headers"] = dict(kwargs.get("headers") or {})
        captured["data"] = kwargs.get("content")
        return httpx.Response(status_code=200)

    monkeypatch.setattr(httpx.Client, "request", _fake_request)

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
    # Header keys can be normalized; compare case-insensitively
    hdrs = {k.lower(): v for k, v in (captured["headers"] or {}).items()}
    assert hdrs["content-type"] == "application/json"
    assert json.loads(captured["data"].decode("utf-8")) == {"ok": True}


def test_webhook_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(self, method, url, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(httpx.Client, "request", _boom)

    input_data = WorkerInput(
        data_type="url",
        data="https://example.com",
        config=WorkerConfig(params={"execute": True, "include_dangerous": True}),
    )
    with pytest.raises(RuntimeError):
        WebhookResponder(input_data).execute()


def test_webhook_plain_text_and_invalid_headers_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Execute with plain-text body; also call run()

    from typing import Any

    captured: dict[str, Any] = {}

    def _fake_request(self, method, url, **kwargs):
        hdrs = dict(kwargs.get("headers") or {})
        captured["headers"] = {k.lower(): v for k, v in hdrs.items()}
        captured["data"] = kwargs.get("content")
        return httpx.Response(status_code=204)

    monkeypatch.setattr(httpx.Client, "request", _fake_request)

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
    assert (captured["headers"] or {})["content-type"] == "text/plain"
    assert (captured["data"] or b"").decode("utf-8") == "plain text"
