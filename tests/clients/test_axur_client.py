from __future__ import annotations

from typing import Any

import httpx
import pytest

from sentineliqsdk.clients.axur import AxurClient, _merge_query


def test_merge_query_boolean_and_existing() -> None:
    url = "https://api.example.test/path?a=1"
    out = _merge_query(url, {"b": True, "c": None, "d": 5})
    assert "a=1" in out and "b=true" in out and "d=5" in out


def test_call_dry_run_returns_plan() -> None:
    client = AxurClient(api_token="tok")
    plan = client.call(
        "GET",
        "/tickets-api/tickets",
        query={"page": 1},
        dry_run=True,
    )
    assert plan["dry_run"] is True
    assert plan["method"] == "GET"
    assert "/tickets-api/tickets" in plan["url"]
    assert plan["headers"]["Authorization"].startswith("Bearer ")


def test_request_json_success() -> None:
    client = AxurClient(api_token="tok")
    body = b'{"ok": true}'

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(
            status_code=200, content=body, headers={"Content-Type": "application/json"}
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client.call("GET", "/customers/customers")
        assert isinstance(result, dict) and result["ok"] is True
    finally:
        monkeypatch.undo()


def test_request_text_fallback_on_invalid_json() -> None:
    client = AxurClient(api_token="tok")
    body = b"not-json"

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(
            status_code=200, content=body, headers={"Content-Type": "application/json"}
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client.call("GET", "/customers/customers")
        assert result == "not-json"
    finally:
        monkeypatch.undo()


def test_request_non_json_content_type() -> None:
    client = AxurClient(api_token="tok")
    body = b"plain"

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(status_code=200, content=body, headers={"Content-Type": "text/plain"})

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client.call("GET", "/customers/customers")
        assert result == "plain"
    finally:
        monkeypatch.undo()


def test_http_error_with_body() -> None:
    client = AxurClient(api_token="tok")

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(
            status_code=400,
            content=b"failure-detail",
            headers={"Content-Type": "text/plain"},
            request=httpx.Request(method, url),
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        with pytest.raises(httpx.HTTPStatusError) as ei:
            client.call("GET", "/customers/customers")
        assert "failure-detail" in str(ei.value)
    finally:
        monkeypatch.undo()


def test_http_error_without_body() -> None:
    client = AxurClient(api_token="tok")

    def _fake_request(self, method, url, **kwargs):
        # No body
        return httpx.Response(status_code=400, request=httpx.Request(method, url))

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        with pytest.raises(httpx.HTTPStatusError):
            client.call("GET", "/x")
    finally:
        monkeypatch.undo()


def test_request_with_bytes_body_and_headers(monkeypatch) -> None:
    client = AxurClient(api_token="tok")

    def _fake_request(self, method, url, **kwargs):
        hdrs = kwargs.get("headers") or {}
        assert hdrs.get("X-Test") == "1"
        return httpx.Response(status_code=200, content=b"")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client.call(
            "POST",
            "/tickets-api/tickets",
            headers={"X-Test": "1"},
            data=b"raw",
        )
        assert result is None
    finally:
        monkeypatch.undo()


def test_wrappers_delegate_to_request(monkeypatch) -> None:
    captured: list[tuple[str, str, dict[str, Any]]] = []

    def fake_request(self, method, path, **kwargs):
        captured.append((method, path, kwargs))
        return {"ok": True}

    monkeypatch.setattr(AxurClient, "_request", fake_request)
    c = AxurClient(api_token="tok")
    c.customers()
    c.users(customers="ACM", pageSize=10)
    c.users_stream()
    c.tickets_search({"page": 1})
    c.ticket_create({"reference": "x", "customer": "ACM", "type": "phishing", "assets": ["A"]})
    c.tickets_by_keys("k1,k2", timezone="Z", include="fields")
    c.filter_create({"queries": [], "operation": "AND"})
    c.filter_results("qid", page=1, pageSize=2, sortBy="current.open.date", order="desc")
    c.ticket_get("abc")
    c.ticket_types()
    c.ticket_texts("xyz")
    c.integration_feed("fid", dry_run_param=True)

    assert any(p[1].startswith("/customers/") for p in captured)
    assert any(p[1].startswith("/identity/users") for p in captured)
    assert any(p[1].startswith("/tickets-api/tickets") for p in captured)
