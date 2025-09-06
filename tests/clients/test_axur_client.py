from __future__ import annotations

import io
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.clients.axur import AxurClient, _merge_query


class DummyResponse:
    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        self._body = body
        self.headers = {"Content-Type": content_type}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> DummyResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


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

    def _fake_urlopen(req, timeout=None, context=None):
        return DummyResponse(body, content_type="application/json")

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client.call("GET", "/customers/customers")
        assert isinstance(result, dict) and result["ok"] is True


def test_request_text_fallback_on_invalid_json() -> None:
    client = AxurClient(api_token="tok")
    body = b"not-json"

    def _fake_urlopen(req, timeout=None, context=None):
        return DummyResponse(body, content_type="application/json")

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client.call("GET", "/customers/customers")
        assert result == "not-json"


def test_request_non_json_content_type() -> None:
    client = AxurClient(api_token="tok")
    body = b"plain"

    def _fake_urlopen(req, timeout=None, context=None):
        return DummyResponse(body, content_type="text/plain")

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client.call("GET", "/customers/customers")
        assert result == "plain"


def test_http_error_with_body() -> None:
    client = AxurClient(api_token="tok")

    def _fake_urlopen(req, timeout=None, context=None):
        fp = io.BytesIO(b"failure-detail")
        raise Exception  # type: ignore[misc]

    # Build a real HTTPError with a file-like to exercise error branch
    err = None
    fp = io.BytesIO(b"failure-detail")
    http_error = None
    try:
        http_error = __import__("urllib.error").error.HTTPError(
            url="http://x", code=400, msg="bad", hdrs=None, fp=fp
        )
    except Exception as e:  # pragma: no cover - safety
        err = e
    assert err is None

    def _raise_http_error(req, timeout=None, context=None):
        raise http_error  # type: ignore[misc]

    with patch("urllib.request.urlopen", _raise_http_error):
        with pytest.raises(__import__("urllib.error").error.HTTPError) as ei:
            client.call("GET", "/customers/customers")
        assert "failure-detail" in str(ei.value)


def test_http_error_without_body() -> None:
    client = AxurClient(api_token="tok")

    # Simulate HTTPError without readable body
    http_error = __import__("urllib.error").error.HTTPError(
        url="http://x", code=400, msg="bad", hdrs=None, fp=None
    )

    def _raise(req, timeout=None, context=None):
        raise http_error

    with patch("urllib.request.urlopen", _raise):
        with pytest.raises(__import__("urllib.error").error.HTTPError):
            client.call("GET", "/x")


def test_request_with_bytes_body_and_headers(monkeypatch) -> None:
    client = AxurClient(api_token="tok")

    def _fake_urlopen(req, timeout=None, context=None):
        # Ensure custom header is propagated (case-insensitive)
        assert (req.headers.get("X-Test") or req.headers.get("X-test")) == "1"
        return DummyResponse(b"")  # no body

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client.call(
            "POST",
            "/tickets-api/tickets",
            headers={"X-Test": "1"},
            data=b"raw",
        )
        assert result is None


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
