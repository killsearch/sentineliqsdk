from __future__ import annotations

import httpx
import pytest

from sentineliqsdk.clients.shodan import ShodanClient, _merge_query


def test_merge_query_appends_params() -> None:
    url = "https://api.shodan.io/path?x=1"
    out = _merge_query(url, {"y": 2, "z": True})
    assert "x=1" in out and "y=2" in out and "z=true" in out


def test_merge_query_none_and_skip_none_values() -> None:
    base = "https://api.shodan.io/path"
    # None params -> url unchanged
    assert _merge_query(base, None) == base
    # Skip keys with None values
    out = _merge_query(base, {"a": None, "b": 1})
    assert "a=" not in out and "b=1" in out


def test_get_parses_json_and_injects_key() -> None:
    client = ShodanClient(api_key="abc", base_url="https://api.shodan.io")
    captured = {}

    def _fake_request(self, method, url, **kwargs):
        captured["url"] = url
        return httpx.Response(
            status_code=200, content=b'{"ok": true}', headers={"Content-Type": "application/json"}
        )

    # Patch httpx.Client.request
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client._get("/shodan/ports")
        assert result == {"ok": True}
        assert "key=abc" in captured["url"]
    finally:
        monkeypatch.undo()


def test_post_with_json_body() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_request(self, method, url, **kwargs):
        # Ensure content-type header is json
        hdrs = kwargs.get("headers") or {}
        ct = hdrs.get("Content-Type")
        # httpx sets the json content-type automatically, but header may not be present here;
        # Accept either header set by client or rely on body being present in json kwarg
        assert (kwargs.get("json") is not None) or (ct and ct.startswith("application/json"))
        return httpx.Response(
            status_code=200,
            content=b'{"status": "ok"}',
            headers={"Content-Type": "application/json"},
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client._post("/shodan/scan", json_body={"ips": "1.1.1.1"})
        assert result["status"] == "ok"
    finally:
        monkeypatch.undo()


def test_post_with_form_data() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_request(self, method, url, **kwargs):
        hdrs = kwargs.get("headers") or {}
        ct = hdrs.get("Content-Type") or ""
        assert "application/x-www-form-urlencoded" in ct
        return httpx.Response(
            status_code=200, content=b'{"done": true}', headers={"Content-Type": "application/json"}
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client._post("/shodan/scan", data={"ips": "8.8.8.8"})
        assert result["done"] is True
    finally:
        monkeypatch.undo()


def test_http_error_includes_body() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(
            status_code=400,
            content=b"bad-request",
            headers={"Content-Type": "text/plain"},
            request=httpx.Request(method, url),
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        with pytest.raises(httpx.HTTPStatusError) as ei:
            client._get("/shodan/ports")
        assert "bad-request" in str(ei.value)
    finally:
        monkeypatch.undo()


def test_post_with_bytes_data() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_request(self, method, url, **kwargs):
        return httpx.Response(
            status_code=200, content=b"ok", headers={"Content-Type": "text/plain"}
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(httpx.Client, "request", _fake_request)
    try:
        result = client._post("/shodan/scan", data=b"raw")
        assert result == "ok"
    finally:
        monkeypatch.undo()
