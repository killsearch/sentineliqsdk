from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from sentineliqsdk.clients.shodan import ShodanClient, _merge_query


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

    def _fake_urlopen(req, timeout=None, context=None):
        # Capture URL to assert key param injection
        captured["url"] = req.full_url
        return DummyResponse(b'{"ok": true}')

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client._get("/shodan/ports")
        assert result == {"ok": True}
        assert "key=abc" in captured["url"]


def test_post_with_json_body() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_urlopen(req, timeout=None, context=None):
        # Ensure content-type header is json (case-insensitive in urllib)
        ct = req.headers.get("Content-Type") or req.headers.get("Content-type")
        assert ct and ct.startswith("application/json")
        return DummyResponse(b'{"status": "ok"}')

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client._post("/shodan/scan", json_body={"ips": "1.1.1.1"})
        assert result["status"] == "ok"


def test_post_with_form_data() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_urlopen(req, timeout=None, context=None):
        ct = req.headers.get("Content-Type") or req.headers.get("Content-type")
        assert ct and "application/x-www-form-urlencoded" in ct
        return DummyResponse(b'{"done": true}')

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client._post("/shodan/scan", data={"ips": "8.8.8.8"})
        assert result["done"] is True


def test_http_error_includes_body() -> None:
    client = ShodanClient(api_key="abc")
    fp = io.BytesIO(b"bad-request")
    http_error = __import__("urllib.error").error.HTTPError(
        url="http://x", code=400, msg="bad", hdrs=None, fp=fp
    )

    def _raise(req, timeout=None, context=None):
        raise http_error

    with patch("urllib.request.urlopen", _raise):
        with pytest.raises(__import__("urllib.error").error.HTTPError) as ei:
            client._get("/shodan/ports")
        assert "bad-request" in str(ei.value)


def test_post_with_bytes_data() -> None:
    client = ShodanClient(api_key="abc")

    def _fake_urlopen(req, timeout=None, context=None):
        return DummyResponse(b"ok", content_type="text/plain")

    with patch("urllib.request.urlopen", _fake_urlopen):
        result = client._post("/shodan/scan", data=b"raw")
        assert result == "ok"
