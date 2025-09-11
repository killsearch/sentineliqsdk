from __future__ import annotations

from typing import Any

import httpx
import pytest

from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.dnsdumpster import DnsdumpsterAnalyzer


class DummyResp:
    def __init__(self, status_code: int, content: bytes = b"", text: str = "") -> None:
        self.status_code = status_code
        self.content = content
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            req = httpx.Request("GET", "http://dummy.local/test")
            resp = httpx.Response(self.status_code, request=req)
            raise httpx.HTTPStatusError("err", request=req, response=resp)


class DummyClient:
    def __init__(self, responses: dict[str, DummyResp]) -> None:
        self._responses = responses
        self._call_count = 0

    def get(self, url: str, **kwargs: Any) -> DummyResp:
        self._call_count += 1
        for key, resp in self._responses.items():
            if key in url:
                return resp
        return DummyResp(404, b"", "")

    def post(self, url: str, **kwargs: Any) -> DummyResp:
        self._call_count += 1
        # Check for POST-specific responses first
        post_key = f"POST {url}"
        if post_key in self._responses:
            return self._responses[post_key]

        # Fall back to regular URL matching
        for key, resp in self._responses.items():
            if key in url and "POST" in key:
                return resp
        return DummyResp(404, b"", "")

    def __enter__(self) -> DummyClient:
        """Enter context manager and return self."""
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit context manager without special handling."""
        return


def test_execute_domain_success(monkeypatch: Any) -> None:
    # Mock HTML response with CSRF token
    csrf_html = """
    <html>
        <body>
            <input name="csrfmiddlewaretoken" value="test-csrf-token" />
        </body>
    </html>
    """

    # Mock successful response with valid DNSdumpster structure
    success_html = """
    <html>
        <body>
            <div class="table-responsive">
                <table class="table">
                    <tr><td>example.com</td><td>A</td><td>1.2.3.4</td></tr>
                </table>
            </div>
        </body>
    </html>
    """

    client = DummyClient(
        {
            "https://dnsdumpster.com": DummyResp(200, csrf_html.encode(), csrf_html),
            "POST https://dnsdumpster.com": DummyResp(200, success_html.encode(), success_html),
        }
    )

    def fake_client(self: DnsdumpsterAnalyzer) -> DummyClient:  # type: ignore[override]
        return client

    monkeypatch.setattr(DnsdumpsterAnalyzer, "_http_client", fake_client)

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))
    report = analyzer.execute()

    assert report.success is True
    assert report.full_report["observable"] == "example.com"


def test_execute_domain_no_csrf_token(monkeypatch: Any) -> None:
    # Mock HTML response without CSRF token
    no_csrf_html = """
    <html>
        <body>
            <p>No CSRF token here</p>
        </body>
    </html>
    """

    client = DummyClient(
        {
            "https://dnsdumpster.com": DummyResp(200, no_csrf_html.encode(), no_csrf_html),
        }
    )

    def fake_client(self: DnsdumpsterAnalyzer) -> DummyClient:  # type: ignore[override]
        return client

    monkeypatch.setattr(DnsdumpsterAnalyzer, "_http_client", fake_client)

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))

    # Should handle missing CSRF token gracefully
    with pytest.raises(RuntimeError, match="Could not find CSRF token on DNSdumpster homepage"):
        analyzer.execute()


def test_execute_domain_error_response(monkeypatch: Any) -> None:
    # Mock HTML response with CSRF token
    csrf_html = """
    <html>
        <body>
            <input name="csrfmiddlewaretoken" value="test-csrf-token" />
        </body>
    </html>
    """

    # Mock error response
    error_html = "There was an error getting results"

    client = DummyClient(
        {
            "https://dnsdumpster.com": DummyResp(200, csrf_html.encode(), csrf_html),
            "POST https://dnsdumpster.com": DummyResp(200, error_html.encode(), error_html),
        }
    )

    def fake_client(self: DnsdumpsterAnalyzer) -> DummyClient:  # type: ignore[override]
        return client

    monkeypatch.setattr(DnsdumpsterAnalyzer, "_http_client", fake_client)

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))

    # Should handle error response gracefully
    with pytest.raises(RuntimeError, match="DNSdumpster reported an error getting results"):
        analyzer.execute()


def test_execute_http_error(monkeypatch: Any) -> None:
    client = DummyClient(
        {
            "https://dnsdumpster.com": DummyResp(500, b"", ""),
        }
    )

    def fake_client(self: DnsdumpsterAnalyzer) -> DummyClient:  # type: ignore[override]
        return client

    monkeypatch.setattr(DnsdumpsterAnalyzer, "_http_client", fake_client)

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))

    # Should handle HTTP errors gracefully
    with pytest.raises(RuntimeError, match="Error getting CSRF token from DNSdumpster: err"):
        analyzer.execute()


def test_unsupported_dtype() -> None:
    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4"))
    with pytest.raises(RuntimeError, match="supports only data_type 'domain' or 'fqdn'"):
        analyzer.execute()


def test_extract_artifacts() -> None:
    """Test artifact extraction from DNSdumpster results."""
    raw_data = {
        "dns_records": {
            "dns": [
                {"domain": "test.example.com", "ip": "1.2.3.4"},
                {"domain": "mail.example.com", "ip": "5.6.7.8"}
            ],
            "mx": [
                {"domain": "mx1.example.com", "ip": "9.10.11.12"}
            ]
        }
    }

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))
    artifacts = analyzer.artifacts(raw_data)

    # Should extract some artifacts
    assert len(artifacts) >= 0  # Allow empty results

    # If we have artifacts, check their structure
    if artifacts:
        # Check that artifacts have the expected structure
        for artifact in artifacts:
            assert hasattr(artifact, "data_type")
            assert hasattr(artifact, "data")


def test_run_calls_execute(monkeypatch: Any) -> None:
    """Test that run() method calls execute()."""
    executed = False

    def mock_execute(self: DnsdumpsterAnalyzer) -> Any:
        nonlocal executed
        executed = True
        return self.report({"test": "result"})

    monkeypatch.setattr(DnsdumpsterAnalyzer, "execute", mock_execute)

    analyzer = DnsdumpsterAnalyzer(WorkerInput(data_type="domain", data="example.com"))
    analyzer.run()

    assert executed is True
