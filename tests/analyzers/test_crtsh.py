from __future__ import annotations

from typing import Any

import httpx
import pytest

from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.crtsh import CrtshAnalyzer


class DummyResp:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            req = httpx.Request("GET", "http://dummy.local/test")
            resp = httpx.Response(self.status_code, request=req)
            raise httpx.HTTPStatusError("err", request=req, response=resp)


class DummyClient:
    def __init__(self, responses: dict[str, DummyResp]) -> None:
        self._responses = responses

    def get(self, url: str) -> DummyResp:
        for key, resp in self._responses.items():
            if key in url:
                return resp
        return DummyResp(404, "")

    def __enter__(self) -> DummyClient:
        """Enter context manager and return self."""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Exit context manager without special handling."""
        return


def test_execute_domain_monolithic_json(monkeypatch: Any) -> None:
    # Two concatenated JSON objects without comma
    base_payload = (
        '{"min_cert_id": 1, "name_value": "a.example.com"}'
        '{"min_cert_id": 2, "name_value": "b.example.com"}'
    )
    detail_html = (
        '<TH class="outer">SHA-1(Certificate)</TH>\n<TD class="outer">ABCDEF0123456789</TD>'
    )
    client = DummyClient(
        {
            "https://crt.sh/?q=example.com&output=json": DummyResp(200, base_payload),
            "https://crt.sh/?q=%25example.com.&output=json": DummyResp(200, base_payload),
            "https://crt.sh/?q=1": DummyResp(200, detail_html),
            "https://crt.sh/?q=2": DummyResp(200, detail_html),
        }
    )

    def fake_client(self: CrtshAnalyzer) -> DummyClient:  # type: ignore[override]
        return client

    monkeypatch.setattr(CrtshAnalyzer, "_http_client", fake_client)

    analyzer = CrtshAnalyzer(WorkerInput(data_type="domain", data="example.com"))
    report = analyzer.execute()

    assert report.success is True
    assert report.full_report["observable"] == "example.com"
    certs = report.full_report["certificates"]
    assert isinstance(certs, list)
    assert len(certs) >= 2
    assert all("sha1" in c for c in certs)


def test_unsupported_dtype() -> None:
    analyzer = CrtshAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4"))
    with pytest.raises(RuntimeError):
        analyzer.execute()
