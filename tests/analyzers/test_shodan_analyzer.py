from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.shodan import ShodanAnalyzer
from sentineliqsdk.models import DataType, WorkerInput


class DummyShodanClient:
    def __init__(self, *a, **k):
        pass

    def ports(self):
        return [80, 443]

    def protocols(self):
        return {"http": 80}

    def host_information(self, ip: str, *, minify: bool | None = None) -> dict[str, Any]:
        # Return malware tag for 1.2.3.4 to trigger malicious
        if ip == "1.2.3.4":
            return {"tags": ["malware"]}
        return {"vulns": {"CVE-2024-0001": {}}}

    def dns_domain(self, domain: str):
        return {"domain": domain}

    def dns_resolve(self, domains: list[str]):
        return {domains[0]: "5.6.7.8"}

    def search_host_tokens(self, query: str):
        return {"query": query}


def build_analyzer(dtype: DataType, data: str) -> ShodanAnalyzer:
    os.environ["SHODAN_API_KEY"] = "key"
    return ShodanAnalyzer(WorkerInput(data_type=dtype, data=data))


def test_ip_analysis_malicious() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("ip", "1.2.3.4")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "malicious"
        assert rep.full_report["source"] == "shodan"


def test_domain_analysis_suspicious() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("domain", "example.com")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] in {"suspicious", "malicious", "safe"}
        # Given vulns present for 5.6.7.8, expect suspicious
        assert rep.full_report["verdict"] == "suspicious"


def test_dynamic_other_payload_call() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        payload = json.dumps({"method": "search_host_tokens", "params": {"query": "ssl"}})
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["taxonomy"][0]["predicate"] == "api-call"


def test_ip_analysis_safe_branch() -> None:
    class NoIssuesClient(DummyShodanClient):
        def host_information(self, ip: str, *, minify: bool | None = None):
            return {"tags": [], "vulns": {}}

    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", NoIssuesClient):
        analyzer = build_analyzer("ip", "9.9.9.9")
        rep = analyzer.execute()
        assert rep.full_report["verdict"] == "safe"


def test_other_payload_invalid_json() -> None:
    analyzer = build_analyzer("other", "not-json")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_other_payload_missing_method_and_bad_params() -> None:
    # Missing method
    analyzer = build_analyzer("other", json.dumps({"params": {}}))
    with pytest.raises(SystemExit):
        analyzer.execute()
    # Params not a mapping
    analyzer2 = build_analyzer("other", json.dumps({"method": "ports", "params": [1, 2]}))
    with pytest.raises(SystemExit):
        analyzer2.execute()


def test_env_params_invalid_json(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_METHOD", "ports")
    monkeypatch.setenv("SHODAN_PARAMS", "not-json")
    analyzer = build_analyzer("ip", "8.8.8.8")
    with pytest.raises(SystemExit):
        analyzer.execute()


def test_dynamic_env_call_tokens() -> None:
    os.environ["SHODAN_METHOD"] = "search_host_tokens"
    os.environ["SHODAN_PARAMS"] = json.dumps({"query": "ssl"})
    payload = json.dumps({"method": "ignored", "params": {}})
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("other", payload)
        rep = analyzer.execute()
        assert rep.full_report["details"]["method"] == "search_host_tokens"


def test_unsupported_dtype_error() -> None:
    os.environ.pop("SHODAN_METHOD", None)
    os.environ.pop("SHODAN_PARAMS", None)
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("hash", "deadbeef")
        with pytest.raises(SystemExit):
            analyzer.execute()


def test_run_returns_none() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("ip", "8.8.8.8")
        analyzer.run()
