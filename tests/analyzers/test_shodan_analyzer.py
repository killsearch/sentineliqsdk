from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from sentineliqsdk.analyzers.shodan import ShodanAnalyzer
from sentineliqsdk.models import DataType, WorkerConfig, WorkerInput


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
    cfg = WorkerConfig(secrets={"shodan": {"api_key": "key"}})
    return ShodanAnalyzer(WorkerInput(data_type=dtype, data=data, config=cfg))


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
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_other_payload_missing_method_and_bad_params() -> None:
    # Missing method
    analyzer = build_analyzer("other", json.dumps({"params": {}}))
    with pytest.raises(RuntimeError):
        analyzer.execute()
    # Params not a mapping
    analyzer2 = build_analyzer("other", json.dumps({"method": "ports", "params": [1, 2]}))
    with pytest.raises(RuntimeError):
        analyzer2.execute()


def test_config_params_not_mapping() -> None:
    cfg = WorkerConfig(
        secrets={"shodan": {"api_key": "k"}},
        params={"shodan": {"method": "ports", "params": [1, 2]}},
    )
    analyzer = ShodanAnalyzer(WorkerInput(data_type="ip", data="8.8.8.8", config=cfg))
    with pytest.raises(RuntimeError):
        analyzer.execute()


def test_dynamic_config_call_tokens() -> None:
    cfg = WorkerConfig(
        secrets={"shodan": {"api_key": "key"}},
        params={"shodan": {"method": "search_host_tokens", "params": {"query": "ssl"}}},
    )
    payload = json.dumps({"method": "ignored", "params": {}})
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = ShodanAnalyzer(WorkerInput(data_type="other", data=payload, config=cfg))
        rep = analyzer.execute()
        assert rep.full_report["details"]["method"] == "search_host_tokens"


def test_unsupported_dtype_error() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("hash", "deadbeef")
        with pytest.raises(RuntimeError):
            analyzer.execute()


def test_run_returns_none() -> None:
    with patch("sentineliqsdk.analyzers.shodan.ShodanClient", DummyShodanClient):
        analyzer = build_analyzer("ip", "8.8.8.8")
        analyzer.run()
