"""Shodan Analyzer: wraps the ShodanClient to analyze IPs and domains.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.shodan import ShodanAnalyzer

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    result = ShodanAnalyzer(input_data).run()  # returns AnalyzerReport

Configuration:
- Provide API key via environment variable `SHODAN_API_KEY`.
- HTTP proxies honored via `WorkerConfig.proxy` or environment.
"""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Mapping
from typing import Any

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.clients import ShodanClient
from sentineliqsdk.models import TaxonomyLevel


class ShodanAnalyzer(Analyzer):
    """Analyzer that queries Shodan for information about IPs and domains."""

    def _client(self) -> ShodanClient:
        api_key = self.get_env("SHODAN_API_KEY", message="Missing SHODAN_API_KEY in environment.")
        # Proxies are already exported to env by Worker; urllib will respect them.
        return ShodanClient(api_key=api_key)

    def _call_dynamic(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Call any supported ShodanClient method using kwargs.

        This enables full API coverage from the analyzer via either:
        - Environment: `SHODAN_METHOD` and optional `SHODAN_PARAMS` (JSON string)
        - Data payload when `data_type == "other"` and `data` is a JSON string
          like: {"method": "search_host", "params": {"query": "port:22"}}
        """
        client = self._client()

        # Allowlist of callable methods (full coverage of client)
        allowed = {
            "host_information",
            "search_host_count",
            "search_host",
            "search_host_facets",
            "search_host_filters",
            "search_host_tokens",
            "ports",
            "protocols",
            "scan",
            "scan_internet",
            "scans",
            "scan_by_id",
            "alert_create",
            "alert_info",
            "alert_delete",
            "alert_edit",
            "alerts",
            "alert_triggers",
            "alert_enable_trigger",
            "alert_disable_trigger",
            "alert_whitelist_service",
            "alert_unwhitelist_service",
            "alert_add_notifier",
            "alert_remove_notifier",
            "notifiers",
            "notifier_providers",
            "notifier_create",
            "notifier_delete",
            "notifier_get",
            "notifier_update",
            "queries",
            "query_search",
            "query_tags",
            "data_datasets",
            "data_dataset",
            "org",
            "org_member_update",
            "org_member_remove",
            "account_profile",
            "dns_domain",
            "dns_resolve",
            "dns_reverse",
            "tools_httpheaders",
            "tools_myip",
            "api_info",
        }
        if method not in allowed:
            self.error(f"Unsupported Shodan method: {method}")
        func = getattr(client, method)
        try:
            return func(**(dict(params) if params else {}))
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            self.error(f"Shodan API call failed: {e}")

    def _analyze_ip(self, ip: str) -> dict[str, Any]:
        client = self._client()
        try:
            host = client.host_information(ip, minify=False)
            # Optionally include aux data
            ports = client.ports()
            protos = client.protocols()
            return {"host": host, "ports_catalog": ports, "protocols": protos}
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            self.error(f"Shodan host lookup failed: {e}")

    def _analyze_domain(self, domain: str) -> dict[str, Any]:
        client = self._client()
        try:
            dom = client.dns_domain(domain)
            resolved = client.dns_resolve([domain])
            # If it resolves, enrich with host details for each resolved IP (minify to keep light)
            hosts: dict[str, Any] = {}
            if isinstance(resolved, dict):
                for host, ip in resolved.items():
                    try:
                        hosts[ip] = client.host_information(ip, minify=True)
                    except (urllib.error.HTTPError, urllib.error.URLError):
                        hosts[ip] = {"error": "lookup-failed"}
            return {"domain": dom, "resolved": resolved, "hosts": hosts}
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            self.error(f"Shodan domain lookup failed: {e}")

    def _verdict_from_shodan(self, payload: dict[str, Any]) -> TaxonomyLevel:
        # Very lightweight heuristic: vulns => suspicious; malware tag => malicious
        try:
            # host payload could be at payload["host"] (ip) or nested under hosts (domain)
            candidates: list[dict[str, Any]] = []
            if "host" in payload and isinstance(payload["host"], dict):
                candidates.append(payload["host"])
            if "hosts" in payload and isinstance(payload["hosts"], dict):
                for v in payload["hosts"].values():
                    if isinstance(v, dict):
                        candidates.append(v)

            has_malware = any("malware" in (h.get("tags") or []) for h in candidates)
            has_vulns = any(bool(h.get("vulns")) for h in candidates)
            if has_malware:
                return "malicious"
            if has_vulns:
                return "suspicious"
        except Exception:
            pass
        return "safe"

    def run(self) -> None:
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via environment variables
        env_method = self.get_env("SHODAN_METHOD")
        if env_method:
            params: dict[str, Any] = {}
            env_params = self.get_env("SHODAN_PARAMS")
            if env_params:
                try:
                    params = json.loads(env_params)
                except json.JSONDecodeError:
                    self.error("Invalid SHODAN_PARAMS (must be JSON).")

            full = {
                "method": env_method,
                "params": params,
                "result": self._call_dynamic(env_method, params),
            }
            taxonomy = self.build_taxonomy(
                level="info",
                namespace="shodan",
                predicate="api-call",
                value=env_method,
            )
            envelope = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "source": "shodan",
                "data_type": dtype,
                "details": full,
            }
            self.report(envelope)
            return

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            try:
                payload = json.loads(str(observable))
                method = payload["method"]
                params = payload.get("params", {})
                full = {
                    "method": method,
                    "params": params,
                    "result": self._call_dynamic(method, params),
                }
                taxonomy = self.build_taxonomy(
                    level="info",
                    namespace="shodan",
                    predicate="api-call",
                    value=method,
                )
                envelope = {
                    "observable": observable,
                    "verdict": "info",
                    "taxonomy": [taxonomy.to_dict()],
                    "source": "shodan",
                    "data_type": dtype,
                    "details": full,
                }
                self.report(envelope)
                return
            except Exception:
                self.error(
                    "For data_type 'other', data must be a JSON string with keys 'method' and 'params'."
                )

        # 3) Default behavior for common observables
        if dtype == "ip":
            full = self._analyze_ip(str(observable))
            verdict = self._verdict_from_shodan(full)
        elif dtype in ("domain", "fqdn"):
            full = self._analyze_domain(str(observable))
            verdict = self._verdict_from_shodan(full)
        else:
            self.error(f"Unsupported data type for ShodanAnalyzer: {dtype}.")

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="shodan",
            predicate="reputation",
            value=str(observable),
        )
        envelope = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "shodan",
            "data_type": dtype,
            "details": full,
        }
        self.report(envelope)
