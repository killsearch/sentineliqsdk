"""Shodan Analyzer: wraps the ShodanClient to analyze IPs and domains.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.shodan import ShodanAnalyzer

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    report = ShodanAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Provide API key via `WorkerConfig.secrets['shodan']['api_key']`.
- HTTP proxies honored via `WorkerConfig.proxy`.
"""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Mapping
from typing import Any

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.clients import ShodanClient
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Allowlist of ShodanClient methods exposed for dynamic calls
ALLOWED_METHODS: set[str] = {
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


class ShodanAnalyzer(Analyzer):
    """Analyzer that queries Shodan for information about IPs and domains."""

    METADATA = ModuleMetadata(
        name="Shodan Analyzer",
        description="Query Shodan for IP/domain intel and dynamic API calls",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/shodan/",
        version_stage="STABLE",
    )

    def _client(self) -> ShodanClient:
        api_key = self.get_secret("shodan.api_key")
        if not api_key:
            self.error("Missing Shodan API key (set config.secrets['shodan']['api_key'])")
        return ShodanClient(api_key=str(api_key))

    def _call_dynamic(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Call any supported ShodanClient method using kwargs.

        This enables full API coverage from the analyzer via either:
        - Programmatic config params: `config.params['shodan']['method']` and optional
          `config.params['shodan']['params']`
        - Data payload when `data_type == "other"` and `data` is a JSON string
          like: {"method": "search_host", "params": {"query": "port:22"}}
        """
        client = self._client()

        # Validate method against allowlist
        if method not in ALLOWED_METHODS:
            self.error(f"Unsupported Shodan method: {method}")
        if params is not None and not isinstance(params, Mapping):
            self.error("Shodan params must be a mapping object (JSON object).")
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

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via environment variables
        # Programmatic dynamic call via params: shodan.method / shodan.params
        env_method = self.get_config("shodan.method")
        if env_method:
            params: dict[str, Any] = {}
            cfg_params = self.get_config("shodan.params")
            if isinstance(cfg_params, Mapping):
                params = dict(cfg_params)
            elif cfg_params is not None:
                self.error("Shodan params must be a JSON object.")

            details = {
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
            full_report = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "source": "shodan",
                "data_type": dtype,
                "details": details,
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            try:
                payload = json.loads(str(observable))
            except json.JSONDecodeError:
                self.error(
                    "For data_type 'other', data must be a JSON string with keys 'method' and 'params'."
                )
            if not isinstance(payload, Mapping):
                self.error("For data_type 'other', JSON payload must be an object.")
            if "method" not in payload:
                self.error("Missing 'method' in payload for data_type 'other'.")
            method = str(payload["method"])  # force to str
            params_val = payload.get("params", {})
            if params_val is None:
                params_val = {}
            if not isinstance(params_val, Mapping):
                self.error("Payload 'params' must be a JSON object.")
            details = {
                "method": method,
                "params": dict(params_val),
                "result": self._call_dynamic(method, params_val),
            }
            taxonomy = self.build_taxonomy(
                level="info",
                namespace="shodan",
                predicate="api-call",
                value=method,
            )
            full_report = {
                "observable": observable,
                "verdict": "info",
                "taxonomy": [taxonomy.to_dict()],
                "source": "shodan",
                "data_type": dtype,
                "details": details,
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

        # 3) Default behavior for common observables
        if dtype == "ip":
            details = self._analyze_ip(str(observable))
            verdict = self._verdict_from_shodan(details)
        elif dtype in ("domain", "fqdn"):
            details = self._analyze_domain(str(observable))
            verdict = self._verdict_from_shodan(details)
        else:
            self.error(f"Unsupported data type for ShodanAnalyzer: {dtype}.")

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="shodan",
            predicate="reputation",
            value=str(observable),
        )
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "shodan",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> None:
        """Run analysis (side-effect only; use execute() for programmatic result)."""
        self.execute()
