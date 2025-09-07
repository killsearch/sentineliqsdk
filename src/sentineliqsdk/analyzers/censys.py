"""Censys Analyzer: comprehensive analyzer for Censys Platform API.

This analyzer provides access to all Censys Platform API methods including:
- Collections management (list, create, delete, get, update, events)
- Global data search and retrieval (hosts, certificates, web properties)
- Search and aggregation capabilities
- Timeline analysis for hosts

Usage example:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.censys import CensysAnalyzer

    secrets = {
        "censys": {
            "personal_access_token": "your_token_here",
            "organization_id": "your_org_id_here"
        }
    }
    input_data = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(secrets=secrets)
    )
    report = CensysAnalyzer(input_data).execute()

Configuration:
- Provide API credentials via `WorkerConfig.secrets['censys']['personal_access_token']`
- Provide organization ID via `WorkerConfig.secrets['censys']['organization_id']`
- HTTP proxies honored via `WorkerConfig.proxy`
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Allowlist of Censys Platform API methods exposed for dynamic calls
ALLOWED_METHODS: set[str] = {
    # Collections methods
    "collections_list",
    "collections_create",
    "collections_delete",
    "collections_get",
    "collections_update",
    "collections_list_events",
    "collections_aggregate",
    "collections_search",
    # Global data methods
    "global_data_get_certificates",
    "global_data_get_certificate",
    "global_data_get_hosts",
    "global_data_get_host",
    "global_data_get_host_timeline",
    "global_data_get_web_properties",
    "global_data_get_web_property",
    "global_data_aggregate",
    "global_data_search",
}


class CensysAnalyzer(Analyzer):
    """Comprehensive analyzer for Censys Platform API with full method coverage."""

    METADATA = ModuleMetadata(
        name="Censys Analyzer",
        description="Comprehensive Censys Platform API analyzer with full method coverage",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/censys/",
        version_stage="STABLE",
    )

    def _client(self) -> Any:
        """Initialize Censys Platform SDK client."""
        try:
            from censys_platform import SDK
        except ImportError:
            self.error("Censys Platform SDK not installed. Run: pip install censys-platform")

        personal_access_token = self.get_secret("censys.personal_access_token")
        organization_id = self.get_secret("censys.organization_id")

        if not personal_access_token:
            self.error(
                "Missing Censys personal access token (set config.secrets['censys']['personal_access_token'])"
            )
        if not organization_id:
            self.error(
                "Missing Censys organization ID (set config.secrets['censys']['organization_id'])"
            )

        return SDK(
            personal_access_token=str(personal_access_token), organization_id=str(organization_id)
        )

    def _call_dynamic(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Call any supported Censys Platform API method using kwargs.

        This enables full API coverage from the analyzer via either:
        - Programmatic config params: `config.params['censys']['method']` and optional
          `config.params['censys']['params']`
        - Data payload when `data_type == "other"` and `data` is a JSON string
          like: {"method": "global_data_search", "params": {"query": "services.port:80"}}
        """
        with self._client() as sdk:
            # Validate method against allowlist
            if method not in ALLOWED_METHODS:
                self.error(f"Unsupported Censys method: {method}")
            if params is not None and not isinstance(params, Mapping):
                self.error("Censys params must be a mapping object (JSON object).")

            try:
                # Map method names to SDK calls
                if method.startswith("collections_"):
                    return self._call_collections_method(sdk, method, params)
                if method.startswith("global_data_"):
                    return self._call_global_data_method(sdk, method, params)
                self.error(f"Unknown method category: {method}")
            except Exception as e:
                self.error(f"Censys API call failed: {e}")

    def _call_collections_method(
        self, sdk: Any, method: str, params: Mapping[str, Any] | None
    ) -> Any:
        """Call collections-related methods."""
        method_map = {
            "collections_list": sdk.collections.list,
            "collections_create": sdk.collections.create,
            "collections_delete": sdk.collections.delete,
            "collections_get": sdk.collections.get,
            "collections_update": sdk.collections.update,
            "collections_list_events": sdk.collections.list_events,
            "collections_aggregate": sdk.collections.aggregate,
            "collections_search": sdk.collections.search,
        }

        func = method_map.get(method)
        if not func:
            self.error(f"Unknown collections method: {method}")

        return func(**(dict(params) if params else {}))

    def _call_global_data_method(
        self, sdk: Any, method: str, params: Mapping[str, Any] | None
    ) -> Any:
        """Call global data-related methods."""
        method_map = {
            "global_data_get_certificates": sdk.global_data.get_certificates,
            "global_data_get_certificate": sdk.global_data.get_certificate,
            "global_data_get_hosts": sdk.global_data.get_hosts,
            "global_data_get_host": sdk.global_data.get_host,
            "global_data_get_host_timeline": sdk.global_data.get_host_timeline,
            "global_data_get_web_properties": sdk.global_data.get_web_properties,
            "global_data_get_web_property": sdk.global_data.get_web_property,
            "global_data_aggregate": sdk.global_data.aggregate,
            "global_data_search": sdk.global_data.search,
        }

        func = method_map.get(method)
        if not func:
            self.error(f"Unknown global data method: {method}")

        return func(**(dict(params) if params else {}))

    def _analyze_ip(self, ip: str) -> dict[str, Any]:
        """Analyze IP address using Censys host data."""
        with self._client() as sdk:
            try:
                # Get host information
                host_data = sdk.global_data.get_host(ip=ip)

                # Get host timeline for historical data
                timeline_data = sdk.global_data.get_host_timeline(ip=ip)

                # Search for related hosts
                search_query = f"ip:{ip}"
                search_results = sdk.global_data.search(
                    search_query_input_body={"query": search_query},
                    organization_id=self.get_secret("censys.organization_id"),
                )

                return {
                    "host": host_data,
                    "timeline": timeline_data,
                    "search_results": search_results,
                }
            except Exception as e:
                self.error(f"Censys host lookup failed: {e}")

    def _analyze_domain(self, domain: str) -> dict[str, Any]:
        """Analyze domain using Censys web properties and certificates."""
        with self._client() as sdk:
            try:
                # Search for web properties
                web_search_query = f"services.http.response.html_title:{domain}"
                web_results = sdk.global_data.search(
                    search_query_input_body={"query": web_search_query},
                    organization_id=self.get_secret("censys.organization_id"),
                )

                # Search for certificates
                cert_search_query = f"parsed.names:{domain}"
                cert_results = sdk.global_data.search(
                    search_query_input_body={"query": cert_search_query},
                    organization_id=self.get_secret("censys.organization_id"),
                )

                # Get web properties if found
                web_properties = []
                if hasattr(web_results, "hits") and web_results.hits:
                    for hit in web_results.hits[:5]:  # Limit to first 5
                        if hasattr(hit, "ip"):
                            try:
                                web_prop = sdk.global_data.get_web_property(ip=hit.ip)
                                web_properties.append(web_prop)
                            except Exception:
                                continue

                return {
                    "domain": domain,
                    "web_search_results": web_results,
                    "certificate_search_results": cert_results,
                    "web_properties": web_properties,
                }
            except Exception as e:
                self.error(f"Censys domain lookup failed: {e}")

    def _analyze_certificate(self, cert_hash: str) -> dict[str, Any]:
        """Analyze certificate using Censys certificate data."""
        with self._client() as sdk:
            try:
                # Get certificate details
                cert_data = sdk.global_data.get_certificate(fingerprint=cert_hash)

                # Search for related certificates
                search_query = f"parsed.fingerprint_sha256:{cert_hash}"
                search_results = sdk.global_data.search(
                    search_query_input_body={"query": search_query},
                    organization_id=self.get_secret("censys.organization_id"),
                )

                return {"certificate": cert_data, "search_results": search_results}
            except Exception as e:
                self.error(f"Censys certificate lookup failed: {e}")

    def _verdict_from_censys(self, payload: dict[str, Any]) -> TaxonomyLevel:
        """Determine verdict based on Censys data analysis."""
        try:
            # Check for malicious indicators in host data
            if "host" in payload:
                host_data = payload["host"]
                if isinstance(host_data, dict):
                    # Check for known malicious services or vulnerabilities
                    services = host_data.get("services", [])
                    if isinstance(services, list):
                        for service in services:
                            if isinstance(service, dict):
                                # Check for suspicious ports or services
                                port = service.get("port")
                                if port in [
                                    22,
                                    23,
                                    135,
                                    139,
                                    445,
                                    1433,
                                    3389,
                                ]:  # Common attack vectors
                                    return "suspicious"

                                # Check for known malicious banners
                                banner = service.get("banner", "").lower()
                                if any(
                                    keyword in banner
                                    for keyword in ["malware", "trojan", "backdoor", "exploit"]
                                ):
                                    return "malicious"

            # Check for suspicious certificate patterns
            if "certificate" in payload:
                cert_data = payload["certificate"]
                if isinstance(cert_data, dict):
                    # Check for self-signed certificates
                    if cert_data.get("parsed", {}).get("is_ca") is False:
                        return "suspicious"

                    # Check for expired certificates
                    if cert_data.get("parsed", {}).get("validity", {}).get("not_after"):
                        # This would need date parsing in a real implementation
                        pass

            # Check search results for suspicious patterns
            if "search_results" in payload:
                search_data = payload["search_results"]
                if hasattr(search_data, "hits") and search_data.hits:
                    # If many results, might indicate widespread presence
                    if len(search_data.hits) > 100:
                        return "suspicious"

        except Exception:
            pass

        return "safe"

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via configuration parameters
        config_method = self.get_config("censys.method")
        if config_method:
            return self._handle_config_method(config_method, observable, dtype)

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            return self._handle_other_dtype(observable, dtype)

        # 3) Default behavior for common observables
        return self._handle_default_analysis(observable, dtype)

    def _handle_config_method(
        self, config_method: str, observable: Any, dtype: str
    ) -> AnalyzerReport:
        """Handle dynamic call via configuration parameters."""
        params: dict[str, Any] = {}
        cfg_params = self.get_config("censys.params")
        if isinstance(cfg_params, Mapping):
            params = dict(cfg_params)
        elif cfg_params is not None:
            self.error("Censys params must be a JSON object.")

        details = {
            "method": config_method,
            "params": params,
            "result": self._call_dynamic(config_method, params),
        }
        taxonomy = self.build_taxonomy(
            level="info",
            namespace="censys",
            predicate="api-call",
            value=config_method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "censys",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def _handle_other_dtype(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle dynamic call via data payload when dtype == other."""
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

        method = str(payload["method"])
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
            namespace="censys",
            predicate="api-call",
            value=method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "censys",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def _handle_default_analysis(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle default behavior for common observables."""
        if dtype == "ip":
            details = self._analyze_ip(str(observable))
            verdict = self._verdict_from_censys(details)
        elif dtype in ("domain", "fqdn"):
            details = self._analyze_domain(str(observable))
            verdict = self._verdict_from_censys(details)
        elif dtype == "hash":
            # Assume hash is certificate fingerprint
            details = self._analyze_certificate(str(observable))
            verdict = self._verdict_from_censys(details)
        else:
            self.error(f"Unsupported data type for CensysAnalyzer: {dtype}.")

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="censys",
            predicate="reputation",
            value=str(observable),
        )
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "censys",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> None:
        """Run analysis (side-effect only; use execute() for programmatic result)."""
        self.execute()
