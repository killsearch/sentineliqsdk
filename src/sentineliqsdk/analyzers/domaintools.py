"""DomainTools Analyzer: comprehensive domain intelligence using DomainTools API.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.domaintools import DomainToolsAnalyzer

    input_data = WorkerInput(data_type="domain", data="example.com")
    report = DomainToolsAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Provide API credentials via `WorkerConfig.secrets['domaintools']['username']` and
  `WorkerConfig.secrets['domaintools']['api_key']`.
- HTTP proxies honored via `WorkerConfig.proxy`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from domaintools import API

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Allowlist of DomainTools API methods exposed for dynamic calls
ALLOWED_METHODS: set[str] = {
    "iris_enrich",
    "iris_investigate",
    "domain_profile",
    "domain_search",
    "reverse_ip",
    "host_domains",
    "name_server_domains",
    "whois",
    "whois_history",
    "parsed_whois",
    "reverse_whois",
    "reputation",
    "reverse_name_server",
    "ip_registrant_monitor",
    "name_server_monitor",
    "reverse_ip_whois",
    "hosting_history",
    "ip_monitor",
    "registrant_monitor",
    "whois_lookup",
    "brand_monitor",
    "domain_suggestions",
    "phisheye",
    "phisheye_term_list",
    "account_information",
    "usage",
    "risk",
}


class DomainToolsAnalyzer(Analyzer):
    """Analyzer that queries DomainTools for comprehensive domain intelligence.

    Supports multiple DomainTools API endpoints including Iris Enrich, Domain Profile,
    Risk scoring, Whois data, and more. Provides both default analysis and dynamic
    method calling capabilities.
    """

    METADATA = ModuleMetadata(
        name="DomainTools Analyzer",
        description="Comprehensive domain intelligence using DomainTools Iris API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/domaintools/",
        version_stage="TESTING",
    )

    def _client(self) -> API:
        """Initialize DomainTools API client with credentials."""
        username = self.get_secret("domaintools.username")
        api_key = self.get_secret("domaintools.api_key")

        if not username or not api_key:
            self.error(
                "Missing DomainTools credentials. Set config.secrets['domaintools']['username'] "
                "and config.secrets['domaintools']['api_key']"
            )

        return API(str(username), str(api_key))

    def _call_dynamic(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Call any supported DomainTools API method using kwargs.

        This enables full API coverage from the analyzer via either:
        - Programmatic config params: `config.params['domaintools']['method']` and optional
          `config.params['domaintools']['params']`
        - Data payload when `data_type == "other"` and `data` is a JSON string
          like: {"method": "iris_enrich", "params": {"domains": ["example.com"]}}
        """
        client = self._client()

        # Validate method against allowlist
        if method not in ALLOWED_METHODS:
            self.error(f"Unsupported DomainTools method: {method}")
        if params is not None and not isinstance(params, Mapping):
            self.error("DomainTools params must be a mapping object (JSON object).")

        func = getattr(client, method)
        try:
            result = func(**(dict(params) if params else {}))
            # Handle different response types from DomainTools API
            if hasattr(result, "response"):
                return result.response()
            if hasattr(result, "data"):
                return result.data()
            return result
        except Exception as e:
            self.error(f"DomainTools API call failed: {e}")

    def _analyze_domain(self, domain: str) -> dict[str, Any]:
        """Perform comprehensive domain analysis using multiple DomainTools endpoints."""
        client = self._client()
        results = {}

        try:
            # Core domain intelligence
            results["iris_enrich"] = client.iris_enrich(domain).response()
            results["domain_profile"] = client.domain_profile(domain).response()
            results["risk"] = client.risk(domain).response()

            # Whois information
            try:
                results["whois"] = client.whois(domain).response()
            except Exception:
                results["whois"] = {"error": "whois-lookup-failed"}

            # Historical data if available
            try:
                results["whois_history"] = client.whois_history(domain).response()
            except Exception:
                results["whois_history"] = {"error": "history-not-available"}

        except Exception as e:
            self.error(f"DomainTools domain analysis failed: {e}")

        return results

    def _analyze_ip(self, ip: str) -> dict[str, Any]:
        """Analyze IP address using DomainTools reverse IP lookup."""
        client = self._client()
        results = {}

        try:
            results["reverse_ip"] = client.reverse_ip(ip).response()
            results["host_domains"] = client.host_domains(ip).response()
        except Exception as e:
            self.error(f"DomainTools IP analysis failed: {e}")

        return results

    def _analyze_email(self, email: str) -> dict[str, Any]:
        """Analyze email using DomainTools reverse whois lookup."""
        client = self._client()
        results = {}

        try:
            results["reverse_whois"] = client.reverse_whois(terms=email).response()
        except Exception as e:
            self.error(f"DomainTools email analysis failed: {e}")

        return results

    def _verdict_from_domaintools(self, payload: dict[str, Any]) -> TaxonomyLevel:
        """Determine verdict based on DomainTools analysis results."""
        try:
            # Check risk score from risk endpoint
            if "risk" in payload and isinstance(payload["risk"], dict):
                risk_data = payload["risk"]
                if "risk_score" in risk_data:
                    risk_score = risk_data["risk_score"]
                    if isinstance(risk_score, (int, float)):
                        if risk_score >= 70:
                            return "malicious"
                        if risk_score >= 40:
                            return "suspicious"
                        return "safe"

            # Check Iris Enrich results for risk indicators
            if "iris_enrich" in payload and isinstance(payload["iris_enrich"], dict):
                iris_data = payload["iris_enrich"]
                if "results" in iris_data and isinstance(iris_data["results"], list):
                    for result in iris_data["results"]:
                        if isinstance(result, dict) and "risk_score" in result:
                            risk_score = result["risk_score"]
                            if isinstance(risk_score, (int, float)):
                                if risk_score >= 70:
                                    return "malicious"
                                if risk_score >= 40:
                                    return "suspicious"

            # Check domain profile for suspicious indicators
            if "domain_profile" in payload and isinstance(payload["domain_profile"], dict):
                profile = payload["domain_profile"]
                if "response" in profile and isinstance(profile["response"], dict):
                    response = profile["response"]
                    # Check for recent registration (potential indicator)
                    if "registrant" in response and "registration" in response:
                        # Additional heuristics can be added here
                        pass

        except Exception:
            pass

        return "safe"

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via environment variables
        env_method = self.get_config("domaintools.method")
        if env_method:
            return self._handle_env_method(env_method, observable, dtype)

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            return self._handle_other_dtype(observable, dtype)

        # 3) Default behavior for common observables
        return self._handle_default_analysis(observable, dtype)

    def _handle_env_method(self, env_method: str, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle dynamic call via environment variables."""
        params: dict[str, Any] = {}
        cfg_params = self.get_config("domaintools.params")
        if isinstance(cfg_params, Mapping):
            params = dict(cfg_params)
        elif cfg_params is not None:
            self.error("DomainTools params must be a JSON object.")

        details = {
            "method": env_method,
            "params": params,
            "result": self._call_dynamic(env_method, params),
        }
        taxonomy = self.build_taxonomy(
            level="info",
            namespace="domaintools",
            predicate="api-call",
            value=env_method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "domaintools",
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
            namespace="domaintools",
            predicate="api-call",
            value=method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "domaintools",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def _handle_default_analysis(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle default behavior for common observables."""
        if dtype in ("domain", "fqdn"):
            details = self._analyze_domain(str(observable))
            verdict = self._verdict_from_domaintools(details)
        elif dtype == "ip":
            details = self._analyze_ip(str(observable))
            verdict = "info"  # IP analysis is informational by default
        elif dtype == "mail":
            details = self._analyze_email(str(observable))
            verdict = "info"  # Email analysis is informational by default
        else:
            self.error(f"Unsupported data type for DomainToolsAnalyzer: {dtype}.")

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="domaintools",
            predicate="reputation",
            value=str(observable),
        )
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "domaintools",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
