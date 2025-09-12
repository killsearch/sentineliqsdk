"""Elasticsearch Analyzer: queries Elasticsearch clusters for security analysis.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.elasticsearch import ElasticsearchAnalyzer

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    report = ElasticsearchAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Provide connection details via `WorkerConfig.secrets['elasticsearch']`:
  - 'host': Elasticsearch host URL (required)
  - 'username': Authentication username (optional)
  - 'password': Authentication password (optional)
  - 'api_key': API key for authentication (optional)
  - 'ca_certs': Path to CA certificates (optional)
- HTTP proxies honored via `WorkerConfig.proxy`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Allowlist of safe Elasticsearch API endpoints for dynamic calls
ALLOWED_ENDPOINTS: set[str] = {
    "_search",
    "_count",
    "_mapping",
    "_settings",
    "_stats",
    "_health",
    "_nodes",
    "_cluster/health",
    "_cluster/stats",
    "_cat/indices",
    "_cat/nodes",
    "_cat/health",
}


class ElasticsearchAnalyzer(Analyzer):
    """Analyzer that queries Elasticsearch for security-related information."""

    # Security thresholds constants
    ATTACK_COUNT_THRESHOLD = 5
    SUSPICIOUS_COUNT_THRESHOLD = 3
    FAILED_LOGINS_THRESHOLD = 10

    METADATA = ModuleMetadata(
        name="Elasticsearch Analyzer",
        description="Query Elasticsearch clusters for security analysis and threat hunting",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/elasticsearch/",
        version_stage="TESTING",
    )

    def _get_client_config(self) -> dict[str, Any]:
        """Get Elasticsearch client configuration from secrets."""
        host = self.get_secret("elasticsearch.host")
        if not host:
            self.error("Missing Elasticsearch host (set config.secrets['elasticsearch']['host'])")

        config = {
            "base_url": str(host).rstrip("/"),
            "timeout": self.get_config("elasticsearch.timeout", 30),
            "verify": self.get_config("elasticsearch.verify_ssl", True),
        }

        # Authentication options
        username = self.get_secret("elasticsearch.username")
        password = self.get_secret("elasticsearch.password")
        api_key = self.get_secret("elasticsearch.api_key")

        if api_key:
            config["headers"] = {"Authorization": f"ApiKey {api_key}"}
        elif username and password:
            config["auth"] = (str(username), str(password))

        # SSL configuration
        ca_certs = self.get_secret("elasticsearch.ca_certs")
        if ca_certs:
            config["verify"] = str(ca_certs)

        return config

    def _make_request(self, endpoint: str, method: str = "GET", **kwargs) -> dict[str, Any]:
        """Make HTTP request to Elasticsearch API."""
        config = self._get_client_config()

        with httpx.Client(**config) as client:
            try:
                response = client.request(method=method, url=f"/{endpoint.lstrip('/')}", **kwargs)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                self.error(f"Elasticsearch API request failed: {e}")
            except json.JSONDecodeError as e:
                self.error(f"Failed to parse Elasticsearch response: {e}")

    def _search_observable(self, observable: str, data_type: str) -> dict[str, Any]:
        """Search for observable in Elasticsearch indices."""
        # Build query based on data type
        query_field_map = {
            "ip": ["src_ip", "dst_ip", "client_ip", "server_ip", "ip", "host.ip"],
            "domain": ["domain", "dns.question.name", "url.domain", "host.name"],
            "url": ["url.full", "url.original", "http.request.referrer"],
            "hash": ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5"],
            "mail": ["email", "user.email", "source.user.email", "destination.user.email"],
        }

        fields = query_field_map.get(data_type, ["message", "_all"])

        # Build multi-field query
        should_clauses = []
        for field in fields:
            should_clauses.extend(
                [
                    {"term": {field: observable}},
                    {"wildcard": {field: f"*{observable}*"}},
                ]
            )

        query = {
            "query": {"bool": {"should": should_clauses, "minimum_should_match": 1}},
            "size": self.get_config("elasticsearch.max_results", 100),
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": True,
        }

        # Search across all indices by default
        index = self.get_config("elasticsearch.index", "*")
        endpoint = f"{index}/_search"

        return self._make_request(endpoint, method="POST", json=query)

    def _analyze_search_results(self, results: dict[str, Any]) -> dict[str, Any]:
        """Analyze search results for security indicators."""
        hits = results.get("hits", {}).get("hits", [])
        total_hits = results.get("hits", {}).get("total", {}).get("value", 0)

        # Security analysis
        security_indicators = {
            "malware_signatures": 0,
            "suspicious_processes": 0,
            "network_anomalies": 0,
            "failed_logins": 0,
            "privilege_escalations": 0,
        }

        threat_keywords = [
            "malware",
            "virus",
            "trojan",
            "backdoor",
            "ransomware",
            "suspicious",
            "anomaly",
            "attack",
            "intrusion",
            "breach",
            "failed",
            "unauthorized",
            "privilege",
            "escalation",
        ]

        for hit in hits:
            source = hit.get("_source", {})
            message = str(source.get("message", "")).lower()

            # Count security indicators
            for keyword in threat_keywords:
                if keyword in message:
                    if keyword in ["malware", "virus", "trojan", "backdoor", "ransomware"]:
                        security_indicators["malware_signatures"] += 1
                    elif keyword in ["suspicious", "anomaly"]:
                        security_indicators["suspicious_processes"] += 1
                    elif keyword in ["attack", "intrusion", "breach"]:
                        security_indicators["network_anomalies"] += 1
                    elif keyword in ["failed", "unauthorized"]:
                        security_indicators["failed_logins"] += 1
                    elif keyword in ["privilege", "escalation"]:
                        security_indicators["privilege_escalations"] += 1

        return {
            "total_hits": total_hits,
            "analyzed_hits": len(hits),
            "security_indicators": security_indicators,
            "sample_events": hits[:5],  # Include first 5 events as samples
        }

    def _determine_verdict(self, analysis: dict[str, Any]) -> TaxonomyLevel:
        """Determine security verdict based on analysis results."""
        indicators = analysis.get("security_indicators", {})
        total_hits = analysis.get("total_hits", 0)

        # High-risk indicators
        malware_count = indicators.get("malware_signatures", 0)
        attack_count = indicators.get("network_anomalies", 0)

        if malware_count > 0 or attack_count > self.ATTACK_COUNT_THRESHOLD:
            return "malicious"

        # Medium-risk indicators
        suspicious_count = indicators.get("suspicious_processes", 0)
        failed_logins = indicators.get("failed_logins", 0)
        privilege_escalations = indicators.get("privilege_escalations", 0)

        if (
            suspicious_count > self.SUSPICIOUS_COUNT_THRESHOLD
            or failed_logins > self.FAILED_LOGINS_THRESHOLD
            or privilege_escalations > 0
        ):
            return "suspicious"

        # Low activity but present
        if total_hits > 0:
            return "info"

        return "safe"

    def _call_dynamic_endpoint(
        self, endpoint: str, method: str = "GET", params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call Elasticsearch API endpoint dynamically."""
        if endpoint not in ALLOWED_ENDPOINTS:
            self.error(f"Unsupported Elasticsearch endpoint: {endpoint}")

        kwargs = {}
        if method.upper() == "POST" and params:
            kwargs["json"] = params
        elif params:
            kwargs["params"] = params

        return self._make_request(endpoint, method=method, **kwargs)

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport."""
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via config method
        config_method = self.get_config("elasticsearch.method")
        if config_method:
            return self._handle_config_method(config_method, observable, dtype)

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            return self._handle_other_data_type(observable, dtype)

        # 3) Default behavior: search for observable
        return self._handle_default_search(observable, dtype)

    def _handle_config_method(self, method: str, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle dynamic API call via config method."""
        params = self.get_config("elasticsearch.params", {})
        if not isinstance(params, dict):
            self.error("Elasticsearch params must be a dictionary")

        details = {
            "method": method,
            "params": params,
            "result": self._call_dynamic_endpoint(method, "GET", params),
        }

        taxonomy = self.build_taxonomy(
            level="info",
            namespace="elasticsearch",
            predicate="api-call",
            value=method,
        )

        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "elasticsearch",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def _handle_other_data_type(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle dynamic call via JSON payload when dtype == other."""
        try:
            payload = json.loads(str(observable))
        except json.JSONDecodeError:
            self.error(
                "For data_type 'other', data must be a JSON string with 'endpoint' and optional 'params'"
            )

        if not isinstance(payload, dict):
            self.error("For data_type 'other', JSON payload must be an object")

        if "endpoint" not in payload:
            self.error("Missing 'endpoint' in payload for data_type 'other'")

        endpoint = str(payload["endpoint"])
        method = str(payload.get("method", "GET")).upper()
        params = payload.get("params", {})

        if not isinstance(params, dict):
            self.error("Payload 'params' must be a dictionary")

        details = {
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "result": self._call_dynamic_endpoint(endpoint, method, params),
        }

        taxonomy = self.build_taxonomy(
            level="info",
            namespace="elasticsearch",
            predicate="api-call",
            value=endpoint,
        )

        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "elasticsearch",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def _handle_default_search(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle default search behavior for observables."""
        if dtype not in ["ip", "domain", "url", "hash", "mail", "fqdn"]:
            self.error(f"Unsupported data type for ElasticsearchAnalyzer: {dtype}")

        # Perform search
        search_results = self._search_observable(str(observable), dtype)
        analysis = self._analyze_search_results(search_results)
        verdict = self._determine_verdict(analysis)

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="elasticsearch",
            predicate="search",
            value=str(observable),
        )

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "elasticsearch",
            "data_type": dtype,
            "details": {
                "search_results": search_results,
                "analysis": analysis,
            },
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
