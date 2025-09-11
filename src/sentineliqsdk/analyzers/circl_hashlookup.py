"""CIRCL Hashlookup Analyzer: queries the CIRCL hashlookup service for hash reputation.

This analyzer provides comprehensive hash lookup capabilities using the CIRCL hashlookup
API, including basic lookups, bulk operations, parent/child relationships, and session
management.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

    input_data = WorkerInput(data_type="hash", data="5d41402abc4b2a76b9719d911017c592")
    report = CirclHashlookupAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- No API key required (public service)
- HTTP proxies honored via `WorkerConfig.proxy`
- Supports dynamic method calls via config.params
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# HTTP status codes
HTTP_NOT_FOUND = 404
HTTP_BAD_REQUEST = 400

# Allowlist of supported methods for dynamic calls
ALLOWED_METHODS: set[str] = {
    "lookup_md5",
    "lookup_sha1",
    "lookup_sha256",
    "bulk_md5",
    "bulk_sha1",
    "get_children",
    "get_parents",
    "get_info",
    "create_session",
    "get_session",
    "get_stats_top",
}


class CirclHashlookupAnalyzer(Analyzer):
    """Analyzer that queries CIRCL hashlookup for hash reputation and relationships."""

    METADATA = ModuleMetadata(
        name="CIRCL Hashlookup Analyzer",
        description="Query CIRCL hashlookup for hash reputation, relationships, and bulk operations",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/circl_hashlookup/",
        version_stage="STABLE",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)
        self.base_url = "https://hashlookup.circl.lu"
        self.session = httpx.Client(
            headers={"Content-type": "application/json", "Accept": "text/plain"},
            timeout=30.0,
        )

    def __del__(self):
        """Clean up HTTP session."""
        if hasattr(self, "session"):
            self.session.close()

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length and format."""
        hash_value = hash_value.lower().strip()

        if re.match(r"^[0-9a-f]{32}$", hash_value):
            return "md5"
        if re.match(r"^[0-9a-f]{40}$", hash_value):
            return "sha1"
        if re.match(r"^[0-9a-f]{64}$", hash_value):
            return "sha256"
        if re.match(r"^[0-9a-f]{128}$", hash_value):
            return "sha512"
        return "unknown"

    def _make_request(self, method: str, url: str, **kwargs) -> dict[str, Any]:
        """Make HTTP request with error handling."""
        try:
            if method.upper() == "GET":
                response = self.session.get(url, **kwargs)
            if method.upper() == "POST":
                response = self.session.post(url, **kwargs)
            if method.upper() not in ("GET", "POST"):
                self.error(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == HTTP_NOT_FOUND:
                return {"error": "not_found", "message": "Hash not found in database"}
            if e.response.status_code == HTTP_BAD_REQUEST:
                return {"error": "invalid_format", "message": "Invalid hash format"}
            self.error(f"CIRCL API request failed: {e}")
        except httpx.RequestError as e:
            self.error(f"CIRCL API connection failed: {e}")
        except json.JSONDecodeError:
            self.error("Invalid JSON response from CIRCL API")

    def _lookup_hash(self, hash_value: str, hash_type: str) -> dict[str, Any]:
        """Perform basic hash lookup."""
        url = f"{self.base_url}/lookup/{hash_type}/{hash_value}"
        return self._make_request("GET", url)

    def _bulk_lookup(self, hashes: list[str], hash_type: str) -> dict[str, Any]:
        """Perform bulk hash lookup."""
        url = f"{self.base_url}/bulk/{hash_type}"
        payload = {"hashes": hashes}
        return self._make_request("POST", url, json=payload)

    def _get_children(self, sha1: str, count: int = 100, cursor: str = "0") -> dict[str, Any]:
        """Get children of a SHA1 hash."""
        url = f"{self.base_url}/children/{sha1}/{count}/{cursor}"
        return self._make_request("GET", url)

    def _get_parents(self, sha1: str, count: int = 100, cursor: str = "0") -> dict[str, Any]:
        """Get parents of a SHA1 hash."""
        url = f"{self.base_url}/parents/{sha1}/{count}/{cursor}"
        return self._make_request("GET", url)

    def _get_info(self) -> dict[str, Any]:
        """Get database information."""
        url = f"{self.base_url}/info"
        return self._make_request("GET", url)

    def _create_session(self, name: str) -> dict[str, Any]:
        """Create a session for tracking searches."""
        url = f"{self.base_url}/session/create/{name}"
        return self._make_request("GET", url)

    def _get_session(self, name: str) -> dict[str, Any]:
        """Get session results."""
        url = f"{self.base_url}/session/get/{name}"
        return self._make_request("GET", url)

    def _get_stats_top(self) -> dict[str, Any]:
        """Get top statistics."""
        url = f"{self.base_url}/stats/top"
        return self._make_request("GET", url)

    def _call_lookup_methods(self, method: str, params_dict: dict[str, Any]) -> Any:
        """Handle lookup methods."""
        if method == "lookup_md5":
            return self._lookup_hash(params_dict["hash"], "md5")
        if method == "lookup_sha1":
            return self._lookup_hash(params_dict["hash"], "sha1")
        if method == "lookup_sha256":
            return self._lookup_hash(params_dict["hash"], "sha256")
        return None

    def _call_bulk_methods(self, method: str, params_dict: dict[str, Any]) -> Any:
        """Handle bulk methods."""
        if method == "bulk_md5":
            return self._bulk_lookup(params_dict["hashes"], "md5")
        if method == "bulk_sha1":
            return self._bulk_lookup(params_dict["hashes"], "sha1")
        return None

    def _call_relationship_methods(self, method: str, params_dict: dict[str, Any]) -> Any:
        """Handle relationship methods."""
        if method == "get_children":
            return self._get_children(
                params_dict["sha1"],
                params_dict.get("count", 100),
                params_dict.get("cursor", "0"),
            )
        if method == "get_parents":
            return self._get_parents(
                params_dict["sha1"],
                params_dict.get("count", 100),
                params_dict.get("cursor", "0"),
            )
        return None

    def _call_utility_methods(self, method: str, params_dict: dict[str, Any]) -> Any:
        """Handle utility methods."""
        if method == "get_info":
            return self._get_info()
        if method == "create_session":
            return self._create_session(params_dict["name"])
        if method == "get_session":
            return self._get_session(params_dict["name"])
        if method == "get_stats_top":
            return self._get_stats_top()
        return None

    def _call_dynamic(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Call any supported method using kwargs."""
        if method not in ALLOWED_METHODS:
            self.error(f"Unsupported CIRCL method: {method}")

        if params is not None and not isinstance(params, Mapping):
            self.error("CIRCL params must be a mapping object (JSON object).")

        params_dict = dict(params) if params else {}

        try:
            # Try lookup methods
            result = self._call_lookup_methods(method, params_dict)
            if result is not None:
                return result

            # Try bulk methods
            result = self._call_bulk_methods(method, params_dict)
            if result is not None:
                return result

            # Try relationship methods
            result = self._call_relationship_methods(method, params_dict)
            if result is not None:
                return result

            # Try utility methods
            result = self._call_utility_methods(method, params_dict)
            if result is not None:
                return result

            self.error(f"Method {method} not implemented")
        except KeyError as e:
            self.error(f"Missing required parameter for {method}: {e}")

    def _verdict_from_result(self, result: dict[str, Any]) -> TaxonomyLevel:
        """Determine verdict based on lookup result."""
        if "error" in result:
            if result["error"] == "not_found":
                return "info"  # Unknown hash
            return "info"  # Other errors

        # Hash found in database - consider it safe/known
        if "hashlookup:trust" in result or "KnownGood" in str(result):
            return "safe"
        return "info"

    def _analyze_hash(self, hash_value: str) -> dict[str, Any]:
        """Analyze a single hash."""
        hash_type = self._detect_hash_type(hash_value)

        if hash_type == "unknown":
            self.error(f"Unsupported hash type for: {hash_value}")

        result = self._lookup_hash(hash_value, hash_type)

        # Try to get relationships if it's a SHA1
        relationships = {}
        if hash_type == "sha1" and "error" not in result:
            try:
                relationships["children"] = self._get_children(hash_value, count=10)
                relationships["parents"] = self._get_parents(hash_value, count=10)
            except Exception:
                # Relationships are optional
                pass

        return {
            "hash": hash_value,
            "hash_type": hash_type,
            "lookup_result": result,
            "relationships": relationships,
        }

    def _handle_config_method_call(self, observable: Any, dtype: str) -> AnalyzerReport | None:
        """Handle dynamic method call via config params."""
        env_method = self.get_config("circl.method")
        if not env_method:
            return None

        params: dict[str, Any] = {}
        cfg_params = self.get_config("circl.params")
        if isinstance(cfg_params, Mapping):
            params = dict(cfg_params)
        if cfg_params is not None and not isinstance(cfg_params, Mapping):
            self.error("CIRCL params must be a JSON object.")

        details = {
            "method": env_method,
            "params": params,
            "result": self._call_dynamic(env_method, params),
        }
        taxonomy = self.build_taxonomy(
            level="info",
            namespace="circl",
            predicate="api-call",
            value=env_method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "circl_hashlookup",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def _handle_other_data_type(self, observable: Any, dtype: str) -> AnalyzerReport:
        """Handle dynamic method call via data payload."""
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
            namespace="circl",
            predicate="api-call",
            value=method,
        )
        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "circl_hashlookup",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # 1) Dynamic call via config params
        result = self._handle_config_method_call(observable, dtype)
        if result is not None:
            return result

        # 2) Dynamic call via data payload when dtype == other
        if dtype == "other":
            return self._handle_other_data_type(observable, dtype)

        # 3) Default behavior for hash observables
        if dtype != "hash":
            self.error(f"Unsupported data type for CirclHashlookupAnalyzer: {dtype}.")

        details = self._analyze_hash(str(observable))
        verdict = self._verdict_from_result(details["lookup_result"])

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="circl",
            predicate="reputation",
            value=str(observable),
        )
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "circl_hashlookup",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
