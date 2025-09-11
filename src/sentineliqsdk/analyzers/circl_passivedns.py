"""CIRCL Passive DNS Analyzer: queries the CIRCL Passive DNS service for historical DNS records.

This analyzer provides comprehensive passive DNS lookup capabilities using the CIRCL Passive DNS
API, including domain, IP, and URL queries with support for filtering and pagination.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.circl_passivedns import CirclPassivednsAnalyzer

    input_data = WorkerInput(data_type="domain", data="example.com")
    report = CirclPassivednsAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Requires CIRCL Passive DNS credentials (username/password)
- HTTP proxies honored via `WorkerConfig.proxy`
- Supports filtering by RR type and pagination
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.constants import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    HTTP_UNAUTHORIZED,
    SAFE_RECORD_THRESHOLD,
)
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# HTTP status codes


class CirclPassivednsAnalyzer(Analyzer):
    """Analyzer that queries CIRCL Passive DNS for historical DNS records."""

    METADATA = ModuleMetadata(
        name="CIRCL Passive DNS Analyzer",
        description="Query CIRCL Passive DNS for historical DNS records and relationships",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/circl_passivedns/",
        version_stage="STABLE",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)
        self.base_url = "https://www.circl.lu/pdns/query"

        # Get credentials from config
        username = self.get_secret(
            "circl_passivedns.username", message="CIRCL Passive DNS username required"
        )
        password = self.get_secret(
            "circl_passivedns.password", message="CIRCL Passive DNS password required"
        )

        self.session = httpx.Client(
            auth=(username, password),
            headers={"Accept": "application/x-ndjson"},
            timeout=30.0,
        )

    def __del__(self):
        """Clean up HTTP session."""
        if hasattr(self, "session"):
            self.session.close()

    def _make_request(self, query: str, **kwargs) -> list[dict[str, Any]]:
        """Make HTTP request to CIRCL Passive DNS API."""
        url = f"{self.base_url}/{query}"

        try:
            response = self.session.get(url, **kwargs)
            response.raise_for_status()

            # Parse NDJSON response
            results = []
            for line in response.text.strip().split("\n"):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            return results

        except httpx.HTTPStatusError as e:
            if e.response.status_code == HTTP_UNAUTHORIZED:
                self.error("CIRCL Passive DNS authentication failed. Check credentials.")
            elif e.response.status_code == HTTP_FORBIDDEN:
                self.error("CIRCL Passive DNS access forbidden. Check permissions.")
            elif e.response.status_code == HTTP_NOT_FOUND:
                return []  # No results found
            else:
                self.error(f"CIRCL Passive DNS API request failed: {e}")
        except httpx.RequestError as e:
            self.error(f"CIRCL Passive DNS connection failed: {e}")

    def _clean_datetime_fields(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Clean datetime fields for JSON serialization."""
        clean_results = []

        for result in results:
            clean_result = result.copy()

            # Convert time_first to ISO format
            if clean_result.get("time_first"):
                try:
                    if isinstance(clean_result["time_first"], int | float):
                        # Unix timestamp
                        dt = datetime.fromtimestamp(clean_result["time_first"], tz=UTC)
                        clean_result["time_first"] = dt.isoformat(" ")
                    else:
                        # Already a datetime object
                        clean_result["time_first"] = clean_result["time_first"].isoformat(" ")
                except (ValueError, TypeError):
                    clean_result["time_first"] = str(clean_result["time_first"])

            # Convert time_last to ISO format
            if clean_result.get("time_last"):
                try:
                    if isinstance(clean_result["time_last"], int | float):
                        # Unix timestamp
                        dt = datetime.fromtimestamp(clean_result["time_last"], tz=UTC)
                        clean_result["time_last"] = dt.isoformat(" ")
                    else:
                        # Already a datetime object
                        clean_result["time_last"] = clean_result["time_last"].isoformat(" ")
                except (ValueError, TypeError):
                    clean_result["time_last"] = str(clean_result["time_last"])

            clean_results.append(clean_result)

        return clean_results

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        if not url:
            return ""

        # Remove protocol
        if "://" in url:
            url = url.split("://", 1)[1]

        # Split by path and take first part
        domain = url.split("/")[0]

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        return domain

    def _query_passive_dns(self, query: str, rrtype: str | None = None) -> list[dict[str, Any]]:
        """Query CIRCL Passive DNS with optional RR type filtering."""
        headers = {}

        if rrtype:
            headers["dribble-filter-rrtype"] = rrtype

        results = self._make_request(query, headers=headers)
        return self._clean_datetime_fields(results)

    def _analyze_domain(self, domain: str) -> dict[str, Any]:
        """Analyze a domain using Passive DNS."""
        if "/" in domain:
            self.error("'/' found in the supplied domain. Use the URL datatype instead.")

        results = self._query_passive_dns(domain)

        return {
            "query": domain,
            "query_type": "domain",
            "results": results,
            "result_count": len(results),
        }

    def _analyze_ip(self, ip: str) -> dict[str, Any]:
        """Analyze an IP address using Passive DNS."""
        results = self._query_passive_dns(ip)

        return {
            "query": ip,
            "query_type": "ip",
            "results": results,
            "result_count": len(results),
        }

    def _analyze_url(self, url: str) -> dict[str, Any]:
        """Analyze a URL by extracting domain and querying Passive DNS."""
        domain = self._extract_domain_from_url(url)

        if not domain:
            self.error("Could not extract domain from URL")

        results = self._query_passive_dns(domain)

        return {
            "query": domain,
            "original_url": url,
            "query_type": "url",
            "results": results,
            "result_count": len(results),
        }

    def _verdict_from_results(self, result_count: int) -> TaxonomyLevel:
        """Determine verdict based on result count."""
        if result_count == 0:
            return "info"  # No historical records
        if result_count <= SAFE_RECORD_THRESHOLD:
            return "safe"  # Few records, likely legitimate
        return "suspicious"  # Many records, worth investigating

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # Route to appropriate analysis method
        if dtype == "domain":
            details = self._analyze_domain(str(observable))
        elif dtype == "ip":
            details = self._analyze_ip(str(observable))
        elif dtype == "url":
            details = self._analyze_url(str(observable))
        else:
            self.error(f"Unsupported data type for CirclPassivednsAnalyzer: {dtype}")

        verdict = self._verdict_from_results(details["result_count"])

        # Build taxonomy
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="CIRCL",
            predicate="PassiveDNS",
            value=f"{details['result_count']} records",
        )

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "circl_passivedns",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
