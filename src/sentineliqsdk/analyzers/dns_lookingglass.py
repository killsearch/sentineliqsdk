"""DNS Lookingglass Analyzer: query DNS information via ISC SANS API.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer

    input_data = WorkerInput(data_type="domain", data="example.com")
    report = DnsLookingglassAnalyzer(input_data).execute()

Notes
-----
- No API key required. HTTP proxies are honored via `WorkerConfig.proxy`.
- Extracts IPv4 and IPv6 addresses from DNS responses as artifacts.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

_HTTP_OK = 200


class DnsLookingglassAnalyzer(Analyzer):
    """Analyzer that queries ISC SANS DNS Lookingglass for domain information."""

    METADATA = ModuleMetadata(
        name="DNS Lookingglass Analyzer",
        description="Query DNS information for domains using ISC SANS DNS Lookingglass API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dns_lookingglass/",
        version_stage="TESTING",
    )

    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )

    # Regex patterns for IP extraction
    _IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    _IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|"
        r"\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|"
        r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    )

    def _http_client(self) -> httpx.Client:
        """Create HTTP client with configured timeout and headers."""
        timeout = self.get_config("dns_lookingglass.timeout", 30.0)
        headers = {"User-Agent": self._UA}
        return httpx.Client(timeout=timeout, headers=headers)

    def _query_domain(self, domain: str) -> list[dict[str, Any]]:
        """Query DNS information for a domain via ISC SANS API."""
        url = f"https://isc.sans.edu/api/dnslookup/{domain}?json"

        with self._http_client() as client:
            try:
                resp = client.get(url)
                resp.raise_for_status()

                if resp.status_code == _HTTP_OK:
                    data = resp.json()
                    return data if isinstance(data, list) else []
                return []

            except httpx.HTTPError as e:
                self.error(f"Error querying DNS Lookingglass API: {e}")
            except Exception as e:
                self.error(f"Unexpected error: {e}")

    def _extract_ips(self, data: list[dict[str, Any]]) -> list[str]:
        """Extract IPv4 and IPv6 addresses from DNS response data."""
        ips = set()

        for record in data:
            # Convert record to string for IP extraction
            record_str = str(record)

            # Extract IPv4 addresses
            ipv4_matches = self._IPV4_PATTERN.findall(record_str)
            ips.update(ipv4_matches)

            # Extract IPv6 addresses
            ipv6_matches = self._IPV6_PATTERN.findall(record_str)
            ips.update(ipv6_matches)

            # Also check specific fields if they exist
            if isinstance(record, dict):
                answer = record.get("answer", "")
                if answer:
                    ipv4_in_answer = self._IPV4_PATTERN.findall(str(answer))
                    ipv6_in_answer = self._IPV6_PATTERN.findall(str(answer))
                    ips.update(ipv4_in_answer)
                    ips.update(ipv6_in_answer)

        return list(ips)

    def _get_hit_status(self, results: list[dict[str, Any]]) -> str:
        """Determine hit status based on results count."""
        count = len(results)
        if count == 0:
            return "NXDOMAIN"
        if count >= 1:
            return "DomainExist"
        return "Error"

    def execute(self) -> AnalyzerReport:
        """Execute DNS Lookingglass query and return an AnalyzerReport."""
        dtype = self.data_type
        if dtype not in ("domain", "fqdn"):
            self.error("DnsLookingglassAnalyzer supports only data_type 'domain' or 'fqdn'.")

        domain = str(self.get_data())
        raw_results = self._query_domain(domain)

        # Process results
        results = []
        if raw_results:
            for hit in raw_results:
                result = {}
                try:
                    result["answer"] = hit.get("answer", "")
                    result["status"] = hit.get("status", "")
                    result["country"] = hit.get("country", "")
                    results.append(result)
                except (KeyError, AttributeError):
                    # Skip malformed records
                    continue

        # Extract IP artifacts
        extracted_ips = self._extract_ips(raw_results)
        artifacts = []
        for ip in extracted_ips:
            artifacts.append(self.build_artifact("ip", ip))

        # Determine verdict and taxonomy
        hit_status = self._get_hit_status(results)
        count = len(results)

        taxonomy = self.build_taxonomy(
            level="info", namespace="Lookingglass", predicate=hit_status, value=f"{count} hit(s)"
        )

        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "ISC SANS DNS Lookingglass",
            "data_type": dtype,
            "results": results,
            "hits": hit_status,
            "count": count,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def artifacts(self, raw: Any) -> list:
        """Extract IP artifacts from DNS lookup results."""
        artifacts = []
        if isinstance(raw, dict) and "results" in raw:
            for result in raw["results"]:
                if "answer" in result:
                    ips = self._extract_ips(result["answer"])
                    for ip in ips:
                        artifacts.append(self.build_artifact("ip", ip))

        # Merge with auto-extracted artifacts when enabled
        try:
            auto = super().artifacts(raw)
        except Exception:
            auto = []
        return artifacts + auto

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
