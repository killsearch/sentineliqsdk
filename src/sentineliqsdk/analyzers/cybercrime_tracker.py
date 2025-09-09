"""CyberCrime Tracker Analyzer implementation for SentinelIQ SDK.

Searches cybercrime-tracker.net for possible C2 servers related to an observable.
"""

from __future__ import annotations

from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

_HTTP_OK = 200


class CyberCrimeTrackerAnalyzer(Analyzer):
    """Search cybercrime-tracker.net for possible C2 servers matching the observable.

    Notes
    -----
    - Public web scraping; no API key required. Honor proxies via WorkerConfig.proxy.
    - Paginates using offset/limit until fewer than limit results are returned.
    - Supports textual observables (domain, fqdn, ip, url, other).
    """

    METADATA = ModuleMetadata(
        name="CyberCrime Tracker Analyzer",
        description="Search cybercrime-tracker.net for C2 servers related to the observable",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cybercrime_tracker/",
        version_stage="TESTING",
    )

    _BASE_URL = "https://cybercrime-tracker.net/"

    def _client(self) -> httpx.Client:
        """Build an HTTPX client with configured timeout and headers."""
        timeout = float(self.get_config("cct.timeout", 30.0))
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        }
        return httpx.Client(timeout=timeout, headers=headers)

    def _search_once(
        self, client: httpx.Client, query: str, offset: int, limit: int
    ) -> list[dict[str, Any]]:
        """Perform a single page search and return raw result rows."""
        # cybercrime-tracker does not provide a stable JSON API; emulate the behavior
        # of the original analyzer by calling a known endpoint that returns JSON when possible.
        # If the endpoint changes, we fail with a clear error.
        # Known community wrappers used `/search.json?q=<>&offset=<>&limit=<>` pattern.
        params = {"q": query, "offset": str(offset), "limit": str(limit)}
        try:
            resp = client.get(self._BASE_URL + "search.json", params=params)
        except httpx.HTTPError as e:
            self.error(f"Network error querying cybercrime-tracker: {e}")
        if resp.status_code != _HTTP_OK:
            self.error(f"cybercrime-tracker responded with {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            self.error("Unexpected response from cybercrime-tracker (not JSON)")
        if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
            return data["results"]
        if isinstance(data, list):
            return data
        # Fallback to empty list on unknown shapes
        return []

    def execute(self) -> AnalyzerReport:
        """Execute the search workflow and return an AnalyzerReport."""
        dtype = self.data_type
        if dtype not in ("domain", "fqdn", "ip", "url", "other"):
            self.error("CyberCrimeTrackerAnalyzer expects textual data (domain/fqdn/ip/url/other).")

        observable = str(self.get_data())
        limit = int(self.get_config("cct.limit", 40))
        offset = int(self.get_config("cct.offset", 0))
        max_pages = int(self.get_config("cct.max_pages", 50))  # guard rails

        results: list[dict[str, Any]] = []

        with self._client() as client:
            pages = 0
            while True:
                pages += 1
                if pages > max_pages:
                    break
                new_results = self._search_once(client, observable, offset=offset, limit=limit)
                results.extend(new_results)
                no_more = len(new_results) < limit
                if no_more:
                    break
                offset += limit

        hit_count = len(results)
        predicate = "C2 Search"
        value = f"{hit_count} hits" if hit_count != 1 else "1 hit"

        if hit_count > 0:
            taxonomy = self.build_taxonomy(
                level="malicious", namespace="CCT", predicate=predicate, value=value
            )
            verdict = "malicious"
        else:
            taxonomy = self.build_taxonomy(
                level="info", namespace="CCT", predicate=predicate, value=value
            )
            verdict = "info"

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "cybercrime-tracker.net",
            "results": results,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
