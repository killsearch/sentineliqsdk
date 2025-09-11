"""DNSdumpster Analyzer: query DNS information via DNSdumpster.com.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.dnsdumpster import DnsdumpsterAnalyzer

    input_data = WorkerInput(data_type="domain", data="example.com")
    report = DnsdumpsterAnalyzer(input_data).execute()

Notes
-----
- No API key required. HTTP proxies are honored via `WorkerConfig.proxy`.
- Extracts IPv4, IPv6 addresses, domains and URLs from DNS responses as artifacts.
- Performs web scraping of DNSdumpster.com to gather DNS reconnaissance data.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, Literal, cast

import httpx
from bs4 import BeautifulSoup

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, Artifact, ModuleMetadata

_HTTP_OK = 200
_MIN_TABLES_REQUIRED = 4
_MIN_CELLS_REQUIRED = 3


class DnsdumpsterAnalyzer(Analyzer):
    """Analyzer that queries DNSdumpster.com for domain reconnaissance information."""

    METADATA = ModuleMetadata(
        name="DNSdumpster Analyzer",
        description="Query DNS reconnaissance information for domains using DNSdumpster.com",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dnsdumpster/",
        version_stage="TESTING",
    )

    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/95.0.4638.69 Safari/537.36"
    )

    # Regex patterns for IP extraction
    _IPV4_PATTERN = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")

    def _http_client(self) -> httpx.Client:
        """Create HTTP client with configured timeout and headers."""
        timeout = self.get_config("dnsdumpster.timeout", 30.0)
        headers = {"User-Agent": self._UA}
        return httpx.Client(timeout=timeout, headers=headers, follow_redirects=True)

    def _get_csrf_token(self, client: httpx.Client) -> tuple[str, dict[str, str]]:
        """Get CSRF token from DNSdumpster homepage."""
        try:
            resp = client.get("https://dnsdumpster.com")
            resp.raise_for_status()

            soup = BeautifulSoup(resp.content, "html.parser")
            csrf_input = soup.find("input", attrs={"name": "csrfmiddlewaretoken"})

            if not csrf_input:
                self.error("Could not find CSRF token on DNSdumpster homepage")
                raise RuntimeError("Could not find CSRF token on DNSdumpster homepage")

            csrf_token = (
                csrf_input.get("value", "") if csrf_input and hasattr(csrf_input, "get") else ""
            )
            cookies = {"csrftoken": csrf_token}

            return csrf_token, cookies

        except httpx.HTTPError as e:
            self.error(f"Error getting CSRF token from DNSdumpster: {e}")
            raise RuntimeError(f"Error getting CSRF token from DNSdumpster: {e}") from e

    def _query_domain(self, domain: str) -> dict[str, Any]:
        """Query DNS information for a domain via DNSdumpster.com."""
        with self._http_client() as client:
            # Get CSRF token
            csrf_token, cookies = self._get_csrf_token(client)
            if not csrf_token:
                return {}

            # Prepare request data
            headers = {
                "Referer": "https://dnsdumpster.com",
                "User-Agent": self._UA,
            }

            data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain, "user": "free"}

            try:
                resp = client.post(
                    "https://dnsdumpster.com", cookies=cookies, data=data, headers=headers
                )

                if resp.status_code != _HTTP_OK:
                    self.error(f"Unexpected status code from DNSdumpster: {resp.status_code}")
                    raise RuntimeError(
                        f"Unexpected status code from DNSdumpster: {resp.status_code}"
                    )

                content = resp.content.decode("utf-8")
                if "There was an error getting results" in content:
                    self.error("DNSdumpster reported an error getting results")
                    raise RuntimeError("DNSdumpster reported an error getting results")

                return self._parse_response(content, domain)

            except httpx.HTTPError as e:
                self.error(f"Error querying DNSdumpster API: {e}")
                raise RuntimeError(f"Error querying DNSdumpster API: {e}") from e
            except Exception as e:
                self.error(f"Unexpected error: {e}")
                raise RuntimeError(f"Unexpected error: {e}") from e

    def _parse_response(self, content: str, domain: str) -> dict[str, Any]:
        """Parse DNSdumpster HTML response."""
        soup = BeautifulSoup(content, "html.parser")
        tables = soup.find_all("table")

        if len(tables) < _MIN_TABLES_REQUIRED:
            return {"domain": domain, "dns_records": {}}

        result = {
            "domain": domain,
            "dns_records": {
                "dns": self._retrieve_results(tables[0]),
                "mx": self._retrieve_results(tables[1]),
                "txt": self._retrieve_txt_record(tables[2]),
                "host": self._retrieve_results(tables[3]),
                "map_url": f"https://dnsdumpster.com/static/map/{domain}.png",
            },
        }

        return result

    def _retrieve_txt_record(self, table) -> list[str]:
        """Extract TXT records from table."""
        results = []
        for td in table.find_all("td"):
            text = td.get_text(strip=True)
            if text:
                results.append(text)
        return results

    def _retrieve_results(self, table) -> list[dict[str, Any]]:
        """Extract DNS records from table."""
        results = []
        rows = table.find_all("tr")

        for row in rows:
            cells = row.find_all("td")
            if len(cells) < _MIN_CELLS_REQUIRED:
                continue

            try:
                # Extract IP address
                ip_matches = self._IPV4_PATTERN.findall(cells[1].get_text())
                ip = ip_matches[0] if ip_matches else ""

                # Extract domain
                domain_cell = str(cells[0])
                if "<br/>" in domain_cell:
                    domain = domain_cell.split("<br/>")[0].split(">")[1].split("<")[0]
                else:
                    domain = cells[0].get_text(strip=True)

                # Extract header info
                header_text = cells[0].get_text()
                header = " ".join(header_text.replace("\n", "").split(" ")[1:])

                # Extract reverse DNS
                reverse_dns_span = cells[1].find("span")
                reverse_dns = reverse_dns_span.get_text(strip=True) if reverse_dns_span else ""

                # Extract additional info
                additional_info = cells[2].get_text(strip=True)
                country_span = cells[2].find("span")
                country = country_span.get_text(strip=True) if country_span else ""

                # Parse AS and provider
                info_parts = additional_info.split(" ")
                autonomous_system = info_parts[0] if info_parts else ""
                provider = " ".join(info_parts[1:]).replace(country, "").strip()

                record = {
                    "domain": domain,
                    "ip": ip,
                    "reverse_dns": reverse_dns,
                    "as": autonomous_system,
                    "provider": provider,
                    "country": country,
                    "header": header,
                }

                results.append(record)

            except Exception:
                # Skip malformed records
                continue

        return results

    def _extract_artifacts_from_records(
        self, records: list, seen: set, artifacts: list[Artifact]
    ) -> None:
        """Extract artifacts from DNS records."""
        for record in records:
            if isinstance(record, dict):
                # Extract IP addresses
                ip = record.get("ip", "")
                if ip and ip not in seen:
                    artifacts.append(self.build_artifact("ip", ip))
                    seen.add(ip)

                # Extract domains
                domain = record.get("domain", "")
                if domain and domain not in seen:
                    artifacts.append(self.build_artifact("domain", domain))
                    seen.add(domain)

    def _extract_artifacts_from_txt(
        self, txt_records: list, seen: set, artifacts: list[Artifact]
    ) -> None:
        """Extract artifacts from TXT records."""
        url_pattern = re.compile(r"https?://[^\s]+")
        for txt in txt_records:
            urls = url_pattern.findall(str(txt))
            for url in urls:
                if url not in seen:
                    artifacts.append(self.build_artifact("url", url))
                    seen.add(url)

    def _extract_artifacts(self, data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract IP addresses, domains and URLs as artifacts."""
        artifacts: list[Artifact] = []
        seen: set[str] = set()

        if "dns_records" not in data:
            return []

        dns_records = data["dns_records"]

        # Extract from all record types
        for record_type in ["dns", "mx", "host"]:
            records = dns_records.get(record_type, [])
            if isinstance(records, list):
                self._extract_artifacts_from_records(records, seen, artifacts)

        # Extract from TXT records
        txt_records = dns_records.get("txt", [])
        self._extract_artifacts_from_txt(txt_records, seen, artifacts)

        return [asdict(artifact) for artifact in artifacts]

    def execute(self) -> AnalyzerReport:
        """Execute DNSdumpster query and return an AnalyzerReport."""
        dtype = self.data_type
        if dtype not in ("domain", "fqdn"):
            self.error("DnsdumpsterAnalyzer supports only data_type 'domain' or 'fqdn'.")

        domain = str(self.get_data())
        raw_results = self._query_domain(domain)

        # Extract artifacts
        artifacts = self._extract_artifacts(raw_results)

        # Determine verdict and taxonomy
        dns_records = raw_results.get("dns_records", {})
        total_records = 0

        for record_type in ["dns", "mx", "host"]:
            records = dns_records.get(record_type, [])
            if isinstance(records, list):
                total_records += len(records)

        # Add TXT records count
        txt_records = dns_records.get("txt", [])
        if isinstance(txt_records, list):
            total_records += len(txt_records)

        if total_records > 0:
            level_val = cast(Literal["info", "safe", "suspicious", "malicious"], "info")
            predicate = "Records Found"
            value = f"{total_records} record(s)"
        else:
            level_val = cast(Literal["info", "safe", "suspicious", "malicious"], "info")
            predicate = "No Records"
            value = "0 records"

        taxonomy = self.build_taxonomy(
            level=level_val, namespace="DNSdumpster", predicate=predicate, value=value
        )

        full_report = {
            "observable": domain,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "DNSdumpster.com",
            "data_type": dtype,
            "results": raw_results,
            "total_records": total_records,
            "artifacts": artifacts,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def artifacts(self, raw: Any) -> list:
        """Extract artifacts from DNSdumpster results."""
        artifacts = []
        if isinstance(raw, dict) and "results" in raw:
            artifacts = self._extract_artifacts(raw["results"])

        # Merge with auto-extracted artifacts when enabled
        try:
            auto = super().artifacts(raw)
        except Exception:
            auto = []
        return artifacts + auto

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
