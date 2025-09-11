"""crt.sh Analyzer: enumerate certificates for a domain via crt.sh.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.crtsh import CrtshAnalyzer

    input_data = WorkerInput(data_type="domain", data="example.com")
    report = CrtshAnalyzer(input_data).execute()

Notes
-----
- No API key required. HTTP proxies are honored via `WorkerConfig.proxy`.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

_HTTP_OK = 200


class CrtshAnalyzer(Analyzer):
    """Analyzer that queries crt.sh for certificates of a domain/FQDN."""

    METADATA = ModuleMetadata(
        name="crt.sh Analyzer",
        description="Search certificates for a domain using crt.sh (Certificate Transparency)",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/crtsh/",
        version_stage="TESTING",
    )

    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )

    _DETAIL_SHA1_RE = re.compile(
        r"\<TH\sclass=\"outer\">SHA-1\(Certificate\)\</TH\>\s+\<TD\sclass=\"outer\"\>([^\<]+)\</TD\>",
        re.IGNORECASE,
    )

    def _http_client(self) -> httpx.Client:
        timeout = self.get_config("crtsh.timeout", 30.0)
        headers = {"User-Agent": self._UA}
        return httpx.Client(timeout=timeout, headers=headers)

    def _fetch_json(self, client: httpx.Client, url: str) -> list[dict[str, Any]]:
        resp = client.get(url)
        resp.raise_for_status()
        # crt.sh sometimes concatenates JSON objects without commas
        text = resp.text
        normalized = text.replace("}{", "},{")
        # The output should be a JSON array; ensure brackets
        if not normalized.strip().startswith("["):
            normalized = f"[{normalized}]"
        return httpx.Response(_HTTP_OK, text=normalized).json()

    def _augment_sha1(self, client: httpx.Client, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            cert_id = row.get("min_cert_id") or row.get("id")
            if not cert_id:
                row["sha1"] = ""
                continue
            try:
                detail = client.get(f"https://crt.sh/?q={cert_id}")
                if detail.status_code == _HTTP_OK:
                    m = self._DETAIL_SHA1_RE.search(detail.text)
                    row["sha1"] = m.group(1) if m else ""
                else:
                    row["sha1"] = ""
            except httpx.HTTPError:
                row["sha1"] = ""

    def _search(self, domain: str, wildcard: bool = True) -> list[dict[str, Any]]:
        base = "https://crt.sh/?q={}&output=json"
        with self._http_client() as client:
            try:
                data = self._fetch_json(client, base.format(domain))
            except httpx.HTTPError as e:
                self.error(f"Error retrieving base domain information from crt.sh: {e}")

            if wildcard:
                try:
                    # %25 is percent-encoded '%'
                    data2 = self._fetch_json(client, base.format(f"%25{domain}."))
                    data.extend(data2)
                except httpx.HTTPError:
                    # ignore wildcard failures, keep base results
                    pass

            # Enrich rows with SHA-1 when possible
            self._augment_sha1(client, data)
            return data

    def execute(self) -> AnalyzerReport:
        """Execute a query on crt.sh and return an AnalyzerReport."""
        dtype = self.data_type
        if dtype not in ("domain", "fqdn"):
            self.error("CrtshAnalyzer supports only data_type 'domain' or 'fqdn'.")

        domain = str(self.get_data())
        results = self._search(domain, wildcard=True)

        taxonomy = self.build_taxonomy(
            level="info", namespace="crt.sh", predicate="certificates", value=domain
        )

        full_report = {
            "observable": domain,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "source": "crt.sh",
            "data_type": dtype,
            "certificates": results,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
