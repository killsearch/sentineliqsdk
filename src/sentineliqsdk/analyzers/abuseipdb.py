"""AbuseIPDB Analyzer: check IP reputation via AbuseIPDB v2 API.

Features:
- Accepts `data_type == "ip"` and queries the `check` endpoint.
- Summarizes whitelist/TOR/usage type and confidence score into taxonomy.
- Adds convenience aggregates: reporting countries, category counts, and freshness.

Configuration (dataclasses only):
- API key via `WorkerConfig.secrets['abuseipdb']['api_key']`.
- Optional days via `WorkerConfig.params['abuseipdb']['days']` (default 30).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.abuseipdb import AbuseIPDBAnalyzer

    inp = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(secrets={"abuseipdb": {"api_key": "YOUR_KEY"}}),
    )
    report = AbuseIPDBAnalyzer(inp).execute()
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.constants import HTTP_OK_MAX, HTTP_OK_MIN, MALICIOUS_THRESHOLD
from sentineliqsdk.models import AnalyzerReport, Artifact, ModuleMetadata, TaxonomyLevel


def _category_name(category_number: int | str) -> str:
    mapping = {
        "1": "DNS Compromise",
        "2": "DNS Poisoning",
        "3": "Fraud Orders",
        "4": "DDOS Attack",
        "5": "FTP Brute-Force",
        "6": "Ping of Death",
        "7": "Phishing",
        "8": "Fraud VOIP",
        "9": "Open Proxy",
        "10": "Web Spam",
        "11": "Email Spam",
        "12": "Blog Spam",
        "13": "VPN IP",
        "14": "Port Scan",
        "15": "Hacking",
        "16": "SQL Injection",
        "17": "Spoofing",
        "18": "Brute Force",
        "19": "Bad Web Bot",
        "20": "Exploited Host",
        "21": "Web App Attack",
        "22": "SSH",
        "23": "IoT Targeted",
    }
    return mapping.get(str(category_number), "Unknown Category")


class AbuseIPDBAnalyzer(Analyzer):
    """Analyzer that queries AbuseIPDB for IP reputation and reports taxonomy/artifacts."""

    METADATA = ModuleMetadata(
        name="AbuseIPDB Analyzer",
        description="Consulta reputação de IPs na AbuseIPDB (API v2)",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/abuseipdb/",
        version_stage="TESTING",
    )

    def _api_key(self) -> str:
        key = self.get_secret("abuseipdb.api_key")
        if not key:
            self.error("Missing AbuseIPDB API key (set config.secrets['abuseipdb']['api_key'])")
        return str(key)

    def _days(self) -> int:
        try:
            raw = self.get_config("abuseipdb.days", 30)
            return int(raw) if raw is not None else 30
        except Exception:
            return 30

    def _fetch(self, ip: str) -> list[dict[str, Any]]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self._api_key(),
        }
        params: dict[str, str | int] = {
            "ipAddress": ip,
            "maxAgeInDays": str(self._days()),
            "verbose": "True",
        }
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:  # pragma: no cover - network dependent
            self.error(f"HTTP call to AbuseIPDB failed: {exc}")

        if not (HTTP_OK_MIN <= resp.status_code < HTTP_OK_MAX):
            body = resp.text
            self.error(f"Unable to query AbuseIPDB API (status {resp.status_code})\n{body}")

        payload = resp.json()
        # Normalize to a list, even if API returns a dict
        return payload if isinstance(payload, list) else [payload]

    @staticmethod
    def _process_categories(reports: list[dict[str, Any]]) -> tuple[list[str], None]:
        """Process categories for all reports and return consolidated list."""
        categories_strings: list[str] = []
        for item in reports:
            out = []
            for c in item.get("categories", []) or []:
                name = _category_name(c)
                out.append(name)
                if name not in categories_strings:
                    categories_strings.append(name)
            item["categories_strings"] = out
        return categories_strings, None

    @staticmethod
    def _process_reporting_countries(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process reporter geography and return top 6 countries."""
        cc_counts: Counter[tuple[str, str]] = Counter()
        for r in reports:
            code = (r.get("reporterCountryCode") or "??").upper()
            name = r.get("reporterCountryName") or code
            cc_counts[(code, name)] += 1
        return [
            {"code": code, "name": name, "count": cnt}
            for (code, name), cnt in cc_counts.most_common(6)
        ]

    @staticmethod
    def _process_category_frequency(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process category frequency and return top 6 categories."""
        cat_counts: Counter[str] = Counter()
        for r in reports:
            for c in r.get("categories_strings") or []:
                cat_counts[c] += 1
        return [{"category": k, "count": v} for k, v in cat_counts.most_common(6)]

    @staticmethod
    def _process_freshness(reports: list[dict[str, Any]]) -> dict[str, int]:
        """Process freshness windows for reports."""

        def _to_dt(x: Any) -> datetime | None:
            try:
                return datetime.fromisoformat(str(x))
            except Exception:
                return None

        now = datetime.now(UTC)
        last_24h = 0
        last_7d = 0
        for r in reports:
            dt = _to_dt(r.get("reportedAt"))
            if not dt:
                continue
            delta = (now - dt).total_seconds()
            if delta <= 24 * 3600:
                last_24h += 1
            if delta <= 7 * 24 * 3600:
                last_7d += 1
        return {"last24h": last_24h, "last7d": last_7d}

    @classmethod
    def _compute_enrichments(cls, entry: dict[str, Any]) -> None:
        """Compute enrichments for an AbuseIPDB entry."""
        data = entry.get("data") or {}
        reports = data.get("reports") or []

        # Process categories
        categories_strings = cls._process_categories(reports)
        entry["categories_strings"] = categories_strings

        # Process reporting countries
        entry["reporting_countries"] = cls._process_reporting_countries(reports)

        # Process category frequency
        entry["category_counts"] = cls._process_category_frequency(reports)

        # Process freshness
        entry["freshness"] = cls._process_freshness(reports)

    def execute(self) -> AnalyzerReport:
        """Execute the AbuseIPDB analysis."""
        dtype = self.data_type
        observable = self.get_data()
        if dtype != "ip":
            self.error(f"Unsupported data type for AbuseIPDBAnalyzer: {dtype}")

        results = self._fetch(str(observable))
        for entry in results:
            if isinstance(entry, dict) and "data" in entry:
                self._compute_enrichments(entry)

        # Taxonomy heuristic from the primary item
        taxonomies = []
        primary = results[0].get("data", {}) if results else {}
        is_whitelisted = bool(primary.get("isWhitelisted") or False)

        if is_whitelisted:
            taxonomies.append(
                self.build_taxonomy("info", "abuseipdb", "is-whitelist", "True").to_dict()
            )
        if primary.get("isTor"):
            taxonomies.append(self.build_taxonomy("info", "abuseipdb", "is-tor", "True").to_dict())
        if "usageType" in primary:
            taxonomies.append(
                self.build_taxonomy(
                    "info", "abuseipdb", "usage-type", str(primary["usageType"])
                ).to_dict()
            )
        score = int(primary.get("abuseConfidenceScore") or 0)
        level: TaxonomyLevel = (
            "malicious" if score >= MALICIOUS_THRESHOLD else ("suspicious" if score > 0 else "safe")
        )
        taxonomies.append(
            self.build_taxonomy(level, "abuseipdb", "abuse-confidence-score", str(score)).to_dict()
        )
        total_reports = int(primary.get("totalReports") or 0)
        if total_reports > 0:
            lvl: TaxonomyLevel = "info" if is_whitelisted else "malicious"
            taxonomies.append(
                self.build_taxonomy(lvl, "abuseipdb", "records", str(total_reports)).to_dict()
            )
        else:
            taxonomies.append(self.build_taxonomy("safe", "abuseipdb", "records", "0").to_dict())

        full_report = {
            "observable": observable,
            "verdict": level,
            "taxonomy": taxonomies,
            "source": "abuseipdb",
            "data_type": dtype,
            "values": results,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def artifacts(self, raw: Any) -> list:
        """Extract artifacts from AbuseIPDB data."""
        # Custom curated artifacts from AbuseIPDB fields + auto-extract when enabled
        artifacts: list[Artifact] = []
        values = (raw or {}).get("values") if isinstance(raw, dict) else None
        if isinstance(values, list):
            domains_out: set[str] = set()
            hostnames_out: set[str] = set()
            for entry in values:
                data = (entry or {}).get("data") or {}
                base = (data.get("domain") or "").strip().rstrip(".").lower()
                if base:
                    domains_out.add(base)
                for hostname in data.get("hostnames") or []:
                    clean_hostname = (hostname or "").strip().rstrip(".").lower()
                    if clean_hostname:
                        hostnames_out.add(clean_hostname)
            artifacts.extend(
                self.build_artifact("domain", d, tags=["AbuseIPDB"]) for d in sorted(domains_out)
            )
            artifacts.extend(
                self.build_artifact("fqdn", hostname, tags=["AbuseIPDB"])
                for hostname in sorted(hostnames_out)
            )

        # Merge with auto-extracted artifacts when enabled
        try:
            auto = super().artifacts(raw)
        except Exception:
            auto = []
        return artifacts + auto

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
