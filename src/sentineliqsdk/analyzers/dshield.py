"""DShield Analyzer: check IP reputation via SANS Internet Storm Center DShield API.

Features:
- Accepts `data_type == "ip"` and queries the DShield API.
- Analyzes attack counts, threat feeds, and risk levels.
- Provides taxonomy based on risk assessment and threat intelligence.
- Extracts artifacts like AS information and abuse contacts.

Configuration:
- No API key required (public API).
- Optional timeout via `WorkerConfig.params['dshield']['timeout']` (default 30).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.dshield import DShieldAnalyzer

    inp = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(),
    )
    report = DShieldAnalyzer(inp).execute()
"""

from __future__ import annotations

import json
import math
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.constants import HTTP_OK_MAX, HTTP_OK_MIN
from sentineliqsdk.models import AnalyzerReport, Artifact, ModuleMetadata, TaxonomyLevel

# Risk level thresholds
_SAFE_RISK_THRESHOLD = 1
_SUSPICIOUS_RISK_THRESHOLD = 6


class DShieldAnalyzer(Analyzer):
    """Analyzer that queries SANS DShield for IP reputation and threat intelligence."""

    METADATA = ModuleMetadata(
        name="DShield Analyzer",
        description="Consulta reputação de IPs no SANS Internet Storm Center DShield",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dshield/",
        version_stage="TESTING",
    )

    def _timeout(self) -> int:
        """Get timeout configuration."""
        try:
            raw = self.get_config("dshield.timeout", 30)
            return int(raw) if raw is not None else 30
        except Exception:
            return 30

    def _fetch_ip_info(self, ip: str) -> dict[str, Any]:
        """Fetch IP information from DShield API."""
        url = f"https://isc.sans.edu/api/ip/{ip}?json"

        try:
            with httpx.Client(timeout=float(self._timeout())) as client:
                resp = client.get(url)
        except Exception as exc:
            self.error(f"HTTP call to DShield failed: {exc}")

        if not (HTTP_OK_MIN <= resp.status_code < HTTP_OK_MAX):
            body = resp.text
            self.error(f"Unable to query DShield API (status {resp.status_code})\n{body}")

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            self.error(f"Invalid JSON response from DShield: {exc}")

    def _calculate_risk_level(self, attacks: int, threat_feeds_count: int) -> tuple[int, str]:
        """Calculate risk level based on attacks and threat feeds."""
        max_risk = 0
        max_risk_threshold = 10

        if attacks > 0:
            max_risk = round(min(math.log10(attacks) * 2, max_risk_threshold))

        # Add threat feeds count to increase detection rate
        total_risk = max_risk + threat_feeds_count

        if total_risk <= _SAFE_RISK_THRESHOLD:
            return total_risk, "safe"
        if total_risk <= _SUSPICIOUS_RISK_THRESHOLD:
            return total_risk, "suspicious"
        return total_risk, "malicious"

    def _process_threat_feeds(self, info: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
        """Process threat feeds information."""
        threat_feeds_count = 0
        threat_feeds = []

        if info.get("threatfeeds"):
            try:
                threat_feeds = json.loads(json.dumps(info["threatfeeds"]))
                threat_feeds_count = len(threat_feeds)
            except (json.JSONDecodeError, TypeError):
                threat_feeds = []
                threat_feeds_count = 0

        return threat_feeds_count, threat_feeds

    def _process_basic_info(self, info: dict[str, Any], observable: str) -> dict[str, Any]:
        """Process basic IP information from DShield response."""
        return {
            "ip": info.get("number", str(observable)),
            "count": info.get("count", 0) if isinstance(info.get("count"), int) else 0,
            "attacks": info.get("attacks", 0) if isinstance(info.get("attacks"), int) else 0,
            "lastseen": info.get("maxdate", "None")
            if isinstance(info.get("maxdate"), str)
            else "None",
            "firstseen": info.get("mindate", "None")
            if isinstance(info.get("mindate"), str)
            else "None",
            "updated": info.get("updated", "None")
            if isinstance(info.get("updated"), str)
            else "None",
            "comment": info.get("comment", "None")
            if isinstance(info.get("comment"), str)
            else "None",
        }

    def _process_as_info(self, info: dict[str, Any], results: dict[str, Any]) -> None:
        """Process AS (Autonomous System) information."""
        if "asabusecontact" in info:
            results["asabusecontact"] = (
                info["asabusecontact"] if isinstance(info["asabusecontact"], str) else "Unknown"
            )
        for field in ["as", "asname", "ascountry", "assize", "network"]:
            if field in info:
                results[field] = info[field]

    def _build_taxonomies(
        self, results: dict[str, Any], threat_feeds_count: int, reputation: str, max_risk: int
    ) -> list[dict[str, Any]]:
        """Build taxonomy list for the analysis report."""
        taxonomies = []
        level: TaxonomyLevel = reputation  # type: ignore

        # Main reputation taxonomy
        score_value = f"{results['count']} count(s) / {results['attacks']} attack(s) / {threat_feeds_count} threatfeed(s)"
        taxonomies.append(self.build_taxonomy(level, "dshield", "score", score_value).to_dict())

        # Risk level taxonomy
        taxonomies.append(
            self.build_taxonomy(level, "dshield", "risk-level", str(max_risk)).to_dict()
        )

        # Attack count taxonomy if attacks > 0
        if results["attacks"] > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", "dshield", "attacks", str(results["attacks"])
                ).to_dict()
            )

        # Threat feeds taxonomy if present
        if threat_feeds_count > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", "dshield", "threat-feeds", str(threat_feeds_count)
                ).to_dict()
            )

        return taxonomies

    def execute(self) -> AnalyzerReport:
        """Execute DShield analysis."""
        dtype = self.data_type
        observable = self.get_data()

        if dtype != "ip":
            self.error(f"Unsupported data type for DShieldAnalyzer: {dtype}")

        raw_data = self._fetch_ip_info(str(observable))

        # Check if we have valid results
        if dtype not in raw_data:
            self.error("No data found for the provided IP")

        info = raw_data[dtype]

        # Process basic information
        results = self._process_basic_info(info, str(observable))

        # Process AS information
        self._process_as_info(info, results)

        # Process threat feeds
        threat_feeds_count, threat_feeds = self._process_threat_feeds(info)
        results["threatfeedscount"] = threat_feeds_count
        results["threatfeeds"] = threat_feeds

        # Calculate risk level
        max_risk, reputation = self._calculate_risk_level(results["attacks"], threat_feeds_count)
        results["maxrisk"] = max_risk
        results["reputation"] = reputation

        # Build taxonomies
        taxonomies = self._build_taxonomies(results, threat_feeds_count, reputation, max_risk)

        full_report = {
            "observable": observable,
            "verdict": reputation,
            "taxonomy": taxonomies,
            "source": "dshield",
            "data_type": dtype,
            "values": results,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def artifacts(self, raw: Any) -> list[Artifact]:
        """Extract artifacts from DShield data."""
        artifacts: list[Artifact] = []
        values = (raw or {}).get("values") if isinstance(raw, dict) else None

        if isinstance(values, dict):
            # Extract AS number as artifact
            if values.get("as"):
                artifacts.append(self.build_artifact("asn", str(values["as"]), tags=["DShield"]))

            # Extract abuse contact as artifact
            if "asabusecontact" in values and values["asabusecontact"] != "Unknown":
                artifacts.append(
                    self.build_artifact("mail", str(values["asabusecontact"]), tags=["DShield"])
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
