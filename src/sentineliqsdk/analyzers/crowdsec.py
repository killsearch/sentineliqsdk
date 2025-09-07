"""CrowdSec CTI Analyzer - Analyzes IP addresses using CrowdSec threat intelligence."""

from __future__ import annotations

import json
from typing import Literal

from sentineliqsdk import Analyzer
from sentineliqsdk.clients.crowdsec import CrowdSecAPIError, CrowdSecClient, CrowdSecRateLimitError
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class CrowdSecAnalyzer(Analyzer):
    """CrowdSec CTI Analyzer.

    Analyzes IP addresses using CrowdSec's threat intelligence API.
    Provides reputation scoring, attack details, behaviors, and CVE information.
    """

    METADATA = ModuleMetadata(
        name="CrowdSec CTI Analyzer",
        description="Analyzes IP addresses using CrowdSec's threat intelligence API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/crowdsec/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        """Execute the CrowdSec analysis.

        Returns
        -------
            AnalyzerReport with threat intelligence data
        """
        observable = self.get_data()

        # Get API key from config
        api_key = self.get_secret("crowdsec.api_key", message="Missing CrowdSec API key")

        # Initialize client
        try:
            client = CrowdSecClient(api_key)
        except Exception as e:
            self.error(f"Failed to initialize CrowdSec client: {e}")

        # Get threat intelligence data
        try:
            raw_data = client.get_ip_summary(observable)
        except CrowdSecRateLimitError as e:
            self.error(f"CrowdSec rate limit exceeded: {e}")
        except CrowdSecAPIError as e:
            self.error(f"CrowdSec API error: {e}")
        except Exception as e:
            self.error(f"Failed to get CrowdSec data: {e}")

        # Build taxonomy entries
        taxonomies = self._build_taxonomies(raw_data)

        # Build full report
        full_report = {
            "observable": observable,
            "raw_data": raw_data,
            "taxonomy": [tax.to_dict() for tax in taxonomies],
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def _build_taxonomies(self, raw_data: dict) -> list:
        """Build taxonomy entries from raw CrowdSec data.

        Args:
            raw_data: Raw data from CrowdSec API

        Returns
        -------
            List of taxonomy entries
        """
        taxonomies = []
        namespace = "CrowdSec"

        # Reputation
        if "reputation" in raw_data:
            reputation = raw_data["reputation"]
            level = self._get_reputation_level(reputation)
            taxonomies.append(self.build_taxonomy(level, namespace, "Reputation", reputation))

        # AS Name
        if "as_name" in raw_data:
            taxonomies.append(self.build_taxonomy("info", namespace, "ASN", raw_data["as_name"]))

        # IP Range Score
        if "ip_range_score" in raw_data:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Score", str(raw_data["ip_range_score"]))
            )

        # Last Seen
        if "history" in raw_data and "last_seen" in raw_data["history"]:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "LastSeen", raw_data["history"]["last_seen"])
            )

        # Attack Details
        if "attack_details" in raw_data:
            attack_taxonomies = [
                self.build_taxonomy("suspicious", namespace, "Attack", attack["name"])
                for attack in raw_data["attack_details"]
                if "name" in attack
            ]
            taxonomies.extend(attack_taxonomies)

        # Behaviors
        if "behaviors" in raw_data:
            behavior_taxonomies = [
                self.build_taxonomy("suspicious", namespace, "Behavior", behavior["name"])
                for behavior in raw_data["behaviors"]
                if "name" in behavior
            ]
            taxonomies.extend(behavior_taxonomies)

        # MITRE Techniques
        if "mitre_techniques" in raw_data:
            mitre_taxonomies = [
                self.build_taxonomy("suspicious", namespace, "Mitre", mitre["name"])
                for mitre in raw_data["mitre_techniques"]
                if "name" in mitre
            ]
            taxonomies.extend(mitre_taxonomies)

        # CVEs
        if "cves" in raw_data:
            cve_taxonomies = [
                self.build_taxonomy("suspicious", namespace, "CVE", cve) for cve in raw_data["cves"]
            ]
            taxonomies.extend(cve_taxonomies)

        # Not Found (when no threat data is available)
        if (
            "reputation" not in raw_data
            and "attack_details" not in raw_data
            and "behaviors" not in raw_data
        ):
            taxonomies.append(self.build_taxonomy("safe", namespace, "Threat", "Not found"))

        return taxonomies

    def _get_reputation_level(
        self, reputation: str
    ) -> Literal["info", "safe", "suspicious", "malicious"]:
        """Convert CrowdSec reputation to taxonomy level.

        Args:
            reputation: CrowdSec reputation value

        Returns
        -------
            Taxonomy level (info, safe, suspicious, malicious)
        """
        reputation_lower = reputation.lower()

        if reputation_lower == "malicious":
            return "malicious"
        if reputation_lower == "suspicious":
            return "suspicious"
        if reputation_lower == "safe":
            return "safe"
        return "info"

    def run(self) -> None:
        """Run the analyzer and print the report."""
        report = self.execute()
        # Print the report in JSON format to stdout
        print(json.dumps(report.full_report, ensure_ascii=False))
