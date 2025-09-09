"""Cluster25 Analyzer - Analyzes indicators using Cluster25 threat intelligence platform."""

from __future__ import annotations

import json
from typing import Any, Literal

from sentineliqsdk import Analyzer
from sentineliqsdk.clients.cluster25 import Cluster25Client
from sentineliqsdk.constants import SAFE_SCORE_THRESHOLD, SUSPICIOUS_SCORE_THRESHOLD
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

# Score thresholds for taxonomy classification



class Cluster25Analyzer(Analyzer):
    """
    Cluster25 Analyzer - Analyzes indicators using Cluster25 threat intelligence platform.

    This analyzer queries the Cluster25 API to get threat intelligence data for various
    indicators including IPs, domains, URLs, and other observables.
    """

    METADATA = ModuleMetadata(
        name="Cluster25 Analyzer",
        description="Analyzes indicators using Cluster25 threat intelligence platform",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cluster25/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)

        # Get credentials from WorkerConfig.secrets
        self.client_id = self.get_secret(
            "cluster25.client_id", message="Cluster25 client ID required"
        )
        self.client_key = self.get_secret(
            "cluster25.client_key", message="Cluster25 client key required"
        )

        # Get configuration from WorkerConfig
        params = dict(self._input.config.params)
        self.base_url = params.get("cluster25.base_url", "https://api.cluster25.com")
        self.timeout = params.get("cluster25.timeout", 30)
        self.max_retries = params.get("cluster25.max_retries", 3)

        # Initialize API client
        self.api_client = Cluster25Client(
            client_id=self.client_id,
            client_key=self.client_key,
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

    def execute(self) -> AnalyzerReport:
        """Execute the Cluster25 analysis."""
        observable = self.get_data()

        try:
            # Investigate the observable
            indicator_data = self.api_client.investigate(observable)

            if "error" in indicator_data:
                return self._create_error_report(observable, indicator_data["error"])

            # Build taxonomy based on the response
            taxonomies = self._build_taxonomies(indicator_data)

            # Create full report
            full_report = {
                "observable": observable,
                "data_type": self.data_type,
                "indicator_data": indicator_data,
                "taxonomy": [tax.to_dict() for tax in taxonomies],
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

        except Exception as e:
            return self._create_error_report(observable, str(e))

    def _build_taxonomies(self, indicator_data: dict[str, Any]) -> list:
        """Build taxonomy entries from indicator data."""
        taxonomies = []
        namespace = "C25"
        level: Literal["info", "safe", "suspicious", "malicious"] = "info"

        # Add indicator taxonomy
        if indicator_data.get("indicator"):
            taxonomies.append(
                self.build_taxonomy(
                    level, namespace, "Indicator", str(indicator_data.get("indicator"))
                )
            )

        # Add indicator type taxonomy
        if indicator_data.get("indicator_type"):
            taxonomies.append(
                self.build_taxonomy(
                    level, namespace, "Indicator Type", str(indicator_data.get("indicator_type"))
                )
            )

        # Add score taxonomy with appropriate level
        if indicator_data.get("score") is not None:
            score = indicator_data.get("score")
            if isinstance(score, int | float) and score < SAFE_SCORE_THRESHOLD:
                level = "safe"
            elif (
                isinstance(score, int | float)
                and SAFE_SCORE_THRESHOLD <= score < SUSPICIOUS_SCORE_THRESHOLD
            ):
                level = "suspicious"
            elif isinstance(score, int | float) and score >= SUSPICIOUS_SCORE_THRESHOLD:
                level = "malicious"

            taxonomies.append(self.build_taxonomy(level, namespace, "Score", str(score)))

        # If no taxonomies were created, add a default one
        if not taxonomies:
            taxonomies.append(self.build_taxonomy(level, namespace, "Threat", "Not found"))

        return taxonomies

    def _create_error_report(self, observable: str, error_message: str) -> AnalyzerReport:
        """Create an error report."""
        full_report = {
            "observable": observable,
            "data_type": self.data_type,
            "error": error_message,
            "taxonomy": [self.build_taxonomy("info", "C25", "Error", error_message).to_dict()],
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run the analyzer and print the report."""
        report = self.execute()
        # Print the report in JSON format to stdout
        print(json.dumps(report.full_report, ensure_ascii=False))
        return report
