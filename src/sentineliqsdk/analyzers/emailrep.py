"""EmailRep Analyzer: check email reputation via EmailRep API.

Features:
- Accepts `data_type == "mail"` and queries the EmailRep API.
- Summarizes suspicious status and references count into taxonomy.
- Provides detailed reputation information for email addresses.

Configuration (dataclasses only):
- API key via `WorkerConfig.secrets['emailrep']['api_key']` (optional for basic queries).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.emailrep import EmailRepAnalyzer

    inp = WorkerInput(
        data_type="mail",
        data="test@example.com",
        config=WorkerConfig(secrets={"emailrep": {"api_key": "YOUR_KEY"}}),
    )
    report = EmailRepAnalyzer(inp).execute()
"""

from __future__ import annotations

from typing import Any

from emailrep import EmailRep

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel


class EmailRepAnalyzer(Analyzer):
    """Analyzer that queries EmailRep for email reputation and reports taxonomy."""

    METADATA = ModuleMetadata(
        name="EmailRep Analyzer",
        description="Consulta reputação de emails via EmailRep API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/emailrep/",
        version_stage="TESTING",
    )

    def _api_key(self) -> str | None:
        """Get EmailRep API key from secrets (optional for basic queries)."""
        return self.get_secret("emailrep.api_key")

    def _fetch(self, email: str) -> dict[str, Any]:
        """Fetch email reputation from EmailRep API."""
        try:
            api_key = self._api_key()
            emailrep_client = EmailRep(api_key)
            result = emailrep_client.query(email)
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            self.error(f"Failed to query EmailRep API: {exc}")

    def execute(self) -> AnalyzerReport:
        """Execute the EmailRep analysis."""
        dtype = self.data_type
        observable = self.get_data()

        if dtype != "mail":
            raise ValueError(f"EmailRep only supports mail data type, got: {dtype}")

        result = self._fetch(str(observable))

        # Build taxonomy based on EmailRep response
        taxonomies = []

        # Determine threat level based on EmailRep response
        suspicious = result.get("suspicious", False)
        reputation = result.get("reputation", "unknown")
        details = result.get("details", {})

        # Check for malicious indicators
        is_malicious = (
            details.get("blacklisted", False)
            or details.get("malicious_activity", False)
            or reputation in ["low", "malicious"]
        )

        if is_malicious:
            level: TaxonomyLevel = "malicious"
        elif suspicious or reputation in ["medium", "suspicious"]:
            level = "suspicious"
        else:
            level = "safe"

        # Add suspicious status taxonomy
        taxonomies.append(
            self.build_taxonomy(level, "EmailRep", "suspicious", str(suspicious)).to_dict()
        )

        # Add references count taxonomy
        references = result.get("references", 0)
        ref_level: TaxonomyLevel = "info"
        if references > 0:
            ref_level = "suspicious" if suspicious else "info"

        taxonomies.append(
            self.build_taxonomy(ref_level, "EmailRep", "references", str(references)).to_dict()
        )

        # Add reputation score if available
        reputation = result.get("reputation", "unknown")
        if reputation != "unknown":
            rep_level: TaxonomyLevel = "info"
            if reputation in ["low", "malicious"]:
                rep_level = "malicious"
            elif reputation in ["suspicious", "medium"]:
                rep_level = "suspicious"
            elif reputation in ["high", "good"]:
                rep_level = "safe"

            taxonomies.append(
                self.build_taxonomy(rep_level, "EmailRep", "reputation", str(reputation)).to_dict()
            )

        full_report = {
            "observable": observable,
            "verdict": level,
            "taxonomy": taxonomies,
            "source": "emailrep",
            "data_type": dtype,
            "values": [result],
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
