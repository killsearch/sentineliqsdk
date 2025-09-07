"""ChainAbuse Analyzer: check blockchain addresses and URLs via ChainAbuse API.

Features:
- Accepts `data_type` in ["ip", "url", "domain", "hash"] and queries the reports endpoint.
- Checks if addresses/URLs are reported as malicious or sanctioned.
- Summarizes report count, categories, and confidence into taxonomy.
- Supports both individual reports and sanctioned address checks.

Configuration (dataclasses only):
- API key via `WorkerConfig.secrets['chainabuse']['api_key']`.
- Optional timeout via `WorkerConfig.params['chainabuse']['timeout']` (default 30).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.chainabuse import ChainAbuseAnalyzer

    inp = WorkerInput(
        data_type="ip",
        data="1.2.3.4",
        config=WorkerConfig(secrets={"chainabuse": {"api_key": "YOUR_KEY"}}),
    )
    report = ChainAbuseAnalyzer(inp).execute()
"""

from __future__ import annotations

import base64
from contextlib import suppress
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# HTTP status codes
HTTP_OK = 200
HTTP_NOT_FOUND = 404

# Thresholds
MALICIOUS_REPORT_THRESHOLD = 5


class ChainAbuseAnalyzer(Analyzer):
    """Analyzer that queries ChainAbuse for blockchain address and URL reputation."""

    METADATA = ModuleMetadata(
        name="ChainAbuse Analyzer",
        description="Consulta reputação de endereços blockchain e URLs na ChainAbuse",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/chainabuse/",
        version_stage="TESTING",
    )

    def _api_key(self) -> str:
        """Get API key from configuration."""
        key = self.get_secret("chainabuse.api_key")
        if not key:
            self.error("Missing ChainAbuse API key (set config.secrets['chainabuse']['api_key'])")
        return str(key)

    def _timeout(self) -> float:
        """Get timeout from configuration."""
        try:
            raw = self.get_config("chainabuse.timeout", 30)
            return float(raw) if raw is not None else 30.0
        except Exception:
            return 30.0

    def _get_auth_header(self) -> str:
        """Get HTTP Basic Auth header for ChainAbuse API."""
        api_key = self._api_key()
        # ChainAbuse uses HTTP Basic Auth where the API-key is passed as both user & password
        credentials = f"{api_key}:{api_key}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded_credentials}"

    def _fetch_reports(self, observable: str) -> dict[str, Any]:
        """Fetch reports for the given observable."""
        url = "https://api.chainabuse.com/v0/reports"
        headers = {
            "Accept": "application/json",
            "Authorization": self._get_auth_header(),
        }
        params = {"address": observable}

        try:
            with httpx.Client(timeout=self._timeout()) as client:
                resp = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            self.error(f"HTTP call to ChainAbuse failed: {exc}")

        if resp.status_code == HTTP_OK:
            try:
                result = resp.json()
                # Normalize response format
                if isinstance(result, list):
                    return {"data": result, "count": len(result)}
                if isinstance(result, dict):
                    return result
                return {"data": [], "count": 0}
            except Exception as e:
                self.error(f"Could not decode JSON response: {e!s}")
        else:
            self.error(
                f"Failed to query ChainAbuse API. Status: {resp.status_code}, Content: {resp.text}"
            )

    def _fetch_sanctioned_address(self, address: str) -> dict[str, Any]:
        """Fetch sanctioned address information."""
        url = f"https://api.chainabuse.com/v0/sanctioned-addresses/{address}"
        headers = {
            "Accept": "application/json",
            "Authorization": self._get_auth_header(),
        }

        try:
            with httpx.Client(timeout=self._timeout()) as client:
                resp = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            self.error(f"HTTP call to ChainAbuse sanctioned addresses failed: {exc}")

        if resp.status_code == HTTP_OK:
            try:
                return resp.json()
            except Exception as e:
                self.error(f"Could not decode JSON response: {e!s}")
        if resp.status_code == HTTP_NOT_FOUND:
            # Address not found in sanctioned list
            return {"sanctioned": False, "data": None}
        self.error(
            f"Failed to query ChainAbuse sanctioned addresses. Status: {resp.status_code}, "
            f"Content: {resp.text}"
        )

    def _determine_verdict(
        self, reports_data: dict[str, Any], sanctioned_data: dict[str, Any]
    ) -> TaxonomyLevel:
        """Determine the verdict based on reports and sanctioned status."""
        report_count = reports_data.get("count", 0)
        is_sanctioned = sanctioned_data.get("sanctioned", False)

        if is_sanctioned or report_count >= MALICIOUS_REPORT_THRESHOLD:
            return "malicious"
        if report_count > 0:
            return "suspicious"
        return "safe"

    def _build_taxonomies(
        self, reports_data: dict[str, Any], sanctioned_data: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Build taxonomy entries from the analysis results."""
        taxonomies = []

        report_count = reports_data.get("count", 0)
        is_sanctioned = sanctioned_data.get("sanctioned", False)

        # Report count taxonomy
        if report_count > 0:
            level: TaxonomyLevel = (
                "malicious" if report_count >= MALICIOUS_REPORT_THRESHOLD else "suspicious"
            )
            taxonomies.append(
                self.build_taxonomy(
                    level, "chainabuse", "report-count", str(report_count)
                ).to_dict()
            )
        else:
            taxonomies.append(
                self.build_taxonomy("safe", "chainabuse", "report-count", "0").to_dict()
            )

        # Sanctioned status taxonomy
        if is_sanctioned:
            taxonomies.append(
                self.build_taxonomy("malicious", "chainabuse", "sanctioned", "True").to_dict()
            )
        else:
            taxonomies.append(
                self.build_taxonomy("safe", "chainabuse", "sanctioned", "False").to_dict()
            )

        # Data type taxonomy
        taxonomies.append(
            self.build_taxonomy("info", "chainabuse", "data-type", self.data_type).to_dict()
        )

        return taxonomies

    def execute(self) -> AnalyzerReport:
        """Execute the ChainAbuse analysis."""
        dtype = self.data_type
        observable = self.get_data()

        # ChainAbuse supports various data types
        supported_types = ["ip", "url", "domain", "hash"]
        if dtype not in supported_types:
            self.error(
                f"Unsupported data type for ChainAbuseAnalyzer: {dtype}. Supported: {supported_types}"
            )

        # Fetch reports data
        reports_data = self._fetch_reports(str(observable))

        # Fetch sanctioned address data (for blockchain addresses)
        sanctioned_data = {"sanctioned": False, "data": None}
        if dtype in ["hash"]:  # Assume hash could be a blockchain address
            with suppress(Exception):
                # If sanctioned check fails, continue with reports only
                sanctioned_data = self._fetch_sanctioned_address(str(observable))

        # Determine verdict
        verdict = self._determine_verdict(reports_data, sanctioned_data)

        # Build taxonomies
        taxonomies = self._build_taxonomies(reports_data, sanctioned_data)

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": taxonomies,
            "source": "chainabuse",
            "data_type": dtype,
            "reports": reports_data,
            "sanctioned": sanctioned_data,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> None:
        """Run the analyzer and print results to stdout."""
        self.execute()
