"""AnyRun Analyzer: submit files and URLs for sandbox analysis via AnyRun API.

Features:
- Accepts `data_type == "file"` and `data_type == "url"` for sandbox analysis.
- Configurable environment settings (bitness, version, type, network options).
- Polls for analysis completion and returns detailed sandbox results.
- Builds taxonomy based on AnyRun verdict scores.

Configuration (dataclasses only):
- API token via `WorkerConfig.secrets['anyrun']['token']`.
- Privacy type via `WorkerConfig.params['anyrun']['privacy_type']` (required).
- Environment settings via `WorkerConfig.params['anyrun']['env_*']` (optional).
- Network options via `WorkerConfig.params['anyrun']['opt_*']` (optional).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.anyrun import AnyRunAnalyzer

    inp = WorkerInput(
        data_type="file",
        filename="/path/to/sample.exe",
        config=WorkerConfig(
            secrets={"anyrun": {"token": "YOUR_TOKEN"}},
            params={"anyrun": {"privacy_type": "public"}}
        ),
    )
    report = AnyRunAnalyzer(inp).execute()
"""

from __future__ import annotations

import time
from typing import Any, NoReturn, cast

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Constants for HTTP status codes and scoring thresholds
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_RATE_LIMIT = 429
HTTP_CLIENT_ERROR_MIN = 400
HTTP_SERVER_ERROR_MIN = 500
SUSPICIOUS_SCORE_THRESHOLD = 50
MALICIOUS_SCORE_THRESHOLD = 100


class AnyRunAnalyzer(Analyzer):
    """Analyzer that submits files and URLs to AnyRun sandbox for analysis."""

    METADATA = ModuleMetadata(
        name="AnyRun Analyzer",
        description="Submete arquivos e URLs para análise em sandbox via AnyRun API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/anyrun/",
        version_stage="TESTING",
    )

    def _api_token(self) -> str:
        token = self.get_secret("anyrun.token")
        if not token:
            self.error("Missing AnyRun API token (set config.secrets['anyrun']['token'])")
        return str(token)

    def _privacy_type(self) -> str:
        privacy_type = self.get_config("anyrun.privacy_type")
        if not privacy_type:
            self.error("Missing privacy type (set config.params['anyrun']['privacy_type'])")
        return str(privacy_type)

    def _verify_ssl(self) -> bool:
        return bool(self.get_config("anyrun.verify_ssl", True))

    def _get_config_param(self, key: str, default: Any = None) -> Any:
        """Get configuration parameter with anyrun prefix."""
        return self.get_config(f"anyrun.{key}", default)

    def _add_optional_params(self, data: dict[str, Any], param_names: list[str]) -> None:
        """Add optional configuration parameters to data dict if they exist."""
        for param_name in param_names:
            value = self._get_config_param(param_name)
            if value is not None:
                data[param_name] = value

    def _build_analysis_data(self, obj_type: str, obj_data: str | None = None) -> dict[str, Any]:
        """Build analysis data payload with configuration parameters."""
        data = {
            "obj_type": obj_type,
            "opt_privacy_type": self._privacy_type(),
        }

        # Add object-specific data
        if obj_type == "url" and obj_data:
            data["obj_url"] = obj_data

        # Environment settings
        env_params = ["env_bitness", "env_version", "env_type"]
        self._add_optional_params(data, env_params)

        # Network options
        network_params = [
            "opt_network_connect",
            "opt_network_fakenet",
            "opt_network_tor",
            "opt_network_mitm",
            "opt_network_geo",
        ]
        self._add_optional_params(data, network_params)

        # Other options
        other_params = [
            "opt_kernel_heavyevasion",
            "opt_timeout",
            "obj_ext_startfolder",
            "obj_ext_browser",
        ]
        self._add_optional_params(data, other_params)

        return data

    def _submit_analysis(self, data: dict[str, Any], files: dict[str, Any] | None = None) -> str:
        """Submit analysis to AnyRun API and return task ID."""
        url = "https://api.any.run/v1/analysis"
        headers = {"Authorization": f"API-Key {self._api_token()}"}

        max_tries = 15
        for attempt in range(max_tries + 1):
            try:
                with httpx.Client(timeout=60.0, verify=self._verify_ssl()) as client:
                    if files:
                        response = client.post(url, data=data, files=files, headers=headers)
                    else:
                        response = client.post(url, data=data, headers=headers)

                if response.status_code in (HTTP_OK, HTTP_CREATED):
                    result = response.json()
                    return str(result["data"]["taskid"])

                if response.status_code == HTTP_RATE_LIMIT:
                    # Rate limited, wait and retry
                    if attempt < max_tries:
                        time.sleep(60)
                        continue
                    self.error("AnyRun API rate limit exceeded after maximum retries")

                error_msg = "Unknown error"
                try:
                    error_data = response.json()
                    error_msg = error_data.get("message", error_msg)
                except Exception:
                    error_msg = response.text or error_msg
                self.error(f"AnyRun API error (status {response.status_code}): {error_msg}")

            except httpx.HTTPError as exc:
                self.error(f"HTTP call to AnyRun failed: {exc}")

        self.error("Failed to submit analysis to AnyRun after maximum retries")
        return cast(str, self._never_returns())  # type: ignore[unreachable]

    def _wait_for_completion(self, task_id: str) -> dict[str, Any]:
        """Poll AnyRun API for analysis completion and return results."""
        url = f"https://api.any.run/v1/analysis/{task_id}"
        headers = {"Authorization": f"API-Key {self._api_token()}"}

        max_tries = 15  # 15 minutes max
        for attempt in range(max_tries + 1):
            try:
                with httpx.Client(timeout=30.0, verify=self._verify_ssl()) as client:
                    response = client.get(url, headers=headers)

                if response.status_code == HTTP_OK:
                    result = response.json()
                    status = result["data"]["status"]
                    if status == "done":
                        return result["data"]

                if HTTP_CLIENT_ERROR_MIN < response.status_code < HTTP_SERVER_ERROR_MIN:
                    error_msg = "Unknown error"
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("message", error_msg)
                    except Exception:
                        error_msg = response.text or error_msg
                    self.error(f"AnyRun API error (status {response.status_code}): {error_msg}")

                self.error(f"AnyRun API error (status {response.status_code})")

            except httpx.HTTPError as exc:
                self.error(f"HTTP call to AnyRun failed: {exc}")

            # Wait before next attempt (only if not the last attempt)
            if attempt < max_tries:  # type: ignore[unreachable]
                time.sleep(60)

        # If we get here, we've exhausted all attempts
        self.error("AnyRun analysis timed out")
        return cast(dict[str, Any], self._never_returns())  # type: ignore[unreachable]

    def _never_returns(self) -> NoReturn:
        """Return a value that never returns, used after self.error() calls."""
        raise RuntimeError("This should never be reached")

    def _clean_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Clean up the report by removing large fields to avoid memory issues."""
        # Remove potentially large fields
        report.pop("environments", None)
        report.pop("modified", None)

        # Clean up incidents
        for incident in report.get("incidents", []):
            incident.pop("events", None)

        # Clean up processes
        for process in report.get("processes", []):
            process.pop("modules", None)

        return report

    def _build_taxonomy(self, report: dict[str, Any]) -> list[dict[str, str]]:
        """Build taxonomy entries based on AnyRun analysis results."""
        taxonomies = []
        analysis = report.get("analysis", {})
        scores = analysis.get("scores", {})
        verdict = scores.get("verdict", {})
        score = int(verdict.get("score", 0))

        # Determine threat level based on score
        level: TaxonomyLevel = "safe"
        if SUSPICIOUS_SCORE_THRESHOLD < score < MALICIOUS_SCORE_THRESHOLD:
            level = "suspicious"
        elif score == MALICIOUS_SCORE_THRESHOLD:
            level = "malicious"

        taxonomies.append(
            self.build_taxonomy(level, "anyrun", "sandbox-score", f"{score}/100").to_dict()
        )

        # Add additional taxonomy entries for other scores
        for score_type, score_data in scores.items():
            if isinstance(score_data, dict) and "score" in score_data:
                score_value = int(score_data.get("score", 0))
                if score_value > 0:
                    taxonomies.append(
                        self.build_taxonomy(
                            "info", "anyrun", f"{score_type}-score", str(score_value)
                        ).to_dict()
                    )

        return taxonomies

    def execute(self) -> AnalyzerReport:
        """Execute AnyRun analysis based on data type."""
        dtype = self.data_type
        observable = self.get_data()

        if dtype not in ("file", "url"):
            self.error(f"Unsupported data type for AnyRunAnalyzer: {dtype}")

        # Build analysis data
        analysis_data = self._build_analysis_data(
            dtype, str(observable) if dtype == "url" else None
        )

        # Submit analysis
        task_id = None
        if dtype == "file":
            # File upload
            try:
                with open(observable, "rb") as f:
                    files = {"file": (observable, f)}
                    task_id = self._submit_analysis(analysis_data, files)
            except FileNotFoundError:
                self.error(f"File not found: {observable}")
            except Exception as exc:
                self.error(f"Error reading file {observable}: {exc}")
        else:
            # URL analysis
            task_id = self._submit_analysis(analysis_data)

        # Wait for completion and get results
        report = self._wait_for_completion(task_id)
        cleaned_report = self._clean_report(report)

        # Build taxonomy
        taxonomies = self._build_taxonomy(cleaned_report)

        # Determine overall verdict
        analysis = cleaned_report.get("analysis", {})
        scores = analysis.get("scores", {})
        verdict = scores.get("verdict", {})
        score = int(verdict.get("score", 0))
        overall_verdict: TaxonomyLevel = "safe"
        if SUSPICIOUS_SCORE_THRESHOLD < score < MALICIOUS_SCORE_THRESHOLD:
            overall_verdict = "suspicious"
        elif score == MALICIOUS_SCORE_THRESHOLD:
            overall_verdict = "malicious"

        full_report = {
            "observable": observable,
            "verdict": overall_verdict,
            "taxonomy": taxonomies,
            "source": "anyrun",
            "data_type": dtype,
            "task_id": task_id,
            "analysis": cleaned_report,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> None:
        """Run the analyzer."""
        self.execute()
