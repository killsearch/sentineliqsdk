"""EchoTrail Analyzer: file hash analysis using EchoTrail API.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

    input_data = WorkerInput(data_type="hash", data="abc123...")
    report = EchoTrailAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Provide API key via `WorkerConfig.secrets['echotrail']['api_key']`.
- HTTP proxies honored via `WorkerConfig.proxy`.
"""

from __future__ import annotations

import hashlib
from typing import Any

import requests

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel


class EchoTrailAnalyzer(Analyzer):
    """Analyzer that queries EchoTrail API for file hash intelligence.

    Provides insights about file prevalence, reputation, and associated metadata
    including paths, parents, children, and network information.
    """

    # Threat assessment thresholds
    MALICIOUS_RANK_THRESHOLD = 10
    SUSPICIOUS_RANK_THRESHOLD = 100
    LOW_PREVALENCE_THRESHOLD = 0.01  # Less than 1%
    HIGH_EPS_THRESHOLD = 1000

    METADATA = ModuleMetadata(
        name="EchoTrail Analyzer",
        description="File hash analysis using EchoTrail API for prevalence and reputation insights",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/echotrail/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None) -> None:
        """Initialize EchoTrail analyzer."""
        super().__init__(input_data, secret_phrases)
        self.api_root = "https://api.echotrail.io/v1/private"
        self.session = requests.Session()
        self.session.verify = True

        # Configure proxy if provided
        proxy_config = self.get_config("echotrail.proxy")
        if proxy_config:
            self.session.proxies = proxy_config

        # Set up headers
        api_key = self.get_secret("echotrail.api_key", message="EchoTrail API key is required")
        self.session.headers.update({"Accept": "application/json", "X-Api-key": str(api_key)})

    @staticmethod
    def get_file_hash(file_path: str, blocksize: int = 8192, algorithm=hashlib.sha256) -> str:
        """Calculate hash of a file.

        Args:
            file_path: Path to the file
            blocksize: Block size for reading file
            algorithm: Hash algorithm to use

        Returns
        -------
            Hexadecimal hash string
        """
        file_hash = algorithm()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(blocksize), b""):
                file_hash.update(chunk)
        return file_hash.hexdigest()

    def _check_for_api_errors(
        self, response: requests.Response, error_prefix: str = "", good_status_code: int = 200
    ) -> None:
        """Check for API failure response and raise error if needed.

        Args:
            response: HTTP response object
            error_prefix: Prefix for error message
            good_status_code: Expected successful status code
        """
        if response.status_code != good_status_code:
            message = None
            try:
                response_dict = response.json()
                if "message" in response_dict:
                    message = f"{error_prefix} {response_dict['message']}"
            except requests.exceptions.JSONDecodeError:
                pass

            if message is None:
                message = f"{error_prefix} HTTP {response.status_code} {response.text}"
            self.error(message)

    def get_insights(self, search_term: str) -> dict[str, Any]:
        """Get insights from EchoTrail API.

        Args:
            search_term: Hash or other search term

        Returns
        -------
            API response data
        """
        url = f"{self.api_root}/insights/{search_term}"
        try:
            response = self.session.get(url)
            self._check_for_api_errors(response, "EchoTrail API error:")
            return response.json()
        except requests.RequestException as e:
            self.error(f"Error while trying to get insights: {e}")

    def _determine_verdict(self, result: dict[str, Any]) -> TaxonomyLevel:
        """Determine verdict based on EchoTrail results.

        Args:
            result: EchoTrail API response

        Returns
        -------
            Taxonomy level (verdict)
        """
        if not result.get("matched", False):
            return "info"

        # Check rank - lower rank indicates more suspicious
        rank = result.get("rank")
        if rank is not None:
            if rank <= self.MALICIOUS_RANK_THRESHOLD:
                return "malicious"
            if rank <= self.SUSPICIOUS_RANK_THRESHOLD:
                return "suspicious"

        # Check host prevalence - very low prevalence might be suspicious
        host_prev = result.get("host_prev")
        if host_prev is not None and host_prev < self.LOW_PREVALENCE_THRESHOLD:
            return "suspicious"

        # Check EPS (Events Per Second) - very high might indicate malware
        eps = result.get("eps")
        if eps is not None and eps > self.HIGH_EPS_THRESHOLD:
            return "suspicious"

        return "safe"

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport."""
        observable = self.get_data()
        data_type = self.data_type

        # Validate hash format for hash data type
        if data_type == "hash":
            hash_str = str(observable)
            if len(hash_str) not in (32, 64):  # MD5 or SHA-256
                self.error(
                    f"The input hash has an invalid length ({len(hash_str)}). "
                    "It should be 32 (MD5) or 64 (SHA-256) characters."
                )

        # Get insights from EchoTrail
        result = self.get_insights(str(observable))

        # Check if we got a match
        if len(result) == 1 and "message" in result:
            result["matched"] = False
        else:
            result["matched"] = True

        # Determine verdict
        verdict = self._determine_verdict(result)

        # Build taxonomy
        taxonomy = self.build_taxonomy(
            level=verdict, namespace="echotrail", predicate="reputation", value=str(observable)
        )

        # Build full report
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "echotrail",
            "data_type": data_type,
            "details": result,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
