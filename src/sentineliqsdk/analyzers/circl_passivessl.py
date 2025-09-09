"""CIRCL PassiveSSL Analyzer: queries the CIRCL PassiveSSL service for certificate/IP relationships.

This analyzer provides comprehensive passive SSL lookup capabilities using the CIRCL PassiveSSL
API, including IP to certificate and certificate to IP queries.

Usage example:

    from sentineliqsdk import WorkerInput
    from sentineliqsdk.analyzers.circl_passivessl import CirclPassivesslAnalyzer

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    report = CirclPassivesslAnalyzer(input_data).execute()  # returns AnalyzerReport

Configuration:
- Requires CIRCL PassiveSSL credentials (username/password)
- HTTP proxies honored via `WorkerConfig.proxy`
- Supports both IP and certificate hash queries
"""

from __future__ import annotations

from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.constants import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    HTTP_UNAUTHORIZED,
    SAFE_CERTIFICATE_THRESHOLD,
    SHA1_HASH_LENGTH,
)
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# HTTP status codes





class CirclPassivesslAnalyzer(Analyzer):
    """Analyzer that queries CIRCL PassiveSSL for certificate and IP relationships."""

    METADATA = ModuleMetadata(
        name="CIRCL PassiveSSL Analyzer",
        description="Query CIRCL PassiveSSL for certificate and IP relationships",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage documented",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/circl_passivessl/",
        version_stage="STABLE",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)
        self.base_url = "https://www.circl.lu/pssl/"

        # Get credentials from config
        username = self.get_secret(
            "circl_passivessl.username", message="CIRCL PassiveSSL username required"
        )
        password = self.get_secret(
            "circl_passivessl.password", message="CIRCL PassiveSSL password required"
        )

        self.session = httpx.Client(
            auth=(username, password),
            headers={"Accept": "application/json"},
            timeout=30.0,
        )

    def __del__(self):
        """Clean up HTTP session."""
        if hasattr(self, "session"):
            self.session.close()

    def _make_request(self, endpoint: str, **kwargs) -> dict[str, Any]:
        """Make HTTP request to CIRCL PassiveSSL API."""
        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.get(url, **kwargs)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == HTTP_UNAUTHORIZED:
                self.error("CIRCL PassiveSSL authentication failed. Check credentials.")
            elif e.response.status_code == HTTP_FORBIDDEN:
                self.error("CIRCL PassiveSSL access forbidden. Check permissions.")
            elif e.response.status_code == HTTP_NOT_FOUND:
                return {}  # No results found
            else:
                self.error(f"CIRCL PassiveSSL API request failed: {e}")
        except httpx.RequestError as e:
            self.error(f"CIRCL PassiveSSL connection failed: {e}")

    def _query_ip(self, ip: str) -> dict[str, Any]:
        """
        Query CIRCL PassiveSSL for an IP address.

        :param ip: IP address to query for
        :type ip: str
        :returns: Dictionary with certificates and subjects
        :rtype: dict
        """
        try:
            result = self._make_request(f"query/{ip}")
        except Exception:
            self.error(
                "Exception during processing with PassiveSSL. Please check the format of IP."
            )

        # Check for empty result
        if not result.get(ip):
            certificates = []
        else:
            certificates = list(result.get(ip, {}).get("certificates", []))
            subjects = result.get(ip, {}).get("subjects", {})

        newresult: dict[str, Any] = {"ip": ip, "certificates": []}

        for cert in certificates:
            if cert not in subjects:
                continue
            subject_data = subjects.get(cert, {})
            values = subject_data.get("values", [])
            if values:
                newresult["certificates"].append({"fingerprint": cert, "subject": values[0]})

        return newresult

    def _query_certificate(self, cert_hash: str) -> dict[str, Any]:
        """
        Query CIRCL PassiveSSL for a certificate hash.

        :param cert_hash: SHA1 hash to query for
        :type cert_hash: str
        :return: Dictionary with query results and certificate details
        :rtype: dict
        """
        try:
            cquery = self._make_request(f"query_cert/{cert_hash}")
        except Exception:
            self.error(
                "Exception during processing with PassiveSSL. "
                "This happens if the given hash is not sha1 or contains dashes/colons etc. "
                "Please make sure to submit a clean formatted sha1 hash."
            )

        # Fetch certificate details
        try:
            cfetch = self._make_request(f"fetch_cert/{cert_hash}")
        except Exception:
            cfetch = {}

        return {"query": cquery, "cert": cfetch}

    def _verdict_from_results(self, result_count: int) -> TaxonomyLevel:
        """Determine verdict based on result count."""
        if result_count == 0:
            return "info"  # No records found
        if result_count <= SAFE_CERTIFICATE_THRESHOLD:
            return "safe"  # Few records, likely legitimate
        return "suspicious"  # Many records, worth investigating

    def execute(self) -> AnalyzerReport:
        """Execute analysis and return an AnalyzerReport (programmatic usage)."""
        dtype = self.data_type
        observable = self.get_data()

        # Route to appropriate analysis method
        if dtype == "hash":
            # Validate SHA1 hash length
            sha1_hash_length = SHA1_HASH_LENGTH
            if len(str(observable)) != sha1_hash_length:
                self.error(
                    "CIRCL PassiveSSL expects a SHA1 hash, given hash has more or less than 40 characters."
                )

            details = self._query_certificate(str(observable))
            result_count = details.get("query", {}).get("hits", 0)

        elif dtype == "ip":
            # Check for CIDR notation
            if "/" in str(observable):
                self.error("CIDRs currently not supported. Please use an IP.")

            details = self._query_ip(str(observable))
            result_count = len(details.get("certificates", []))

        else:
            self.error(f"Unsupported data type for CirclPassivesslAnalyzer: {dtype}")

        verdict = self._verdict_from_results(result_count)

        # Build taxonomy
        value = f"{result_count} record" if result_count in {0, 1} else f"{result_count} records"

        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="CIRCL",
            predicate="PassiveSSL",
            value=value,
        )

        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "source": "circl_passivessl",
            "data_type": dtype,
            "details": details,
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
