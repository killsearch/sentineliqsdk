"""EmergingThreats Analyzer: check reputation via EmergingThreats API.

Features:
- Accepts `data_type` in ["domain", "fqdn", "ip", "hash", "file"] and queries the EmergingThreats API.
- Categorizes threats into malicious, suspicious, or safe based on reputation scores.
- Provides detailed threat intelligence information including reputation, events, and geolocation.

Configuration (dataclasses only):
- API key via `WorkerConfig.secrets['emergingthreats']['api_key']` (required).

Example programmatic usage:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.emergingthreats import EmergingThreatsAnalyzer

    inp = WorkerInput(
        data_type="domain",
        data="malicious.example.com",
        config=WorkerConfig(secrets={"emergingthreats": {"api_key": "YOUR_KEY"}}),
    )
    report = EmergingThreatsAnalyzer(inp).execute()
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import requests

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata, TaxonomyLevel

# Threat categories classification
RED_CATEGORIES = [
    "Blackhole",
    "Bot",
    "Brute_Forcer",
    "CnC",
    "Compromised",
    "DDoSAttacker",
    "DDoSTarget",
    "DriveBySrc",
    "Drop",
    "EXE_Source",
    "FakeAV",
    "Mobile_CnC",
    "Mobile_Spyware_CnC",
    "P2PCnC",
    "Scanner",
    "Spam",
    "SpywareCnC",
]

YELLOW_CATEGORIES = [
    "AbusedTLD",
    "Bitcoin_Related",
    "ChatServer",
    "DynDNS",
    "IPCheck",
    "OnlineGaming",
    "P2P",
    "Parking",
    "Proxy",
    "RemoteAccessService",
    "SelfSignedSSL",
    "Skype_SuperNode",
    "TorNode",
    "Undesirable",
    "VPN",
]

GREEN_CATEGORIES = ["Utility"]


class EmergingThreatsAnalyzer(Analyzer):
    """Analyzer that queries EmergingThreats for threat intelligence and reports taxonomy."""

    METADATA = ModuleMetadata(
        name="EmergingThreats Analyzer",
        description="Consulta inteligência de ameaças via EmergingThreats API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/emergingthreats/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None) -> None:
        super().__init__(input_data, secret_phrases)
        self.session = requests.Session()
        api_key = self.get_secret(
            "emergingthreats.api_key", message="EmergingThreats API key is required"
        )
        self.session.headers.update({"Authorization": api_key})

    def _get_object_hash(self, filepath: str) -> str:
        """Calculate MD5 hash for file objects."""
        try:
            with open(filepath, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as exc:
            self.error(f"Failed to calculate file hash: {exc}")

    def _fetch_threat_data(self, object_name: str, data_type: str) -> dict[str, Any]:
        """Fetch threat intelligence data from EmergingThreats API."""
        info = {}

        try:
            if data_type in ["domain", "fqdn"]:
                url = "https://api.emergingthreats.net/v1/domains/"
                features = {
                    "reputation",
                    "urls",
                    "samples",
                    "ips",
                    "events",
                    "nameservers",
                    "whois",
                    "geoloc",
                }
            elif data_type == "ip":
                url = "https://api.emergingthreats.net/v1/ips/"
                features = {"reputation", "urls", "samples", "domains", "events", "geoloc"}
            elif data_type in ["hash", "file"]:
                url = "https://api.emergingthreats.net/v1/samples/"
                features = {"", "connections", "dns", "http", "events"}
            else:
                raise ValueError(f"Unsupported data type: {data_type}")

            for feature in features:
                end = "/" if feature else ""
                time.sleep(1)  # Rate limiting

                try:
                    response = self.session.get(url + object_name + end + feature)
                    feature_name = "main" if feature == "" else feature

                    if response.status_code == 200:
                        r_json = response.json()
                        if r_json.get("response") not in [{}, []]:
                            info[feature_name] = r_json["response"]
                        else:
                            info[feature_name] = "-"
                    else:
                        info[feature_name] = "Error"

                except Exception as exc:
                    self.error(f"Failed to fetch {feature} data: {exc}")
                    info[feature_name] = "Error"

        except Exception as exc:
            self.error(f"Failed to fetch EmergingThreats data: {exc}")

        return info

    def _determine_threat_level(self, reputation_data: Any) -> TaxonomyLevel:
        """Determine threat level based on reputation data."""
        if not reputation_data or reputation_data in ["-", "Error"]:
            return "info"

        if isinstance(reputation_data, list):
            for rep in reputation_data:
                if isinstance(rep, dict):
                    category = rep.get("category", "")
                    score = rep.get("score", 0)

                    if category in RED_CATEGORIES and score >= 70:
                        return "malicious"
                    if (70 <= score < 100 and category in RED_CATEGORIES) or (
                        score >= 100 and category in YELLOW_CATEGORIES
                    ):
                        return "suspicious"

        return "safe"

    def execute(self) -> AnalyzerReport:
        """Execute the EmergingThreats analysis."""
        dtype = self.data_type
        observable = self.get_data()

        if dtype not in ["domain", "fqdn", "ip", "hash", "file"]:
            raise ValueError(
                f"EmergingThreats supports domain, fqdn, ip, hash, file data types, got: {dtype}"
            )

        # Handle file type by calculating hash
        object_name = str(observable)
        if dtype == "file":
            if (
                hasattr(self._input, "attachment")
                and self._input.attachment
                and self._input.attachment.hashes
            ):
                # Find MD5 hash from attachment hashes
                md5_hash = next((h for h in self._input.attachment.hashes if len(h) == 32), None)
                object_name = md5_hash or self._get_object_hash(str(observable))
            else:
                object_name = self._get_object_hash(str(observable))

        # Fetch threat intelligence data
        result = self._fetch_threat_data(object_name, dtype)

        # Build taxonomies based on EmergingThreats response
        taxonomies = []

        # Determine overall threat level
        reputation_data = result.get("reputation")
        threat_level = self._determine_threat_level(reputation_data)

        # Add reputation taxonomy
        if reputation_data and reputation_data not in ["-", "Error"]:
            if isinstance(reputation_data, list) and reputation_data:
                for rep in reputation_data:
                    if isinstance(rep, dict):
                        category = rep.get("category", "unknown")
                        score = rep.get("score", 0)
                        value = f"{category}={score}"

                        # Determine level for this specific reputation entry
                        if category in RED_CATEGORIES and score >= 70:
                            level: TaxonomyLevel = "malicious"
                        elif (70 <= score < 100 and category in RED_CATEGORIES) or (
                            score >= 100 and category in YELLOW_CATEGORIES
                        ):
                            level = "suspicious"
                        else:
                            level = "safe"

                        taxonomies.append(
                            self.build_taxonomy(level, "ET", f"{dtype}-reputation", value).to_dict()
                        )
            else:
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "ET", f"{dtype}-reputation", str(reputation_data)
                    ).to_dict()
                )

        # Add events taxonomy for hash/file types
        if dtype in ["hash", "file"] and "events" in result:
            events_data = result["events"]
            if events_data and events_data not in ["-", "Error"]:
                if isinstance(events_data, list):
                    event_count = len(events_data)
                    value = f"{event_count} signatures"
                    taxonomies.append(
                        self.build_taxonomy(
                            "malicious", "ET", "malware-signatures", value
                        ).to_dict()
                    )

        full_report = {
            "observable": observable,
            "verdict": threat_level,
            "taxonomy": taxonomies,
            "source": "emergingthreats",
            "data_type": dtype,
            "values": [result],
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run analysis and return AnalyzerReport."""
        return self.execute()
