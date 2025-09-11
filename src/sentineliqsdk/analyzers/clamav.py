"""ClamAV Analyzer for malware detection using ClamAV antivirus engine."""

from __future__ import annotations

import json
import os

import pyclamd

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class ClamavAnalyzer(Analyzer):
    """
    ClamAV antivirus analyzer that scans files for malware using ClamAV engine.

    This analyzer connects to a local ClamAV daemon via Unix socket and scans
    files for known malware signatures. It supports both file path and file
    content scanning.
    """

    METADATA = ModuleMetadata(
        name="ClamAV Analyzer",
        description="Scans files for malware using ClamAV antivirus engine",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="antivirus",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/clamav/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)

        # Get ClamAV configuration
        # Use direct access to params since get_config might have issues with dotted paths
        params = dict(self._input.config.params)
        self.socket_path = params.get("clamav.socket_path", "/var/run/clamav/clamd.ctl")
        self.timeout = params.get("clamav.timeout", 30)

        # Initialize ClamAV connection
        self._init_clamav()

    def _init_clamav(self) -> None:
        """Initialize ClamAV connection."""
        try:
            self.clamd = pyclamd.ClamdUnixSocket(path=self.socket_path)
            # Test connection
            self.clamd.ping()
        except Exception as e:
            self.error(f"Failed to connect to ClamAV daemon at {self.socket_path}: {e}")

    def check_file(self, file_path: str) -> str | None:
        """
        Check a file against ClamAV signatures.

        Args:
            file_path: Path to the file to scan

        Returns
        -------
            Malware name if detected, None if clean
        """
        try:
            if not os.path.exists(file_path):
                self.error(f"File not found: {file_path}")

            if not os.path.isfile(file_path):
                self.error(f"Path is not a file: {file_path}")

            # Scan the file
            result = self.clamd.scan_file(file_path)

            if result and file_path in result:
                # Return the malware name
                return result[file_path][1]

            return None

        except Exception as e:
            self.error(f"Error scanning file {file_path}: {e}")

    def check_data(self, data: bytes) -> str | None:
        """
        Check file data against ClamAV signatures.

        Args:
            data: File content as bytes

        Returns
        -------
            Malware name if detected, None if clean
        """
        try:
            # Scan the data
            result = self.clamd.scan_stream(data)

            if result and "stream" in result:
                # Return the malware name
                return result["stream"][1]

            return None

        except Exception as e:
            self.error(f"Error scanning data: {e}")

    def execute(self) -> AnalyzerReport:
        """Execute the ClamAV analysis."""
        # Determine if we have file path or file data
        if self._input.data_type == "file":
            if self._input.filename:
                # File path provided
                malware_name = self.check_file(self._input.filename)
                observable = self._input.filename
            else:
                # File data provided - get data directly from input
                observable = self._input.data
                data = observable.encode("utf-8") if isinstance(observable, str) else observable
                malware_name = self.check_data(data)
        else:
            self.error("ClamAV analyzer only supports 'file' data type")

        # Build taxonomy
        if malware_name:
            taxonomy = self.build_taxonomy(
                level="malicious", namespace="ClamAV", predicate="detection", value=malware_name
            )
            verdict = "malicious"
        else:
            taxonomy = self.build_taxonomy(
                level="safe", namespace="ClamAV", predicate="detection", value="No threats detected"
            )
            verdict = "safe"

        # Build full report
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "data_type": self.data_type,
            "malware_name": malware_name,
            "taxonomy": [taxonomy.to_dict()],
            "metadata": self.METADATA.to_dict(),
        }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Run the analyzer."""
        report = self.execute()
        # Print the report in JSON format to stdout
        print(json.dumps(report.full_report, ensure_ascii=False))
        return report
