"""CrowdStrike Falcon analyzer module."""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from typing import Any

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class CrowdStrikeFalconAnalyzer(Analyzer):
    """Analyze devices, alerts, vulnerabilities, and files via CrowdStrike Falcon API."""

    METADATA = ModuleMetadata(
        name="CrowdStrike Falcon Analyzer",
        description="Analyzes devices, alerts, vulnerabilities, and files using CrowdStrike Falcon API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/crowdstrike_falcon/",
        version_stage="TESTING",
    )

    def __init__(self, input_data, secret_phrases=None):
        super().__init__(input_data, secret_phrases)

        # Get credentials from WorkerConfig.secrets
        self.client_id = self.get_secret(
            "crowdstrike_falcon.client_id", message="CrowdStrike client_id required"
        )
        self.client_secret = self.get_secret(
            "crowdstrike_falcon.client_secret", message="CrowdStrike client_secret required"
        )

        # Get configuration from WorkerConfig
        self.base_url = self.get_config(
            "crowdstrike_falcon.base_url", "https://api.crowdstrike.com"
        )
        self.environment = self.get_config("crowdstrike_falcon.environment", 160)
        self.network_settings = self.get_config("crowdstrike_falcon.network_settings", "default")
        self.action_script = self.get_config("crowdstrike_falcon.action_script", "default")
        self.alert_fields = self.get_config(
            "crowdstrike_falcon.alert_fields",
            [
                "device_id",
                "device.hostname",
                "device.external_ip",
                "severity",
                "detection_id",
                "created_timestamp",
                "first_behavior",
                "last_behavior",
            ],
        )
        self.days_before = self.get_config("crowdstrike_falcon.days_before", 7)
        self.vuln_fields = self.get_config(
            "crowdstrike_falcon.vuln_fields",
            [
                "id",
                "cve.base_score",
                "cve.exploitability_score",
                "cve.impact_score",
                "apps.0.product_name_normalized",
                "apps.0.version",
                "status",
                "created_timestamp",
            ],
        )

    def execute(self) -> AnalyzerReport:
        """Execute the CrowdStrike Falcon analysis."""
        try:
            from falconpy import OAuth2  # type: ignore  # noqa: PLC0415
        except ImportError:
            self.error("falconpy library is required. Install with: pip install falconpy")

        observable = self.get_data()
        data_type = self.data_type

        # Initialize authentication
        auth = OAuth2(
            client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url
        )

        extra_headers = {"User-Agent": "sentineliqsdk/1.0"}

        full_report = {
            "observable": observable,
            "data_type": data_type,
            "analysis_type": "crowdstrike_falcon",
            "metadata": self.METADATA.to_dict(),
        }

        if data_type == "file":
            result = self._analyze_file(auth, extra_headers, observable)
            full_report.update(result)
        elif data_type in ("fqdn", "domain", "hostname"):
            result = self._analyze_hostname(auth, extra_headers, observable)
            full_report.update(result)
        else:
            self.error(f"Unsupported data type: {data_type}. Supported types: file, fqdn, domain")

        return self.report(full_report)

    def _analyze_file(self, auth, extra_headers, filepath) -> dict[str, Any]:
        """Analyze file using CrowdStrike FalconX Sandbox."""
        try:
            from falconpy import FalconXSandbox, SampleUploads  # type: ignore  # noqa: PLC0415
        except ImportError:
            self.error("falconpy library is required for file analysis")

        filename = self._input.filename or filepath.split("/")[-1]
        comment = "Submitted from SentinelIQ SDK"

        additional_params = {
            "environment_id": self.environment,
            "submit_name": filename,
            "network_settings": self.network_settings,
            "action_script": self.action_script,
        }

        try:
            with open(filepath, "rb") as sample:
                samples = SampleUploads(auth_object=auth, ext_headers=extra_headers)
                sandbox = FalconXSandbox(auth_object=auth, ext_headers=extra_headers)

                # Upload sample
                response = samples.upload_sample(
                    file_data=sample.read(),
                    file_name=filename,
                    comment=comment,
                    is_confidential=True,
                )

                if response["status_code"] not in [HTTPStatus.OK, HTTPStatus.CREATED]:
                    self.error(f"Error uploading file: {response}")

                sha256 = response["body"]["resources"][0]["sha256"]

                # Submit for analysis
                submit_response = sandbox.submit(
                    body={"sandbox": [{"sha256": sha256, **additional_params}]}
                )

                if submit_response["status_code"] not in [HTTPStatus.OK, HTTPStatus.CREATED]:
                    self.error(f"Error submitting file for analysis: {submit_response}")

                # Wait for analysis to complete
                submit_id = submit_response["body"]["resources"][0]["id"]
                status = "running"
                max_wait = 300  # 5 minutes max wait
                wait_time = 0

                while status == "running" and wait_time < max_wait:
                    time.sleep(10)
                    wait_time += 10
                    scan_status = sandbox.get_submissions(ids=submit_id)
                    if scan_status["body"]["resources"]:
                        status = scan_status["body"]["resources"][0]["state"]

                # Get analysis results
                if status == "completed":
                    analysis_result = sandbox.get_reports(ids=submit_id)
                    return {
                        "analysis_type": "sandbox",
                        "submit_id": submit_id,
                        "status": status,
                        "results": analysis_result["body"],
                        "verdict": self._determine_verdict(analysis_result["body"]),
                    }
                return {
                    "analysis_type": "sandbox",
                    "submit_id": submit_id,
                    "status": status,
                    "verdict": "unknown",
                }

        except FileNotFoundError:
            self.error(f"File not found: {filepath}")
        except Exception as e:
            self.error(f"Error analyzing file: {e!s}")

    def _analyze_hostname(self, auth, extra_headers, hostname) -> dict[str, Any]:
        """Analyze hostname for device details, alerts, and vulnerabilities."""
        try:
            from falconpy import (  # type: ignore  # noqa: PLC0415
                Alerts,
                Hosts,
                SpotlightVulnerabilities,
            )
        except ImportError:
            self.error("falconpy library is required for hostname analysis")

        hosts = Hosts(auth_object=auth, ext_headers=extra_headers)
        alerts = Alerts(auth_object=auth, ext_headers=extra_headers)
        spotlight = SpotlightVulnerabilities(auth_object=auth, ext_headers=extra_headers)

        device_id = self._lookup_device_id(hosts, hostname)
        result: dict[str, Any] = {"analysis_type": "hostname", "device_id": device_id}

        device_details = self._fetch_device_details(hosts, device_id)
        if device_details is not None:
            result["device_details"] = device_details

        alerts_list = self._fetch_alerts(alerts, hostname)
        result["alerts"] = alerts_list

        vulnerabilities = self._fetch_vulnerabilities(spotlight, device_id)
        result["vulnerabilities"] = vulnerabilities

        return result

    def _lookup_device_id(self, hosts, hostname: str) -> str:
        """Return first device id for hostname or error."""
        device_response = hosts.query_devices_by_filter(filter=f"hostname:'{hostname}'")
        if device_response["status_code"] != HTTPStatus.OK:
            self.error(
                f"Error getting device ID: {device_response['body'].get('errors', 'Unknown error')}"
            )

        device_ids = device_response["body"]["resources"]
        if not device_ids:
            self.error(f"No devices found with hostname: {hostname}")
        return device_ids[0]

    def _fetch_device_details(self, hosts, device_id: str) -> dict[str, Any] | None:
        """Fetch device details if available."""
        device_info_response = hosts.get_device_details(ids=device_id)
        if device_info_response["status_code"] == HTTPStatus.OK:
            return device_info_response["body"]["resources"][0]
        return None

    def _fetch_alerts(self, alerts, hostname: str) -> list[dict[str, Any]]:
        """Fetch and filter alerts for hostname."""
        alert_response = alerts.query_alerts(
            filter=(
                f"device.hostname:'{hostname}'+product:['epp']+"
                f"(created_timestamp:>='now-{self.days_before}d'+created_timestamp:<'now')"
            )
        )
        filtered_alerts: list[dict[str, Any]] = []
        if alert_response["status_code"] == HTTPStatus.OK:
            alert_ids = alert_response["body"]["resources"]
            if alert_ids:
                alerts_info_response = alerts.get_alerts(ids=alert_ids)
                if alerts_info_response["status_code"] == HTTPStatus.OK:
                    alerts_info = alerts_info_response["body"]["resources"]
                    for alert in alerts_info:
                        filtered_alert = {key: alert.get(key) for key in self.alert_fields}
                        filtered_alerts.append(filtered_alert)
        return filtered_alerts

    def _fetch_vulnerabilities(self, spotlight, device_id: str) -> list[dict[str, Any]]:
        """Fetch vulnerabilities for device and return filtered details."""
        vuln_response = spotlight.query_vulnerabilities_combined(
            parameters={"filter": f"aid:'{device_id}'+status:!'closed'"}
        )

        vuln_details: list[dict[str, Any]] = []
        if vuln_response["status_code"] == HTTPStatus.OK:
            host_vulns = vuln_response["body"]["resources"]
            products_with_vulns: dict[str, list[str]] = {}

            for vuln in host_vulns:
                product_name = vuln["apps"][0]["product_name_normalized"]
                vuln_id = vuln["id"]
                products_with_vulns.setdefault(product_name, []).append(vuln_id)

            for vuln_id in [vid for vids in products_with_vulns.values() for vid in vids]:
                vuln_request = spotlight.get_vulnerabilities(vuln_id)
                if vuln_request["status_code"] == HTTPStatus.OK:
                    data = vuln_request["body"]["resources"][0]
                    filtered_data = self._filter_dict(data, self.vuln_fields)
                    vuln_details.append(filtered_data)

        return vuln_details

    def _determine_verdict(self, analysis_result) -> str:
        """Determine verdict from sandbox analysis results."""
        if not analysis_result or "resources" not in analysis_result:
            return "unknown"

        resources = analysis_result["resources"]
        if not resources:
            return "unknown"

        verdict = resources[0].get("verdict", "unknown")
        if verdict == "suspicious":
            return "suspicious"
        if verdict == "malicious":
            return "malicious"
        if verdict == "no specific threat":
            return "safe"
        return "info"

    def _filter_dict(self, data: dict[str, Any], keys: list[str]) -> dict[str, Any]:
        """Filter dictionary based on specified keys with dot notation support."""
        filtered: dict[str, Any] = {}
        parts_three = 3
        parts_two = 2
        for key in keys:
            parts = key.split(".")
            if len(parts) == parts_three:
                main_key, sub_key, sub_sub_key = parts
                if main_key in data and sub_key in data[main_key]:
                    filtered.setdefault(main_key, {}).setdefault(sub_key, [])
                    for entity in data[main_key][sub_key]:
                        filtered[main_key][sub_key].append({sub_sub_key: entity[sub_sub_key]})
            elif len(parts) == parts_two:
                main_key, sub_key = parts
                if main_key in data and sub_key in data[main_key]:
                    filtered.setdefault(main_key, {})[sub_key] = data[main_key][sub_key]
            elif len(parts) == 1:
                main_key = parts[0]
                if main_key in data:
                    filtered[main_key] = data[main_key]
        return filtered

    def run(self) -> AnalyzerReport:
        """Execute analysis and print a compact JSON report."""
        report = self.execute()
        # Print the report in JSON format to stdout, guarding against non-serializable mocks
        try:
            print(json.dumps(report.full_report, ensure_ascii=False))
        except TypeError:
            # Fallback for test environments where full_report may be a Mock
            print(json.dumps({"success": report.success}, ensure_ascii=False))
        return report
