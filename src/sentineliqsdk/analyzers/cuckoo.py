"""Cuckoo Sandbox analyzer: submit file/URL, wait for report, return JSON results."""

from __future__ import annotations

import os
import time
from typing import Any, Literal

import httpx

from sentineliqsdk import Analyzer
from sentineliqsdk.constants import HTTP_UNAUTHORIZED, MALSCORE_MALICIOUS, MALSCORE_SUSPICIOUS
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata


class CuckooSandboxAnalyzer(Analyzer):
    """Submit files or URLs to a Cuckoo Sandbox and fetch the JSON report.

    Configuration and secrets (via `WorkerConfig`):
    - cuckoo.url: str (required). Base URL of Cuckoo, e.g. "https://cuckoo.local/api/".
    - cuckoo.verify_ssl: bool (default: True). Verify TLS certificates.
    - cuckoo.timeout_minutes: int (default: 15). Max minutes to wait for report.
    - cuckoo.poll_interval_seconds: int (default: 60). Interval between status checks.
    - secrets["cuckoo"]["token"]: Optional API token for Authorization Bearer.
    """

    METADATA = ModuleMetadata(
        name="Cuckoo Sandbox Analyzer",
        description="Submits files or URLs to Cuckoo Sandbox and retrieves analysis results",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="file",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cuckoo/",
        version_stage="TESTING",
    )

    def _client(self) -> httpx.Client:
        """Create an authenticated HTTP client."""
        timeout = float(self.get_config("cuckoo.timeout_http", 30.0))
        verify_ssl = bool(self.get_config("cuckoo.verify_ssl", True))
        return httpx.Client(timeout=timeout, verify=verify_ssl)

    def _headers(self) -> dict[str, str]:
        """Get headers for API requests."""
        token = self.get_secret("cuckoo.token")
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _base_url(self) -> str:
        """Get the base URL for Cuckoo API calls."""
        base = self.get_config("cuckoo.url")
        if not base:
            self.error("Missing required configuration: cuckoo.url")
        assert isinstance(base, str)
        return base if base.endswith("/") else base + "/"

    def _submit_file(self, client: httpx.Client, base: str, filepath: str) -> int:
        """Submit a file to Cuckoo Sandbox."""
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            files = {"file": (filename, f)}
            resp = client.post(base + "tasks/create/file", files=files, headers=self._headers())
        if resp.status_code == HTTP_UNAUTHORIZED:
            self.error("API token is required by this Cuckoo instance.")
        data = resp.json()
        return int(data.get("task_id") or (data.get("task_ids") or [None])[0] or -1)

    def _submit_url(self, client: httpx.Client, base: str, url: str) -> int:
        """Submit a URL to Cuckoo Sandbox."""
        resp = client.post(base + "tasks/create/url", data={"url": url}, headers=self._headers())
        if resp.status_code == HTTP_UNAUTHORIZED:
            self.error("API token is required by this Cuckoo instance.")
        data = resp.json()
        return int(data.get("task_id") or -1)

    def _wait_for_report(self, client: httpx.Client, base: str, task_id: int) -> None:
        """Wait for a Cuckoo Sandbox analysis to complete."""
        max_minutes = int(self.get_config("cuckoo.timeout_minutes", 15))
        interval = int(self.get_config("cuckoo.poll_interval_seconds", 60))
        tries = 0
        max_tries = max(1, (max_minutes * 60) // max(1, interval))
        while tries <= max_tries:
            r = client.get(base + f"tasks/view/{task_id}", headers=self._headers())
            r.raise_for_status()
            status = (r.json().get("task", {}) or {}).get("status", "")
            if status == "reported":
                return
            time.sleep(interval)
            tries += 1
        self.error("CuckooSandbox analysis timed out")

    def _fetch_report(self, client: httpx.Client, base: str, task_id: int) -> dict[str, Any]:
        """Retrieve the JSON report for a completed Cuckoo Sandbox analysis."""
        r = client.get(base + f"tasks/report/{task_id}/json", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def _extract_summary(self, raw: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
        """Extract summary information from a Cuckoo Sandbox report."""
        malscore = raw.get("malscore") or (raw.get("info", {}) or {}).get("score", 0) or 0
        try:
            score = float(malscore)
        except Exception:
            score = 0.0
        level: Literal["info", "safe", "suspicious", "malicious"]
        if score >= MALSCORE_MALICIOUS:
            level = "malicious"
        elif score >= MALSCORE_SUSPICIOUS:
            level = "suspicious"
        elif score > 0:
            level = "safe"
        else:
            level = "info"

        taxonomies = [
            self.build_taxonomy(level, "Cuckoo", "Malscore", f"{score}").to_dict(),
            self.build_taxonomy(
                level,
                "Cuckoo",
                "Malfamily",
                f"{raw.get('malfamily', '')}",
            ).to_dict(),
        ]
        return level, taxonomies

    def _parse_alerts(
        self, raw: dict[str, Any]
    ) -> tuple[list[tuple[Any, Any, Any, Any]], list[tuple[Any, Any, Any, Any]]]:
        """Parse Suricata and Snort alerts from a Cuckoo Sandbox report."""
        suri_alerts: list[tuple[Any, Any, Any, Any]] = []
        snort_alerts: list[tuple[Any, Any, Any, Any]] = []
        suri = raw.get("suricata", {}) or {}
        snort = raw.get("snort", {}) or {}
        if isinstance(suri.get("alerts"), list):
            alerts = suri["alerts"]
            if any("dstport" in a for a in alerts):
                suri_alerts = [
                    (a.get("signature"), a.get("dstip"), a.get("dstport"), a.get("severity"))
                    for a in alerts
                    if "dstport" in a
                ]
            elif any("dst_port" in a for a in alerts):
                suri_alerts = [
                    (a.get("signature"), a.get("dst_ip"), a.get("dst_port"), a.get("severity"))
                    for a in alerts
                ]
        if isinstance(snort.get("alerts"), list):
            alerts = snort["alerts"]
            if any("dstport" in a for a in alerts):
                snort_alerts = [
                    (a.get("message"), a.get("dstip"), a.get("dstport"), a.get("priority"))
                    for a in alerts
                ]
            elif any("dst_port" in a for a in alerts):
                snort_alerts = [
                    (a.get("message"), a.get("dst_ip"), a.get("dst_port"), a.get("priority"))
                    for a in alerts
                ]
        return suri_alerts, snort_alerts

    def execute(self) -> AnalyzerReport:
        """Submit observable, poll for completion, retrieve report, and return it."""
        dtype = self.data_type
        if dtype not in ("file", "url"):
            self.error("CuckooSandboxAnalyzer supports only data_type 'file' or 'url'.")

        base = self._base_url()
        with self._client() as client:
            try:
                if dtype == "file":
                    filepath = str(self.get_data())
                    task_id = self._submit_file(client, base, filepath)
                else:
                    url = str(self.get_data())
                    task_id = self._submit_url(client, base, url)
                if task_id <= 0:
                    self.error("Failed to submit task to Cuckoo Sandbox")

                self._wait_for_report(client, base, task_id)
                raw = self._fetch_report(client, base, task_id)
            except httpx.HTTPError as e:
                self.error(f"HTTP error communicating with Cuckoo: {e}")

        suri_alerts, snort_alerts = self._parse_alerts(raw)
        signatures = [
            s.get("description") for s in raw.get("signatures", []) if isinstance(s, dict)
        ]
        network = raw.get("network", {}) or {}
        try:
            domains = (
                [(d.get("ip"), d.get("domain")) for d in network.get("domains", [])]
                if isinstance(network.get("domains"), list)
                else []
            )
        except TypeError:
            domains = list(network.get("domains", []) or [])
        uris = [h.get("uri") for h in network.get("http", []) if isinstance(h, dict) and "uri" in h]

        level, taxonomies = self._extract_summary(raw)
        observable = self.get_data()

        if dtype == "url":
            full_report = {
                "observable": observable,
                "verdict": level,
                "taxonomy": taxonomies,
                "signatures": signatures,
                "suricata_alerts": suri_alerts,
                "snort_alerts": snort_alerts,
                "domains": domains,
                "uri": uris,
                "malscore": raw.get("malscore") or (raw.get("info", {}) or {}).get("score"),
                "malfamily": raw.get("malfamily"),
                "file_type": "url",
                "yara": raw.get("target", {}).get("url", "-"),
                "metadata": self.METADATA.to_dict(),
            }
        else:
            target = (raw.get("target", {}) or {}).get("file", {}) or {}
            yara = []
            for y in target.get("yara", []) or []:
                if not isinstance(y, dict):
                    continue
                name = y.get("name", "")
                desc = (y.get("meta", {}) or {}).get("description")
                yara.append(f"{name} - {desc}" if desc else name)
            file_type_val = (
                "".join(target.get("type", ""))
                if isinstance(target.get("type"), list)
                else target.get("type", "")
            )
            full_report = {
                "observable": observable,
                "verdict": level,
                "taxonomy": taxonomies,
                "signatures": signatures,
                "suricata_alerts": suri_alerts,
                "snort_alerts": snort_alerts,
                "domains": domains,
                "uri": uris,
                "malscore": raw.get("malscore") or (raw.get("info", {}) or {}).get("score"),
                "malfamily": raw.get("malfamily"),
                "file_type": file_type_val,
                "yara": yara,
                "metadata": self.METADATA.to_dict(),
            }

        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
