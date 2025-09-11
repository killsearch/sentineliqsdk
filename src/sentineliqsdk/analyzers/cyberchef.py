"""CyberChef Analyzer: submit input and recipe to a CyberChef server `/bake` endpoint.

Usage example:

    from sentineliqsdk import WorkerInput, WorkerConfig
    from sentineliqsdk.analyzers.cyberchef import CyberchefAnalyzer

    input_data = WorkerInput(
        data_type="other",
        data="666f6f",
        config=WorkerConfig(params={
            "cyberchef.url": "http://localhost:8000",
            "cyberchef.service": "FromHex",
        })
    )
    report = CyberchefAnalyzer(input_data).execute()

Notes
-----
- No authentication built-in. If your instance requires it, front it with a proxy.
- HTTP proxies are honored via WorkerConfig.proxy.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata

_HTTP_OK = 200


class CyberchefAnalyzer(Analyzer):
    """Call a CyberChef server to process data using a selected recipe/service.

    Configuration (via `WorkerConfig` params):
    - cyberchef.url: str (required). Base URL of CyberChef server (without trailing slash ok).
    - cyberchef.service: str (required). One of: FromHex, FromBase64, FromCharCode.
    - cyberchef.timeout: float (default: 30.0). HTTP timeout seconds.
    """

    METADATA = ModuleMetadata(
        name="CyberChef Analyzer",
        description="Processes input using a CyberChef server (e.g., FromHex/Base64/CharCode)",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cyberchef/",
        version_stage="TESTING",
    )

    def _client(self) -> httpx.Client:
        timeout = float(self.get_config("cyberchef.timeout", 30.0))
        return httpx.Client(timeout=timeout)

    def _base_url(self) -> str:
        base = self.get_config("cyberchef.url")
        if not base:
            self.error("Missing required configuration: cyberchef.url")
        assert isinstance(base, str)
        return base.rstrip("/")

    def _service(self) -> str:
        service = self.get_config("cyberchef.service")
        if not service:
            self.error("Missing required configuration: cyberchef.service")
        return str(service)

    def _build_recipe_payload(self, observable: str, service: str) -> dict[str, Any]:
        if service == "FromHex":
            return {"input": observable, "recipe": {"op": "From Hex", "args": ["Auto"]}}
        if service == "FromBase64":
            return {
                "input": observable,
                "recipe": [{"op": "From Base64", "args": ["A-Za-z0-9+/=", True]}],
            }
        if service == "FromCharCode":
            return {
                "input": observable,
                "recipe": [
                    {
                        "op": "Regular expression",
                        "args": [
                            "User defined",
                            "([0-9]{2,3}(,\\s|))+",
                            True,
                            True,
                            False,
                            False,
                            False,
                            False,
                            "List matches",
                        ],
                    },
                    {"op": "From Charcode", "args": ["Comma", 10]},
                    {
                        "op": "Regular expression",
                        "args": [
                            "User defined",
                            "([0-9]{2,3}(,\\s|))+",
                            True,
                            True,
                            False,
                            False,
                            False,
                            False,
                            "List matches",
                        ],
                    },
                    {"op": "From Charcode", "args": ["Space", 10]},
                ],
            }
        self.error(f"Unsupported cyberchef.service: {service}")
        raise RuntimeError("unreachable")

    def _decode_value(self, json_value: Any) -> str:
        """CyberChef returns an array of numbers sometimes; join into string if so."""
        if isinstance(json_value, list) and all(isinstance(x, int) for x in json_value):
            try:
                return "".join(chr(int(x)) for x in json_value)
            except Exception:
                return ""
        if isinstance(json_value, str):
            return json_value
        return json.dumps(json_value, ensure_ascii=False)

    def execute(self) -> AnalyzerReport:
        """Execute the CyberChef request and return an AnalyzerReport."""
        dtype = self.data_type
        # Accept any textual data type; default examples use "other"
        if dtype not in ("other", "hash", "uri_path", "user-agent", "domain", "fqdn", "url", "ip"):
            self.error("CyberchefAnalyzer expects textual input (e.g., data_type 'other').")

        observable = str(self.get_data())
        service = self._service()
        base = self._base_url()

        payload = self._build_recipe_payload(observable, service)
        headers = {"Content-Type": "application/json"}

        with self._client() as client:
            try:
                resp = client.post(f"{base}/bake", headers=headers, content=json.dumps(payload))
                if resp.status_code != _HTTP_OK:
                    self.error(f"CyberChef responded with {resp.status_code}: {resp.text}")
                data = resp.json()
            except httpx.HTTPError as e:
                self.error(f"HTTP error communicating with CyberChef: {e}")

        output_data = self._decode_value(data.get("value"))

        taxonomy = self.build_taxonomy(
            level="info", namespace="CyberChef", predicate=service, value="baked!"
        )

        full_report = {
            "observable": observable,
            "verdict": "info",
            "taxonomy": [taxonomy.to_dict()],
            "service": service,
            "output_data": output_data,
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        """Compatibility wrapper calling execute()."""
        return self.execute()
