"""RabbitMQ HTTP API responder for SentinelIQ SDK."""

from __future__ import annotations

import urllib.parse
from base64 import b64encode
from typing import Any

import httpx

from sentineliqsdk.models import ModuleMetadata, ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class RabbitMqResponder(Responder):
    """Publish to RabbitMQ via HTTP API.

    Configuration via WorkerConfig (no environment variables):
    - Params: ``rabbitmq.api_url``, ``rabbitmq.vhost``, ``rabbitmq.exchange``,
      ``rabbitmq.routing_key`` (optional), ``rabbitmq.message`` (default: ``WorkerInput.data``),
      ``rabbitmq.properties`` (dict)
    - Secrets: ``rabbitmq.username``, ``rabbitmq.password``
    - Safety gates: ``execute=True`` and ``include_dangerous=True``
    """

    METADATA = ModuleMetadata(
        name="RabbitMQ HTTP Responder",
        description="Publish messages to RabbitMQ via HTTP API",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="rabbitmq",
        doc_pattern="MkDocs module page; customer-facing usage and API",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/rabbitmq_http/",
        version_stage="STABLE",
    )

    def execute(self) -> ResponderReport:
        """Execute the RabbitMQ publish operation."""
        base = str(self.get_config("rabbitmq.api_url", "").rstrip("/"))
        vhost = str(self.get_config("rabbitmq.vhost", "/"))
        exchange = str(self.get_config("rabbitmq.exchange", ""))
        routing_key = str(self.get_config("rabbitmq.routing_key", ""))
        username = str(self.get_secret("rabbitmq.username") or "")
        password = str(self.get_secret("rabbitmq.password") or "")
        message = self.get_config("rabbitmq.message", self.get_data())
        props_cfg = self.get_config("rabbitmq.properties")

        do_execute = _as_bool(self.get_config("execute", False))
        include_dangerous = _as_bool(self.get_config("include_dangerous", False))
        dry_run = not (do_execute and include_dangerous)

        url = f"{base}/api/exchanges/{urllib.parse.quote(vhost, safe='')}/{exchange}/publish"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if username or password:
            token = b64encode(f"{username}:{password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        properties: dict[str, Any] = {}
        if isinstance(props_cfg, dict):
            properties = dict(props_cfg)

        payload = {
            "properties": properties,
            "routing_key": routing_key,
            "payload": str(message),
            "payload_encoding": "string",
        }

        full = {
            "action": "publish",
            "provider": "rabbitmq_http",
            "url": url,
            "exchange": exchange,
            "routing_key": routing_key,
            "dry_run": dry_run,
            "metadata": self.METADATA.to_dict(),
        }

        if dry_run:
            return self.report(full)

        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.request("POST", url, headers=headers, json=payload)
                full["status"] = "published"
                full["http_status"] = resp.status_code
        except Exception as exc:  # pragma: no cover - network dependent
            self.error(f"RabbitMQ publish failed: {exc}")

        return self.report(full)

    def run(self) -> ResponderReport:
        """Run the responder and return ResponderReport."""
        return self.execute()
