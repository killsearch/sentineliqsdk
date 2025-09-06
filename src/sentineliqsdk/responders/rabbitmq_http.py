from __future__ import annotations

import json
import urllib.parse
import urllib.request
from base64 import b64encode
from typing import Any

from sentineliqsdk.models import ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class RabbitMqResponder(Responder):
    """Publish to RabbitMQ via HTTP API.

    Environment variables:
    - ``RABBITMQ_API_URL``: base URL (e.g., http://localhost:15672)
    - ``RABBITMQ_VHOST``: vhost (default "/")
    - ``RABBITMQ_EXCHANGE``: exchange name
    - ``RABBITMQ_ROUTING_KEY``: routing key (default "")
    - ``RABBITMQ_USERNAME`` / ``RABBITMQ_PASSWORD``: basic auth
    - ``RABBITMQ_PROPERTIES``: optional JSON properties
    - ``RABBITMQ_MESSAGE``: override message value (defaults to ``WorkerInput.data``)
    - Gates: ``SENTINELIQ_EXECUTE`` and ``SENTINELIQ_INCLUDE_DANGEROUS`` must both be true.
    """

    def execute(self) -> ResponderReport:
        base = str(self.get_env("RABBITMQ_API_URL", "").rstrip("/"))
        vhost = str(self.get_env("RABBITMQ_VHOST", "/"))
        exchange = str(self.get_env("RABBITMQ_EXCHANGE", ""))
        routing_key = str(self.get_env("RABBITMQ_ROUTING_KEY", ""))
        username = str(self.get_env("RABBITMQ_USERNAME", ""))
        password = str(self.get_env("RABBITMQ_PASSWORD", ""))
        message = self.get_env("RABBITMQ_MESSAGE", self.get_data())
        props_raw = self.get_env("RABBITMQ_PROPERTIES")

        do_execute = _as_bool(self.get_env("SENTINELIQ_EXECUTE", "0"))
        include_dangerous = _as_bool(self.get_env("SENTINELIQ_INCLUDE_DANGEROUS", "0"))
        dry_run = not (do_execute and include_dangerous)

        url = f"{base}/api/exchanges/{urllib.parse.quote(vhost, safe='')}/{exchange}/publish"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if username or password:
            token = b64encode(f"{username}:{password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        properties: dict[str, Any] = {}
        if props_raw:
            try:
                properties = json.loads(props_raw)
            except Exception:
                properties = {}

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
        }

        if dry_run:
            return self.report(full)

        req = urllib.request.Request(url=url, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        data = json.dumps(payload).encode("utf-8")

        try:
            with urllib.request.urlopen(req, data=data, timeout=30) as resp:  # nosec B310
                full["status"] = "published"
                full["http_status"] = getattr(resp, "status", None)
        except Exception as exc:  # pragma: no cover - network dependent
            self.error(f"RabbitMQ publish failed: {exc}")

        return self.report(full)

    def run(self) -> None:
        self.execute()
