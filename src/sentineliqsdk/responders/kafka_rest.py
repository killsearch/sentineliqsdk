from __future__ import annotations

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


class KafkaResponder(Responder):
    """Publish a message to Kafka via Confluent REST Proxy.

    Configuration via WorkerConfig (no environment variables):
    - Params: ``kafka.base_url``, ``kafka.topic``, optional ``kafka.value`` and ``kafka.headers``
    - Secrets: ``kafka.basic_auth`` ("user:pass") or ``kafka.username/password``
    - Safety gates: ``execute=True`` and ``include_dangerous=True``

    The message value defaults to ``WorkerInput.data`` when ``kafka.value`` is absent.
    """

    METADATA = ModuleMetadata(
        name="Kafka REST Responder",
        description="Publish messages to Kafka via Confluent REST Proxy",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="kafka",
        doc_pattern="MkDocs module page; customer-facing usage and API",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/kafka_rest/",
        version_stage="STABLE",
    )

    def execute(self) -> ResponderReport:
        base = str(self.get_config("kafka.base_url", "").rstrip("/"))
        topic = str(self.get_config("kafka.topic", ""))
        value = self.get_config("kafka.value", self.get_data())
        headers_cfg = self.get_config("kafka.headers")
        basic_auth = self.get_secret("kafka.basic_auth")
        if not basic_auth:
            user = self.get_secret("kafka.username") or ""
            pwd = self.get_secret("kafka.password") or ""
            if user or pwd:
                basic_auth = f"{user}:{pwd}"

        do_execute = _as_bool(self.get_config("execute", False))
        include_dangerous = _as_bool(self.get_config("include_dangerous", False))
        dry_run = not (do_execute and include_dangerous)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if isinstance(headers_cfg, dict):
            headers.update(headers_cfg)
        if basic_auth and ":" in str(basic_auth):
            user_pass = str(basic_auth).encode("utf-8")
            headers["Authorization"] = "Basic " + b64encode(user_pass).decode("ascii")

        url = f"{base}/topics/{topic}"
        payload = {"records": [{"value": value}]}

        full = {
            "action": "publish",
            "provider": "kafka_rest",
            "url": url,
            "topic": topic,
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
            self.error(f"Kafka REST publish failed: {exc}")

        return self.report(full)

    def run(self) -> None:
        self.execute()
