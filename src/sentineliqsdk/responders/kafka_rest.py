from __future__ import annotations

import json
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


class KafkaResponder(Responder):
    """Publish a message to Kafka via Confluent REST Proxy.

    Environment variables:
    - ``KAFKA_REST_URL``: base URL (e.g., http://localhost:8082)
    - ``KAFKA_TOPIC``: topic name
    - ``KAFKA_HEADERS``: optional JSON dict of headers
    - ``KAFKA_REST_AUTH``: optional "user:pass" for Basic auth
    - Gates: ``SENTINELIQ_EXECUTE`` and ``SENTINELIQ_INCLUDE_DANGEROUS`` must both be true.

    The message value defaults to ``WorkerInput.data``; set ``KAFKA_VALUE`` to override.
    """

    def execute(self) -> ResponderReport:
        base = str(self.get_env("KAFKA_REST_URL", "").rstrip("/"))
        topic = str(self.get_env("KAFKA_TOPIC", ""))
        value = self.get_env("KAFKA_VALUE", self.get_data())
        headers_raw = self.get_env("KAFKA_HEADERS")
        basic_auth = self.get_env("KAFKA_REST_AUTH")

        do_execute = _as_bool(self.get_env("SENTINELIQ_EXECUTE", "0"))
        include_dangerous = _as_bool(self.get_env("SENTINELIQ_INCLUDE_DANGEROUS", "0"))
        dry_run = not (do_execute and include_dangerous)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if headers_raw:
            try:
                headers.update(json.loads(headers_raw))
            except Exception:
                pass
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
            self.error(f"Kafka REST publish failed: {exc}")

        return self.report(full)

    def run(self) -> None:
        self.execute()
