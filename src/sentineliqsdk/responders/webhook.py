from __future__ import annotations

import json
import urllib.request
from typing import Any

from sentineliqsdk.models import ModuleMetadata, ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class WebhookResponder(Responder):
    """POST (or GET) to a webhook URL using stdlib only.

    Configuration via WorkerConfig.params (no environment variables):
    - Target URL: ``WorkerInput.data`` (``data_type='url'``) or params ``webhook.url``.
    - Method: ``webhook.method`` (POST|GET), default POST.
    - Headers: ``webhook.headers`` (dict)
    - Body: ``webhook.body`` (string or JSON-like dict)
    - Safety gates: ``execute=True`` and ``include_dangerous=True``
    """

    METADATA = ModuleMetadata(
        name="Webhook Responder",
        description="POST/GET to a webhook URL using stdlib",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="webhook",
        doc_pattern="MkDocs module page; customer-facing usage and API",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/webhook/",
        version_stage="STABLE",
    )

    def execute(self) -> ResponderReport:
        # Programmatic configuration via WorkerConfig.params only.
        url = str(self.get_data() or self.get_config("webhook.url", ""))
        method = str(self.get_config("webhook.method", "POST")).upper()
        headers_cfg = self.get_config("webhook.headers")
        body_raw = self.get_config("webhook.body", "")

        do_execute = _as_bool(self.get_config("execute", False))
        include_dangerous = _as_bool(self.get_config("include_dangerous", False))
        dry_run = not (do_execute and include_dangerous)

        headers: dict[str, str] = {}
        if isinstance(headers_cfg, dict):
            headers = dict(headers_cfg)

        data_bytes: bytes | None = None
        content_type = None
        if body_raw:
            try:
                parsed = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
                data_bytes = json.dumps(parsed).encode("utf-8")
                content_type = "application/json"
            except Exception:
                data_bytes = str(body_raw).encode("utf-8")
                content_type = "text/plain"

        full = {
            "action": "webhook",
            "url": url,
            "method": method,
            "headers": headers,
            "dry_run": dry_run,
            "metadata": self.METADATA.to_dict(),
        }

        if dry_run:
            return self.report(full)

        req = urllib.request.Request(url=url, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        if data_bytes is not None and content_type is not None:
            req.add_header("Content-Type", content_type)

        try:
            with urllib.request.urlopen(req, data=data_bytes, timeout=30) as resp:  # nosec B310
                full["status"] = "delivered"
                full["http_status"] = getattr(resp, "status", None)
        except Exception as exc:  # pragma: no cover - network dependent
            self.error(f"Webhook request failed: {exc}")

        return self.report(full)

    def run(self) -> None:
        self.execute()
