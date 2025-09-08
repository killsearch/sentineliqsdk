"""Webhook responder for SentinelIQ SDK."""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentineliqsdk.models import ModuleMetadata, ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class WebhookResponder(Responder):
    """POST (or GET) to a webhook URL using httpx.

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
        """Execute the webhook operation."""
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

        # Build request and send using httpx
        send_headers = dict(headers)
        if data_bytes is not None and content_type is not None:
            send_headers.setdefault("Content-Type", content_type)

        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.request(
                    method,
                    url,
                    headers=send_headers,
                    content=data_bytes,
                )
                full["status"] = "delivered"
                full["http_status"] = resp.status_code
        except Exception as exc:  # pragma: no cover - network dependent
            self.error(f"Webhook request failed: {exc}")

        return self.report(full)

    def run(self) -> ResponderReport:
        """Run the responder and return ResponderReport."""
        return self.execute()
