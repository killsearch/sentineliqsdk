from __future__ import annotations

import json
import urllib.request
from typing import Any

from sentineliqsdk.models import ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class WebhookResponder(Responder):
    """POST (or GET) to a webhook URL using stdlib only.

    - Target URL: ``WorkerInput.data`` (``data_type='url'``) or ``WEBHOOK_URL`` env.
    - Optional ``WEBHOOK_METHOD`` (POST|GET), default POST.
    - Optional ``WEBHOOK_HEADERS`` (JSON), e.g. '{"Authorization": "Bearer ..."}'.
    - Optional ``WEBHOOK_BODY`` (string or JSON). If JSON-like, sent as JSON.
    - Gates: ``SENTINELIQ_EXECUTE`` and ``SENTINELIQ_INCLUDE_DANGEROUS`` must both be true.
    """

    def execute(self) -> ResponderReport:
        url = str(self.get_data() or self.get_env("WEBHOOK_URL", ""))
        method = str(self.get_env("WEBHOOK_METHOD", "POST")).upper()
        headers_raw = self.get_env("WEBHOOK_HEADERS")
        body_raw = self.get_env("WEBHOOK_BODY", "")

        do_execute = _as_bool(self.get_env("SENTINELIQ_EXECUTE", "0"))
        include_dangerous = _as_bool(self.get_env("SENTINELIQ_INCLUDE_DANGEROUS", "0"))
        dry_run = not (do_execute and include_dangerous)

        headers: dict[str, str] = {}
        if headers_raw:
            try:
                headers = json.loads(headers_raw)
            except Exception:
                headers = {}

        data_bytes: bytes | None = None
        content_type = None
        if body_raw:
            try:
                parsed = json.loads(body_raw)
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
