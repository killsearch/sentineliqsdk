from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

from sentineliqsdk.models import ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class OutlookSmtpResponder(Responder):
    """Send an email via Outlook/Office365 SMTP.

    Configuration via environment variables:
    - ``OUTLOOK_SMTP_USER`` / ``OUTLOOK_SMTP_PASSWORD``: credentials.
    - ``EMAIL_FROM``: optional From address (defaults to username).
    - ``EMAIL_SUBJECT`` / ``EMAIL_BODY``: message content.
    - Gates: ``SENTINELIQ_EXECUTE`` and ``SENTINELIQ_INCLUDE_DANGEROUS`` must both be true.

    The target recipient is taken from ``WorkerInput.data`` (``data_type='mail'``).
    """

    SERVER = "smtp.office365.com"
    PORT = 587

    def execute(self) -> ResponderReport:
        to_addr = str(self.get_data())

        username = self.get_env("OUTLOOK_SMTP_USER")
        password = self.get_env("OUTLOOK_SMTP_PASSWORD")
        from_addr = self.get_env("EMAIL_FROM", username or "noreply@example.com")
        subject = self.get_env("EMAIL_SUBJECT", "SentinelIQ Notification")
        body = self.get_env("EMAIL_BODY", "Hello from SentinelIQ SDK.")

        do_execute = _as_bool(self.get_env("SENTINELIQ_EXECUTE", "0"))
        include_dangerous = _as_bool(self.get_env("SENTINELIQ_INCLUDE_DANGEROUS", "0"))
        dry_run = not (do_execute and include_dangerous)

        full = {
            "action": "send_email",
            "provider": "outlook_smtp",
            "server": self.SERVER,
            "port": self.PORT,
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "dry_run": dry_run,
        }

        if dry_run:
            return self.report(full)

        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(str(body))

        try:
            with smtplib.SMTP(self.SERVER, self.PORT, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(msg)
            full["status"] = "sent"
        except Exception as exc:  # pragma: no cover - network dependent
            self.error(f"Failed to send email: {exc}")

        return self.report(full)

    def run(self) -> None:
        self.execute()
