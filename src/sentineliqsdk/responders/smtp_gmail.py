"""Gmail SMTP responder for SentinelIQ SDK."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

from sentineliqsdk.constants import SMTP_GMAIL_SERVER, SMTP_PORT
from sentineliqsdk.models import ModuleMetadata, ResponderReport
from sentineliqsdk.responders.base import Responder


def _as_bool(value: Any | None) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "on"}


class GmailSmtpResponder(Responder):
    """Send an email via Gmail SMTP.

    Configuration via WorkerConfig (no environment variables):
    - Secrets: ``gmail.username`` / ``gmail.password`` (App Password recommended)
    - Params: ``email.from`` (optional; defaults to username), ``email.subject``, ``email.body``
    - Safety gates: ``execute=True`` and ``include_dangerous=True``

    The target recipient is taken from ``WorkerInput.data`` (``data_type='mail'``).
    """

    SERVER = SMTP_GMAIL_SERVER
    PORT = SMTP_PORT
    METADATA = ModuleMetadata(
        name="Gmail SMTP Responder",
        description="Send an email via Gmail SMTP with STARTTLS",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="smtp",
        doc_pattern="MkDocs module page; customer-facing usage and API",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/gmail_smtp/",
        version_stage="STABLE",
    )

    def execute(self) -> ResponderReport:
        """Execute the Gmail SMTP operation."""
        to_addr = str(self.get_data())

        username = self.get_secret("gmail.username") or self.get_secret("smtp.username")
        password = self.get_secret("gmail.password") or self.get_secret("smtp.password")
        from_addr = self.get_config("email.from", username or "noreply@example.com")
        subject = self.get_config("email.subject", "SentinelIQ Notification")
        body = self.get_config("email.body", "Hello from SentinelIQ SDK.")

        do_execute = _as_bool(self.get_config("execute", False))
        include_dangerous = _as_bool(self.get_config("include_dangerous", False))
        dry_run = not (do_execute and include_dangerous)

        full = {
            "action": "send_email",
            "provider": "gmail_smtp",
            "server": self.SERVER,
            "port": self.PORT,
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "dry_run": dry_run,
            "metadata": self.METADATA.to_dict(),
        }

        if dry_run:
            return self.report(full)

        # Perform SMTP send
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

    def run(self) -> ResponderReport:
        """Run the responder and return ResponderReport."""
        return self.execute()
