from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from sentineliqsdk.models import WorkerInput
from sentineliqsdk.responders.smtp_gmail import GmailSmtpResponder


class DummySMTP:
    def __init__(self, server: str, port: int, timeout: int | None = None) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[Any] = []

    # Context manager API
    def __enter__(self) -> DummySMTP:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    # SMTP API we use
    def ehlo(self) -> None:
        return None

    def starttls(self) -> None:
        return None

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, msg) -> None:
        self.sent.append(msg)


def test_gmail_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure dry-run: gates disabled
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "0")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "0")
    monkeypatch.setenv("EMAIL_SUBJECT", "Test")
    monkeypatch.setenv("EMAIL_BODY", "Body")
    monkeypatch.setenv("EMAIL_FROM", "sender@example.com")

    # Guard against any SMTP usage
    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", MagicMock(side_effect=AssertionError("should not send")))

    input_data = WorkerInput(data_type="mail", data="rcpt@example.com")
    report = GmailSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["from"] == "sender@example.com"
    assert report.full_report["to"] == "rcpt@example.com"
    assert report.full_report["provider"] == "gmail_smtp"


def test_gmail_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    # Gates enabled and credentials provided
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("GMAIL_SMTP_USER", "user@example.com")
    monkeypatch.setenv("GMAIL_SMTP_PASSWORD", "apppass")
    monkeypatch.setenv("EMAIL_SUBJECT", "Hello")
    monkeypatch.setenv("EMAIL_BODY", "World")

    # Swap SMTP with dummy to avoid network
    import smtplib as _smtp

    dummy = DummySMTP("", 0)
    monkeypatch.setattr(_smtp, "SMTP", lambda *a, **k: DummySMTP(*a, **k))

    input_data = WorkerInput(data_type="mail", data="rcpt@example.com")
    report = GmailSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "sent"


def test_gmail_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")

    # Force SMTP to raise
    import smtplib as _smtp

    def _boom(*a, **k):
        raise RuntimeError("SMTP down")

    monkeypatch.setattr(_smtp, "SMTP", _boom)

    input_data = WorkerInput(data_type="mail", data="rcpt@example.com")
    with pytest.raises(SystemExit):
        GmailSmtpResponder(input_data).execute()


def test_gmail_execute_no_login_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Execute with gates enabled but without credentials → no login branch
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")

    import smtplib as _smtp

    instances: list[DummySMTP] = []

    def _factory(*a, **k):
        obj = DummySMTP(*a, **k)
        instances.append(obj)
        return obj

    monkeypatch.setattr(_smtp, "SMTP", _factory)

    input_data = WorkerInput(data_type="mail", data="rcpt@example.com")
    # Call run() to cover delegating path
    GmailSmtpResponder(input_data).run()
    # Ensure no login happened
    assert instances and instances[0].logged_in is None
