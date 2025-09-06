from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sentineliqsdk.models import WorkerInput
from sentineliqsdk.responders.smtp_outlook import OutlookSmtpResponder


class DummySMTP:
    def __init__(self, server: str, port: int, timeout: int | None = None) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[object] = []

    def __enter__(self) -> DummySMTP:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def starttls(self) -> None:
        return None

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, msg) -> None:
        self.sent.append(msg)


def test_outlook_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "0")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "0")
    monkeypatch.setenv("EMAIL_FROM", "sender@contoso.com")
    monkeypatch.setenv("EMAIL_SUBJECT", "Subj")
    monkeypatch.setenv("EMAIL_BODY", "Body")

    # Guard against SMTP usage
    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", MagicMock(side_effect=AssertionError("no send expected")))

    input_data = WorkerInput(data_type="mail", data="rcpt@contoso.com")
    report = OutlookSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["from"] == "sender@contoso.com"
    assert report.full_report["to"] == "rcpt@contoso.com"
    assert report.full_report["provider"] == "outlook_smtp"


def test_outlook_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")
    monkeypatch.setenv("OUTLOOK_SMTP_USER", "user@contoso.com")
    monkeypatch.setenv("OUTLOOK_SMTP_PASSWORD", "password")

    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", lambda *a, **k: DummySMTP(*a, **k))

    input_data = WorkerInput(data_type="mail", data="rcpt@contoso.com")
    report = OutlookSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "sent"


def test_outlook_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")

    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    input_data = WorkerInput(data_type="mail", data="rcpt@contoso.com")
    with pytest.raises(SystemExit):
        OutlookSmtpResponder(input_data).execute()


def test_outlook_execute_no_login_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELIQ_EXECUTE", "1")
    monkeypatch.setenv("SENTINELIQ_INCLUDE_DANGEROUS", "1")

    import smtplib as _smtp

    instances: list[DummySMTP] = []

    def _factory(*a, **k):
        obj = DummySMTP(*a, **k)
        instances.append(obj)
        return obj

    monkeypatch.setattr(_smtp, "SMTP", _factory)

    input_data = WorkerInput(data_type="mail", data="rcpt@contoso.com")
    OutlookSmtpResponder(input_data).run()
    assert instances and instances[0].logged_in is None
