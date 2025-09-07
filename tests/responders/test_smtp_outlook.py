from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.smtp_outlook import OutlookSmtpResponder


class DummySMTP:
    def __init__(self, server: str, port: int, timeout: int | None = None) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[object] = []

    def __enter__(self) -> DummySMTP:
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Exit context manager."""
        return

    def ehlo(self) -> None:
        return None

    def starttls(self) -> None:
        return None

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, msg) -> None:
        self.sent.append(msg)


def test_outlook_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guard against SMTP usage
    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", MagicMock(side_effect=AssertionError("no send expected")))

    input_data = WorkerInput(
        data_type="mail",
        data="rcpt@contoso.com",
        config=WorkerConfig(
            params={
                "email": {"from": "sender@contoso.com", "subject": "Subj", "body": "Body"},
                "execute": False,
                "include_dangerous": False,
            }
        ),
    )
    report = OutlookSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is True
    assert report.full_report["from"] == "sender@contoso.com"
    assert report.full_report["to"] == "rcpt@contoso.com"
    assert report.full_report["provider"] == "outlook_smtp"


def test_outlook_execute_success(monkeypatch: pytest.MonkeyPatch) -> None:
    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", lambda *a, **k: DummySMTP(*a, **k))

    input_data = WorkerInput(
        data_type="mail",
        data="rcpt@contoso.com",
        config=WorkerConfig(
            params={"execute": True, "include_dangerous": True},
            secrets={"outlook": {"username": "user@contoso.com", "password": "password"}},
        ),
    )
    report = OutlookSmtpResponder(input_data).execute()
    assert report.full_report["dry_run"] is False
    assert report.full_report.get("status") == "sent"


def test_outlook_execute_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import smtplib as _smtp

    monkeypatch.setattr(_smtp, "SMTP", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    input_data = WorkerInput(
        data_type="mail",
        data="rcpt@contoso.com",
        config=WorkerConfig(params={"execute": True, "include_dangerous": True}),
    )
    with pytest.raises(SystemExit):
        OutlookSmtpResponder(input_data).execute()


def test_outlook_execute_no_login_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import smtplib as _smtp

    instances: list[DummySMTP] = []

    def _factory(*a, **k):
        obj = DummySMTP(*a, **k)
        instances.append(obj)
        return obj

    monkeypatch.setattr(_smtp, "SMTP", _factory)

    input_data = WorkerInput(
        data_type="mail",
        data="rcpt@contoso.com",
        config=WorkerConfig(params={"execute": True, "include_dangerous": True}),
    )
    OutlookSmtpResponder(input_data).run()
    assert instances
    assert instances[0].logged_in is None
