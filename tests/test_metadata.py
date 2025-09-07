from __future__ import annotations

import json
from typing import Any

import pytest

from sentineliqsdk.models import WorkerConfig, WorkerInput
from sentineliqsdk.responders.kafka_rest import KafkaResponder
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder
from sentineliqsdk.responders.smtp_gmail import GmailSmtpResponder
from sentineliqsdk.responders.smtp_outlook import OutlookSmtpResponder
from sentineliqsdk.responders.webhook import WebhookResponder
from sentineliqsdk.analyzers.shodan import ShodanAnalyzer
from sentineliqsdk.analyzers.axur import AxurAnalyzer


REQUIRED_META_KEYS = {
    "Name",
    "Description",
    "Author",
    "License",
    "pattern",
    "doc_pattern",
    "doc",
    "VERSION",
}


def _assert_metadata(full: dict[str, Any]) -> None:
    assert "metadata" in full and isinstance(full["metadata"], dict)
    missing = REQUIRED_META_KEYS - set(full["metadata"].keys())
    assert not missing, f"Missing metadata keys: {missing}"


def test_metadata_in_responders_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    # Webhook (dry run)
    inp = WorkerInput(
        data_type="url",
        data="https://example.com/hook",
        config=WorkerConfig(params={"webhook": {"method": "GET"}}),
    )
    rep = WebhookResponder(inp).execute()
    _assert_metadata(rep.full_report)

    # Kafka REST (dry run)
    inp = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(params={"kafka": {"base_url": "http://x", "topic": "t"}}),
    )
    rep = KafkaResponder(inp).execute()
    _assert_metadata(rep.full_report)

    # RabbitMQ HTTP (dry run)
    inp = WorkerInput(
        data_type="other",
        data="hello",
        config=WorkerConfig(
            params={
                "rabbitmq": {
                    "api_url": "http://x",
                    "exchange": "ex",
                    "vhost": "/",
                }
            }
        ),
    )
    rep = RabbitMqResponder(inp).execute()
    _assert_metadata(rep.full_report)

    # Gmail SMTP (dry run)
    inp = WorkerInput(
        data_type="mail",
        data="to@example.com",
        config=WorkerConfig(params={"email": {"subject": "s", "body": "b"}}),
    )
    rep = GmailSmtpResponder(inp).execute()
    _assert_metadata(rep.full_report)

    # Outlook SMTP (dry run)
    inp = WorkerInput(
        data_type="mail",
        data="to@example.com",
        config=WorkerConfig(params={"email": {"subject": "s", "body": "b"}}),
    )
    rep = OutlookSmtpResponder(inp).execute()
    _assert_metadata(rep.full_report)


def test_metadata_in_shodan_analyzer_report(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch client to avoid network and secrets
    class _DummyClient:
        def dns_domain(self, domain: str) -> dict[str, Any]:
            return {"domain": domain}

        def dns_resolve(self, hosts: list[str]) -> dict[str, str]:
            return {hosts[0]: "1.1.1.1"}

        def host_information(self, ip: str, minify: bool = False) -> dict[str, Any]:
            return {"ip_str": ip, "vulns": []}

    monkeypatch.setattr(ShodanAnalyzer, "_client", lambda self: _DummyClient())

    inp = WorkerInput(data_type="domain", data="example.com")
    rep = ShodanAnalyzer(inp).execute()
    _assert_metadata(rep.full_report)


def test_metadata_in_axur_analyzer_report(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch client to avoid network and secrets
    class _DummyAxur:
        def customers(self) -> dict[str, Any]:
            return {"items": []}

        def call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
            return {"method": method, "path": path, **kwargs}

    monkeypatch.setattr(AxurAnalyzer, "_client", lambda self: _DummyAxur())

    payload = {"method": "customers", "params": {}}
    inp = WorkerInput(data_type="other", data=json.dumps(payload))
    rep = AxurAnalyzer(inp).execute()
    _assert_metadata(rep.full_report)
