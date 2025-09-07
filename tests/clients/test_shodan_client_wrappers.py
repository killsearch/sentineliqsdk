from __future__ import annotations

from typing import Any

from sentineliqsdk.clients.shodan import ShodanClient


def _create_mock_client(monkeypatch) -> tuple[ShodanClient, list[tuple[str, str, dict[str, Any]]]]:
    """Create a mock ShodanClient for testing."""
    captured: list[tuple[str, str, dict[str, Any]]] = []

    def fake_request(self, method, path, options=None, **kwargs):
        captured.append((method, path, kwargs))
        return {"ok": True}

    monkeypatch.setattr(ShodanClient, "_request", fake_request)
    return ShodanClient(api_key="k"), captured


def test_host_search_methods(monkeypatch) -> None:
    """Test host and search related methods."""
    c, captured = _create_mock_client(monkeypatch)

    c.host_information("1.1.1.1", history=True, minify=True)
    c.search_host_count("port:80")
    c.search_host("port:80", page=1, facets="os:linux", minify=True)
    c.search_host_facets()
    c.search_host_filters()
    c.search_host_tokens("ssl")
    c.ports()
    c.protocols()

    assert len(captured) == 8


def test_scanning_methods(monkeypatch) -> None:
    """Test scanning related methods."""
    c, captured = _create_mock_client(monkeypatch)

    c.scan("8.8.8.8")
    c.scan_internet(443, "https")
    c.scans()
    c.scan_by_id("scanid")

    assert len(captured) == 4


def test_alert_notifier_methods(monkeypatch) -> None:
    """Test alert and notifier related methods."""
    c, captured = _create_mock_client(monkeypatch)

    c.alert_create("name", ["1.1.1.1"], expires=60)
    c.alert_info("aid")
    c.alert_delete("aid")
    c.alert_edit("aid", ["8.8.8.8"])
    c.alerts()
    c.alert_triggers()
    c.alert_enable_trigger("aid", "compromised")
    c.alert_disable_trigger("aid", "compromised")
    c.alert_whitelist_service("aid", "open", 80)
    c.alert_unwhitelist_service("aid", "open", 80)
    c.alert_add_notifier("aid", "nid")
    c.alert_remove_notifier("aid", "nid")
    c.notifiers()
    c.notifier_providers()
    c.notifier_create("slack", {"url": "http://"})
    c.notifier_delete("nid")
    c.notifier_get("nid")
    c.notifier_update("nid", "slack", {"url": "http://"})

    assert len(captured) == 18


def test_other_api_methods(monkeypatch) -> None:
    """Test other API methods (queries, data, org, account, DNS, tools)."""
    c, captured = _create_mock_client(monkeypatch)

    # Query directory
    c.queries()
    c.query_search("port:22", page=1)
    c.query_tags(size=10)
    # Data
    c.data_datasets()
    c.data_dataset("name")
    # Org
    c.org()
    c.org_member_update("user@example.com")
    c.org_member_remove("user@example.com")
    # Account
    c.account_profile()
    # DNS
    c.dns_domain("example.com")
    c.dns_resolve(["example.com"])
    c.dns_reverse(["1.1.1.1"])
    # Tools/API info
    c.tools_httpheaders()
    c.tools_myip()
    c.api_info()

    assert len(captured) == 15
