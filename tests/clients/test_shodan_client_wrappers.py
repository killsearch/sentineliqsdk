from __future__ import annotations

from typing import Any

from sentineliqsdk.clients.shodan import ShodanClient


def test_wrappers_delegate(monkeypatch) -> None:
    captured: list[tuple[str, str, dict[str, Any]]] = []

    def fake_request(self, method, path, **kwargs):
        captured.append((method, path, kwargs))
        return {"ok": True}

    monkeypatch.setattr(ShodanClient, "_request", fake_request)
    c = ShodanClient(api_key="k")

    # Host/Host Search
    c.host_information("1.1.1.1", history=True, minify=True)
    c.search_host_count("port:80")
    c.search_host("port:80", page=1, facets="os:linux", minify=True)
    c.search_host_facets()
    c.search_host_filters()
    c.search_host_tokens("ssl")
    c.ports()
    c.protocols()
    # Scanning
    c.scan("8.8.8.8")
    c.scan_internet(443, "https")
    c.scans()
    c.scan_by_id("scanid")
    # Alerts/Notifiers
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

    assert len(captured) >= 30
