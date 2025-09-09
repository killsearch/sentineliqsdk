"""Examples: call all ShodanClient methods in a single script.

Dry-run by default (prints the request plan). Use --execute to actually call
the API. Pass --api-key (no environment fallback).

This script demonstrates programmatic usage with the low-level ShodanClient.
It catches HTTP/URL errors so all calls are attempted without stopping.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from sentineliqsdk.clients.shodan import ShodanClient


def build_examples() -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
    """Return a list of (method_name, args, kwargs) covering all client methods."""
    return [
        # Host/Host Search
        ("host_information", ("1.1.1.1",), {"minify": True}),
        ("search_host_count", ("port:80",), {}),
        ("search_host", ("port:80",), {"page": 1, "minify": True}),
        ("search_host_facets", (), {}),
        ("search_host_filters", (), {}),
        ("search_host_tokens", ("ssl",), {}),
        ("ports", (), {}),
        ("protocols", (), {}),
        # Scanning
        ("scan", ("8.8.8.8,1.1.1.1",), {}),
        ("scan_internet", (443, "https"), {}),
        ("scans", (), {}),
        ("scan_by_id", ("example-scan-id",), {}),
        # Alerts
        (
            "alert_create",
            (
                "example-alert",
                ["1.1.1.1"],
            ),
            {},
        ),
        ("alert_info", ("example-alert-id",), {}),
        ("alert_delete", ("example-alert-id",), {}),
        ("alert_edit", ("example-alert-id", ["8.8.8.8"]), {}),
        ("alerts", (), {}),
        ("alert_triggers", (), {}),
        ("alert_enable_trigger", ("example-alert-id", "compromised"), {}),
        ("alert_disable_trigger", ("example-alert-id", "compromised"), {}),
        ("alert_whitelist_service", ("example-alert-id", "open", 80), {}),
        ("alert_unwhitelist_service", ("example-alert-id", "open", 80), {}),
        ("alert_add_notifier", ("example-alert-id", "example-notifier-id"), {}),
        ("alert_remove_notifier", ("example-alert-id", "example-notifier-id"), {}),
        # Notifiers
        ("notifiers", (), {}),
        ("notifier_providers", (), {}),
        ("notifier_create", ("slack", {"url": "https://hooks.slack.com/services/TOKEN"}), {}),
        ("notifier_delete", ("example-notifier-id",), {}),
        ("notifier_get", ("example-notifier-id",), {}),
        ("notifier_update", ("example-notifier-id", "slack", {"url": "https://hook"}), {}),
        # Query directory
        ("queries", (), {"page": 1, "sort": "timestamp", "order": "desc"}),
        ("query_search", ("port:22",), {"page": 1}),
        ("query_tags", (), {"size": 10}),
        # Data
        ("data_datasets", (), {}),
        ("data_dataset", ("example-dataset",), {}),
        # Org
        ("org", (), {}),
        ("org_member_update", ("user@example.com",), {}),
        ("org_member_remove", ("user@example.com",), {}),
        # Account
        ("account_profile", (), {}),
        # DNS
        ("dns_domain", ("example.com",), {}),
        ("dns_resolve", (["example.com"],), {}),
        ("dns_reverse", (["1.1.1.1", "8.8.8.8"],), {}),
        # Tools
        ("tools_httpheaders", (), {}),
        ("tools_myip", (), {}),
        # API info
        ("api_info", (), {}),
    ]


def main(argv: list[str]) -> int:
    """Run all ShodanClient methods."""
    ap = argparse.ArgumentParser(description="Call all ShodanClient methods (demo)")
    ap.add_argument("--api-key", dest="api_key", required=True)
    ap.add_argument("--base-url", dest="base_url", default="https://api.shodan.io")
    ap.add_argument("--timeout", dest="timeout", type=float, default=10.0)
    ap.add_argument("--execute", dest="execute", action="store_true", help="perform calls")
    ap.add_argument(
        "--only",
        dest="only",
        default=None,
        help="comma-separated method names to run (subset)",
    )
    ap.add_argument(
        "--skip",
        dest="skip",
        default=None,
        help="comma-separated method names to skip",
    )
    args = ap.parse_args(argv)

    # api_key is required by argparse

    client = ShodanClient(api_key=args.api_key, base_url=args.base_url, timeout=args.timeout)

    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()

    examples = build_examples()
    total = 0
    ok = 0
    for name, call_args, call_kwargs in examples:
        if only and name not in only:
            continue
        if name in skip:
            continue
        total += 1
        print(f"==> {name}(*{call_args}, **{call_kwargs})")
        if not args.execute:
            continue
        try:
            func = getattr(client, name)
            result = func(*call_args, **call_kwargs)
            try:
                pretty = json.dumps(result, ensure_ascii=False)[:2000]
                print(pretty)
            except Exception:
                print(str(result)[:2000])
            ok += 1
        except Exception as e:
            print(f"ERROR: {e}")

    print(f"\nFinished. Planned: {total} | Executed OK: {ok if args.execute else 0}")
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
