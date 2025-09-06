"""Execute ShodanAnalyzer.run() for all supported methods.

This example iterates over all methods allowed by the analyzer’s dynamic
interface, setting SHODAN_METHOD and SHODAN_PARAMS and calling .run().

Usage:
  export SHODAN_API_KEY=...  # or pass --api-key
  python examples/analyzers/shodan_analyzer_all_methods.py           # dry-run (plan only)
  python examples/analyzers/shodan_analyzer_all_methods.py --execute # perform calls

Flags:
  --only method1,method2     run a subset
  --skip method1,method2     skip some methods
  --include-dangerous        include actions like scan/alert mutations
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.shodan import ALLOWED_METHODS, ShodanAnalyzer

SAFE_DEFAULT_PARAMS: dict[str, dict[str, Any]] = {
    # Host/search
    "host_information": {"ip": "1.1.1.1", "minify": True},
    "search_host_count": {"query": "port:80"},
    "search_host": {"query": "port:80", "page": 1, "minify": True},
    "search_host_facets": {},
    "search_host_filters": {},
    "search_host_tokens": {"query": "ssl"},
    "ports": {},
    "protocols": {},
    # Scanning (dangerous)
    "scan": {"ips": "8.8.8.8"},
    "scan_internet": {"port": 443, "protocol": "https"},
    "scans": {},
    "scan_by_id": {"scan_id": "example-scan-id"},
    # Alerts (may require org perms)
    "alert_create": {"name": "example-alert", "ips": ["1.1.1.1"]},
    "alert_info": {"alert_id": "example-alert-id"},
    "alert_delete": {"alert_id": "example-alert-id"},
    "alert_edit": {"alert_id": "example-alert-id", "ips": ["8.8.8.8"]},
    "alerts": {},
    "alert_triggers": {},
    "alert_enable_trigger": {"alert_id": "example-alert-id", "trigger": "compromised"},
    "alert_disable_trigger": {"alert_id": "example-alert-id", "trigger": "compromised"},
    "alert_whitelist_service": {
        "alert_id": "example-alert-id",
        "trigger": "open",
        "service": 80,
    },
    "alert_unwhitelist_service": {
        "alert_id": "example-alert-id",
        "trigger": "open",
        "service": 80,
    },
    "alert_add_notifier": {"alert_id": "example-alert-id", "notifier_id": "notifier-id"},
    "alert_remove_notifier": {"alert_id": "example-alert-id", "notifier_id": "notifier-id"},
    # Notifiers
    "notifiers": {},
    "notifier_providers": {},
    "notifier_create": {"provider": "slack", "args": {"url": "https://hooks.slack.com/TOKEN"}},
    "notifier_delete": {"notifier_id": "example-notifier-id"},
    "notifier_get": {"notifier_id": "example-notifier-id"},
    "notifier_update": {
        "notifier_id": "example-notifier-id",
        "provider": "slack",
        "args": {"url": "https://hooks.slack.com/TOKEN"},
    },
    # Query directory
    "queries": {"page": 1, "sort": "timestamp", "order": "desc"},
    "query_search": {"query": "port:22", "page": 1},
    "query_tags": {"size": 10},
    # Data
    "data_datasets": {},
    "data_dataset": {"dataset": "example-dataset"},
    # Org
    "org": {},
    "org_member_update": {"user": "user@example.com"},
    "org_member_remove": {"user": "user@example.com"},
    # Account
    "account_profile": {},
    # DNS
    "dns_domain": {"domain": "example.com"},
    "dns_resolve": {"hostnames": ["example.com"]},
    "dns_reverse": {"ips": ["1.1.1.1", "8.8.8.8"]},
    # Tools
    "tools_httpheaders": {},
    "tools_myip": {},
    # API info
    "api_info": {},
}


DANGEROUS_METHODS = {
    "scan",
    "scan_internet",
    "alert_create",
    "alert_delete",
    "alert_edit",
    "alert_enable_trigger",
    "alert_disable_trigger",
    "alert_whitelist_service",
    "alert_unwhitelist_service",
    "alert_add_notifier",
    "alert_remove_notifier",
    "notifier_create",
    "notifier_delete",
    "notifier_update",
    "org_member_update",
    "org_member_remove",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run ShodanAnalyzer for all supported methods")
    ap.add_argument("--api-key", dest="api_key", default=os.getenv("SHODAN_API_KEY"))
    ap.add_argument("--execute", action="store_true", help="perform API calls (else dry-run)")
    ap.add_argument("--only", default=None, help="comma-separated methods to include")
    ap.add_argument("--skip", default=None, help="comma-separated methods to skip")
    ap.add_argument(
        "--include-dangerous",
        action="store_true",
        help="include scan/alert/org mutating methods",
    )
    args = ap.parse_args(argv)

    if not args.api_key:
        print("Missing SHODAN_API_KEY (env or --api-key)")
        return 2

    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()

    # Prepare a base input; analyzer uses env-driven dynamic path first
    input_data = WorkerInput(data_type="other", data="{}")
    analyzer = ShodanAnalyzer(input_data)

    total = 0
    ok = 0
    for method in sorted(ALLOWED_METHODS):
        if only and method not in only:
            continue
        if method in skip:
            continue
        if not args.include_dangerous and method in DANGEROUS_METHODS:
            continue

        params = SAFE_DEFAULT_PARAMS.get(method, {})
        total += 1
        print(f"==> run {method} with params={params}")

        # Set env for dynamic call
        os.environ["SHODAN_METHOD"] = method
        if params:
            os.environ["SHODAN_PARAMS"] = json.dumps(params)
        else:
            os.environ.pop("SHODAN_PARAMS", None)

        if not args.execute:
            continue

        try:
            # For programmatic result, use execute(); run() performs side-effects only
            report = analyzer.execute()
            payload = {
                "success": report.success,
                "verdict": report.full_report.get("verdict"),
                "method": report.full_report.get("details", {}).get("method"),
            }
            print(json.dumps(payload, ensure_ascii=False))
            ok += 1
        except Exception as e:
            print(f"ERROR: {e}")

    print(f"\nPlanned: {total} | Executed OK: {ok if args.execute else 0}")
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
