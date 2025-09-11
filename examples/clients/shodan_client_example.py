#!/usr/bin/env python3
"""Shodan Client Example.

This example demonstrates how to use the ShodanClient directly for various
API operations including host information, search, scanning, and alerts.

Usage:
    python examples/clients/shodan_client_example.py --help
    python examples/clients/shodan_client_example.py --execute
    python examples/clients/shodan_client_example.py --execute --include-dangerous

The example runs in dry-run mode by default. Use --execute to make real API calls.
Use --include-dangerous to enable operations that create/modify data (scans, alerts).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from sentineliqsdk.clients.shodan import ShodanClient


def print_result(title: str, result: Any) -> None:
    """Print a formatted result."""
    print(f"\n=== {title} ===")
    if result is None:
        print("No result")
    elif isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif isinstance(result, list):
        print(f"List with {len(result)} items:")
        max_items_to_show = 3
        for i, item in enumerate(result[:max_items_to_show]):  # Show first 3 items
            print(f"  [{i}]: {json.dumps(item, ensure_ascii=False)}")
        if len(result) > max_items_to_show:
            print(f"  ... and {len(result) - max_items_to_show} more items")
    else:
        print(str(result))


def demo_basic_info(client: ShodanClient, execute: bool) -> None:
    """Demonstrate basic information operations."""
    print("\n📊 Basic Information")

    # Get your public IP (doesn't require authentication)
    try:
        print_result("My Public IP", client.tools_myip())
    except Exception as e:
        print(f"⚠️  My Public IP: Error - {e}")

    # Get API information (requires authentication)
    if execute:
        try:
            print_result("API Information", client.api_info())
        except Exception as e:
            print(f"⚠️  API Information: Error - {e}")
    else:
        print("⚠️  API Information: Skipped (requires authentication)")

    # Get available ports and protocols (require authentication)
    if execute:
        try:
            print_result("Available Ports", client.ports())
        except Exception as e:
            print(f"⚠️  Available Ports: Error - {e}")

        try:
            print_result("Available Protocols", client.protocols())
        except Exception as e:
            print(f"⚠️  Available Protocols: Error - {e}")
    else:
        print("⚠️  Available Ports: Skipped (requires authentication)")
        print("⚠️  Available Protocols: Skipped (requires authentication)")


def demo_host_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate host information operations."""
    print("\n🖥️  Host Operations")

    if execute:
        try:
            # Get host information for Google DNS
            print_result("Host Information (8.8.8.8)", client.host_information("8.8.8.8"))
        except Exception as e:
            print(f"⚠️  Host Information: Error - {e}")

        try:
            # Search for Apache servers
            print_result("Apache Search Results", client.search_host("apache", page=1))
        except Exception as e:
            print(f"⚠️  Apache Search Results: Error - {e}")

        try:
            # Get search count
            print_result("Apache Search Count", client.search_host_count("apache"))
        except Exception as e:
            print(f"⚠️  Apache Search Count: Error - {e}")

        try:
            # Get search facets and filters
            print_result("Search Facets", client.search_host_facets())
        except Exception as e:
            print(f"⚠️  Search Facets: Error - {e}")

        try:
            print_result("Search Filters", client.search_host_filters())
        except Exception as e:
            print(f"⚠️  Search Filters: Error - {e}")

        try:
            # Get search tokens
            print_result("Search Tokens", client.search_host_tokens("apache port:80"))
        except Exception as e:
            print(f"⚠️  Search Tokens: Error - {e}")
    else:
        print("⚠️  Host operations skipped (require authentication)")


def demo_scanning_operations(client: ShodanClient, execute: bool, include_dangerous: bool) -> None:
    """Demonstrate scanning operations."""
    print("\n🔍 Scanning Operations")

    if execute:
        try:
            # Get existing scans
            print_result("Existing Scans", client.scans())
        except Exception as e:
            print(f"⚠️  Existing Scans: Error - {e}")

        # Start scan (only if include_dangerous is True)
        if include_dangerous:
            try:
                print_result("Start Scan", client.scan("8.8.8.8,1.1.1.1"))
            except Exception as e:
                print(f"⚠️  Start Scan: Error - {e}")

            try:
                print_result("Internet Scan", client.scan_internet(port=80, protocol="http"))
            except Exception as e:
                print(f"⚠️  Internet Scan: Error - {e}")
        else:
            print("⚠️  Scan creation skipped (use --include-dangerous to enable)")
    else:
        print("⚠️  Scanning operations skipped (require authentication)")


def demo_alert_operations(client: ShodanClient, execute: bool, include_dangerous: bool) -> None:
    """Demonstrate alert operations."""
    print("\n🚨 Alert Operations")

    if execute:
        try:
            # Get existing alerts
            print_result("Existing Alerts", client.alerts())
        except Exception as e:
            print(f"⚠️  Existing Alerts: Error - {e}")

        try:
            # Get alert triggers
            print_result("Alert Triggers", client.alert_triggers())
        except Exception as e:
            print(f"⚠️  Alert Triggers: Error - {e}")

        # Create alert (only if include_dangerous is True)
        if include_dangerous:
            try:
                print_result(
                    "Create Alert",
                    client.alert_create(
                        name="SentinelIQ Test Alert",
                        ips=["8.8.8.8", "1.1.1.1"],
                        expires=3600,  # 1 hour
                    ),
                )
            except Exception as e:
                print(f"⚠️  Create Alert: Error - {e}")
        else:
            print("⚠️  Alert creation skipped (use --include-dangerous to enable)")
    else:
        print("⚠️  Alert operations skipped (require authentication)")


def demo_dns_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate DNS operations."""
    print("\n🌐 DNS Operations")

    if execute:
        try:
            # Get DNS domain information
            print_result("DNS Domain Info (google.com)", client.dns_domain("google.com"))
        except Exception as e:
            print(f"⚠️  DNS Domain Info: Error - {e}")

        try:
            # Resolve hostnames
            print_result("DNS Resolve", client.dns_resolve(["google.com", "github.com"]))
        except Exception as e:
            print(f"⚠️  DNS Resolve: Error - {e}")

        try:
            # Reverse DNS lookup
            print_result("Reverse DNS", client.dns_reverse(["8.8.8.8", "1.1.1.1"]))
        except Exception as e:
            print(f"⚠️  Reverse DNS: Error - {e}")
    else:
        print("⚠️  DNS operations skipped (require authentication)")


def demo_directory_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate directory operations."""
    print("\n📁 Directory Operations")

    if execute:
        try:
            # Get queries
            print_result("Queries", client.queries(page=1, sort="votes", order="desc"))
        except Exception as e:
            print(f"⚠️  Queries: Error - {e}")

        try:
            # Search queries
            print_result("Query Search", client.query_search("apache", page=1))
        except Exception as e:
            print(f"⚠️  Query Search: Error - {e}")

        try:
            # Get query tags
            print_result("Query Tags", client.query_tags(size=20))
        except Exception as e:
            print(f"⚠️  Query Tags: Error - {e}")
    else:
        print("⚠️  Directory operations skipped (require authentication)")


def demo_notifier_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate notifier operations."""
    print("\n📧 Notifier Operations")

    if execute:
        try:
            # Get notifiers
            print_result("Notifiers", client.notifiers())
        except Exception as e:
            print(f"⚠️  Notifiers: Error - {e}")

        try:
            # Get notifier providers
            print_result("Notifier Providers", client.notifier_providers())
        except Exception as e:
            print(f"⚠️  Notifier Providers: Error - {e}")
    else:
        print("⚠️  Notifier operations skipped (require authentication)")


def demo_account_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate account operations."""
    print("\n👤 Account Operations")

    if execute:
        try:
            # Get account profile
            print_result("Account Profile", client.account_profile())
        except Exception as e:
            print(f"⚠️  Account Profile: Error - {e}")
    else:
        print("⚠️  Account operations skipped (require authentication)")


def demo_utility_operations(client: ShodanClient, execute: bool) -> None:
    """Demonstrate utility operations."""
    print("\n🛠️  Utility Operations")

    if execute:
        try:
            # Get HTTP headers tool
            print_result("HTTP Headers Tool", client.tools_httpheaders())
        except Exception as e:
            print(f"⚠️  HTTP Headers Tool: Error - {e}")
    else:
        print("⚠️  Utility operations skipped (require authentication)")


def main() -> None:
    """Run the main function."""
    parser = argparse.ArgumentParser(description="Shodan Client Example")
    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry-run mode)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include operations that create/modify data (scans, alerts)",
    )
    parser.add_argument(
        "--api-key", help="Shodan API key (default: from SHODAN_API_KEY environment variable)"
    )
    parser.add_argument(
        "--base-url", default="https://api.shodan.io", help="Base URL for Shodan API"
    )
    parser.add_argument(
        "--ip", default="8.8.8.8", help="IP address to use for host information demo"
    )

    args = parser.parse_args()

    # Get API key
    api_key = args.api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("❌ Error: Shodan API key is required")
        print("Set SHODAN_API_KEY environment variable or use --api-key")
        sys.exit(1)

    # Initialize client
    client = ShodanClient(api_key=api_key, base_url=args.base_url, timeout=30.0)

    print("🚀 Shodan Client Example")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN'}")
    print(f"Dangerous operations: {'ENABLED' if args.include_dangerous else 'DISABLED'}")
    print(f"Base URL: {args.base_url}")
    print(f"Demo IP: {args.ip}")

    try:
        # Run demonstrations
        demo_basic_info(client, args.execute)
        demo_host_operations(client, args.execute)
        demo_scanning_operations(client, args.execute, args.include_dangerous)
        demo_alert_operations(client, args.execute, args.include_dangerous)
        demo_dns_operations(client, args.execute)
        demo_directory_operations(client, args.execute)
        demo_notifier_operations(client, args.execute)
        demo_account_operations(client, args.execute)
        demo_utility_operations(client, args.execute)

        print("\n✅ Example completed successfully!")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
