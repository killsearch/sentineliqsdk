#!/usr/bin/env python3
"""Axur Client Example.

This example demonstrates how to use the AxurClient directly for various
API operations including user management, ticket operations, and filters.

Usage:
    python examples/clients/axur_client_example.py --help
    python examples/clients/axur_client_example.py --execute
    python examples/clients/axur_client_example.py --execute --include-dangerous

The example runs in dry-run mode by default. Use --execute to make real API calls.
Use --include-dangerous to enable operations that create/modify data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from sentineliqsdk.clients.axur import AxurClient, RequestOptions


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


def demo_user_management(client: AxurClient, execute: bool) -> None:
    """Demonstrate user management operations."""
    print("\n🔍 User Management Operations")

    # Get customers
    customers_options = RequestOptions(dry_run=not execute)
    print_result("Customers", client.call("GET", "/customers/customers", customers_options))

    # Get users with filters
    users_options = RequestOptions(query={"pageSize": 10, "offset": 0}, dry_run=not execute)
    print_result("Users (first 10)", client.call("GET", "/identity/users", users_options))

    # Get user stream
    stream_options = RequestOptions(query={"pageSize": 5}, dry_run=not execute)
    print_result(
        "User Stream (first 5)", client.call("GET", "/identity/users/stream", stream_options)
    )


def demo_ticket_operations(client: AxurClient, execute: bool, include_dangerous: bool) -> None:
    """Demonstrate ticket operations."""
    print("\n🎫 Ticket Operations")

    # Get ticket types
    types_options = RequestOptions(dry_run=not execute)
    print_result("Ticket Types", client.call("GET", "/tickets-core/fields/types", types_options))

    # Search tickets
    search_options = RequestOptions(query={"page": 1, "pageSize": 5}, dry_run=not execute)
    print_result("Ticket Search", client.call("GET", "/tickets-api/tickets", search_options))

    # Create ticket (only if include_dangerous is True)
    if include_dangerous:
        create_options = RequestOptions(
            json_body={
                "title": "SentinelIQ Test Ticket",
                "description": "This is a test ticket created by SentinelIQ SDK example",
                "priority": "medium",
            },
            dry_run=not execute,
        )
        print_result("Create Ticket", client.call("POST", "/tickets-api/tickets", create_options))
    else:
        print("⚠️  Ticket creation skipped (use --include-dangerous to enable)")


def demo_filter_operations(client: AxurClient, execute: bool, include_dangerous: bool) -> None:
    """Demonstrate filter operations."""
    print("\n🔍 Filter Operations")

    # Create filter (only if include_dangerous is True)
    if include_dangerous:
        filter_options = RequestOptions(
            json_body={
                "name": "SentinelIQ Test Filter",
                "description": "Test filter created by SentinelIQ SDK",
                "query": "priority:high",
            },
            dry_run=not execute,
        )
        print_result(
            "Create Filter", client.call("POST", "/tickets-filters/filters/tickets", filter_options)
        )
    else:
        print("⚠️  Filter creation skipped (use --include-dangerous to enable)")


def demo_integration_feeds(client: AxurClient, execute: bool) -> None:
    """Demonstrate integration feed operations."""
    print("\n📡 Integration Feed Operations")

    # Get integration feed (using a sample ID)
    feed_options = RequestOptions(query={"dry-run": True}, dry_run=not execute)
    print_result(
        "Integration Feed (sample)",
        client.call("GET", "/integration-feed/feeds/feed/sample-feed-id", feed_options),
    )


def demo_generic_calls(client: AxurClient, execute: bool) -> None:
    """Demonstrate generic API calls."""
    print("\n🔧 Generic API Calls")

    # Example of a custom API call
    custom_options = RequestOptions(
        query={"limit": 5}, headers={"X-Custom-Header": "SentinelIQ-Example"}, dry_run=not execute
    )
    print_result("Custom API Call", client.call("GET", "/customers/customers", custom_options))


def main() -> None:
    """Run the main function."""
    parser = argparse.ArgumentParser(description="Axur Client Example")
    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry-run mode)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include operations that create/modify data",
    )
    parser.add_argument(
        "--api-token", help="Axur API token (default: from AXUR_API_TOKEN environment variable)"
    )
    parser.add_argument(
        "--base-url", default="https://api.axur.com/gateway/1.0/api", help="Base URL for Axur API"
    )

    args = parser.parse_args()

    # Get API token
    api_token = args.api_token or os.getenv("AXUR_API_TOKEN")
    if not api_token:
        print("❌ Error: Axur API token is required")
        print("Set AXUR_API_TOKEN environment variable or use --api-token")
        sys.exit(1)

    # Initialize client
    client = AxurClient(api_token=api_token, base_url=args.base_url, timeout=30.0)

    print("🚀 Axur Client Example")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN'}")
    print(f"Dangerous operations: {'ENABLED' if args.include_dangerous else 'DISABLED'}")
    print(f"Base URL: {args.base_url}")

    try:
        # Run demonstrations
        demo_user_management(client, args.execute)
        demo_ticket_operations(client, args.execute, args.include_dangerous)
        demo_filter_operations(client, args.execute, args.include_dangerous)
        demo_integration_feeds(client, args.execute)
        demo_generic_calls(client, args.execute)

        print("\n✅ Example completed successfully!")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
