#!/usr/bin/env python3
"""ChainAbuse Analyzer Example.

This example demonstrates how to use the ChainAbuseAnalyzer to check
blockchain addresses and URLs for malicious activity reports.

Usage:
    python examples/analyzers/chainabuse_example.py --help
    python examples/analyzers/chainabuse_example.py --execute
    python examples/analyzers/chainabuse_example.py --execute --include-dangerous

The example runs in dry-run mode by default. Use --execute to make real API calls.
Use --include-dangerous to enable operations that create/modify data.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.chainabuse import ChainAbuseAnalyzer


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
        for i, item in enumerate(result[:max_items_to_show]):
            print(f"  [{i}]: {json.dumps(item, ensure_ascii=False)}")
        if len(result) > max_items_to_show:
            print(f"  ... and {len(result) - max_items_to_show} more items")
    else:
        print(str(result))


def demo_ip_analysis(execute: bool, api_key: str) -> None:
    """Demonstrate IP address analysis."""
    print("\n🌐 IP Address Analysis")

    # Test with a known malicious IP (example)
    test_ip = "1.2.3.4"

    if execute:
        try:
            secrets = {"chainabuse": {"api_key": api_key}}
            input_data = WorkerInput(
                data_type="ip", data=test_ip, config=WorkerConfig(secrets=secrets)
            )

            analyzer = ChainAbuseAnalyzer(input_data)
            report = analyzer.execute()

            print_result(f"IP Analysis ({test_ip})", report.full_report)
        except Exception as e:
            print(f"⚠️  IP Analysis: Error - {e}")
    else:
        print("⚠️  IP Analysis: Skipped (use --execute to enable)")


def demo_url_analysis(execute: bool, api_key: str) -> None:
    """Demonstrate URL analysis."""
    print("\n🔗 URL Analysis")

    # Test with a potentially malicious URL (example)
    test_url = "https://example-malicious-site.com"

    if execute:
        try:
            secrets = {"chainabuse": {"api_key": api_key}}
            input_data = WorkerInput(
                data_type="url", data=test_url, config=WorkerConfig(secrets=secrets)
            )

            analyzer = ChainAbuseAnalyzer(input_data)
            report = analyzer.execute()

            print_result(f"URL Analysis ({test_url})", report.full_report)
        except Exception as e:
            print(f"⚠️  URL Analysis: Error - {e}")
    else:
        print("⚠️  URL Analysis: Skipped (use --execute to enable)")


def demo_domain_analysis(execute: bool, api_key: str) -> None:
    """Demonstrate domain analysis."""
    print("\n🏷️  Domain Analysis")

    # Test with a potentially malicious domain (example)
    test_domain = "malicious-example.com"

    if execute:
        try:
            secrets = {"chainabuse": {"api_key": api_key}}
            input_data = WorkerInput(
                data_type="domain", data=test_domain, config=WorkerConfig(secrets=secrets)
            )

            analyzer = ChainAbuseAnalyzer(input_data)
            report = analyzer.execute()

            print_result(f"Domain Analysis ({test_domain})", report.full_report)
        except Exception as e:
            print(f"⚠️  Domain Analysis: Error - {e}")
    else:
        print("⚠️  Domain Analysis: Skipped (use --execute to enable)")


def demo_hash_analysis(execute: bool, api_key: str) -> None:
    """Demonstrate hash/blockchain address analysis."""
    print("\n🔐 Hash/Blockchain Address Analysis")

    # Test with a potentially malicious hash/address (example)
    test_hash = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Example Bitcoin address format

    if execute:
        try:
            secrets = {"chainabuse": {"api_key": api_key}}
            input_data = WorkerInput(
                data_type="hash", data=test_hash, config=WorkerConfig(secrets=secrets)
            )

            analyzer = ChainAbuseAnalyzer(input_data)
            report = analyzer.execute()

            print_result(f"Hash Analysis ({test_hash})", report.full_report)
        except Exception as e:
            print(f"⚠️  Hash Analysis: Error - {e}")
    else:
        print("⚠️  Hash Analysis: Skipped (use --execute to enable)")


def demo_batch_analysis(execute: bool, api_key: str) -> None:
    """Demonstrate batch analysis of multiple observables."""
    print("\n📊 Batch Analysis")

    from sentineliqsdk.models import DataType

    observables: list[tuple[DataType, str]] = [
        ("ip", "8.8.8.8"),
        ("url", "https://google.com"),
        ("domain", "github.com"),
        ("hash", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),  # Example Bitcoin address
    ]

    if execute:
        results = []
        for data_type, data in observables:
            try:
                secrets = {"chainabuse": {"api_key": api_key}}
                input_data = WorkerInput(
                    data_type=data_type, data=data, config=WorkerConfig(secrets=secrets)
                )

                analyzer = ChainAbuseAnalyzer(input_data)
                report = analyzer.execute()

                results.append(
                    {
                        "data_type": data_type,
                        "data": data,
                        "verdict": report.full_report.get("verdict", "unknown"),
                        "report_count": report.full_report.get("reports", {}).get("count", 0),
                        "sanctioned": report.full_report.get("sanctioned", {}).get(
                            "sanctioned", False
                        ),
                    }
                )
            except Exception as e:
                print(f"⚠️  Batch Analysis ({data_type}:{data}): Error - {e}")

        print_result("Batch Analysis Results", results)
    else:
        print("⚠️  Batch Analysis: Skipped (use --execute to enable)")


def demo_custom_configuration(execute: bool, api_key: str) -> None:
    """Demonstrate custom configuration options."""
    print("\n⚙️  Custom Configuration")

    if execute:
        try:
            # Custom timeout configuration
            secrets = {"chainabuse": {"api_key": api_key}}
            config = WorkerConfig(
                secrets=secrets,
                params={"chainabuse": {"timeout": 60}},  # Custom timeout
                check_tlp=True,
                max_tlp=2,
                check_pap=True,
                max_pap=2,
            )

            input_data = WorkerInput(data_type="ip", data="1.1.1.1", tlp=2, pap=2, config=config)

            analyzer = ChainAbuseAnalyzer(input_data)
            report = analyzer.execute()

            print_result("Custom Configuration Analysis", report.full_report)
        except Exception as e:
            print(f"⚠️  Custom Configuration: Error - {e}")
    else:
        print("⚠️  Custom Configuration: Skipped (use --execute to enable)")


def main() -> None:
    """Run the main function."""
    parser = argparse.ArgumentParser(description="ChainAbuse Analyzer Example")
    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry-run mode)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include operations that create/modify data",
    )
    parser.add_argument(
        "--api-key",
        help="ChainAbuse API key (default: from CHAINABUSE_API_KEY environment variable)",
    )

    args = parser.parse_args()

    # Get API key
    import os

    api_key = args.api_key or os.getenv("CHAINABUSE_API_KEY")
    if not api_key and args.execute:
        print("❌ Error: ChainAbuse API key is required for execution")
        print("Set CHAINABUSE_API_KEY environment variable or use --api-key")
        sys.exit(1)

    print("🚀 ChainAbuse Analyzer Example")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN'}")
    print(f"Dangerous operations: {'ENABLED' if args.include_dangerous else 'DISABLED'}")
    if api_key:
        print(f"API Key: {'*' * (len(api_key) - 4) + api_key[-4:] if len(api_key) > 4 else '***'}")
    else:
        print("API Key: Not provided (dry-run mode)")

    try:
        # Run demonstrations
        demo_ip_analysis(args.execute, api_key or "dummy-key")
        demo_url_analysis(args.execute, api_key or "dummy-key")
        demo_domain_analysis(args.execute, api_key or "dummy-key")
        demo_hash_analysis(args.execute, api_key or "dummy-key")
        demo_batch_analysis(args.execute, api_key or "dummy-key")
        demo_custom_configuration(args.execute, api_key or "dummy-key")

        print("\n✅ Example completed successfully!")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
