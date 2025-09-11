#!/usr/bin/env python3
"""Example usage of CIRCL Passive DNS Analyzer.

This example demonstrates how to use the CirclPassivednsAnalyzer to query
CIRCL Passive DNS for historical DNS records.

Prerequisites:
- Configure CIRCL Passive DNS credentials in WorkerConfig.secrets
- Or use --execute flag to run with real credentials

Usage:
    python circl_passivedns_example.py --help
    python circl_passivedns_example.py --domain example.com
    python circl_passivedns_example.py --ip 8.8.8.8
    python circl_passivedns_example.py --url https://example.com/path
    python circl_passivedns_example.py --execute --domain example.com
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

# Add the src directory to the path so we can import the SDK
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.circl_passivedns import CirclPassivednsAnalyzer


def print_compact_result(report: Any) -> None:
    """Print a compact version of the analysis result."""
    full = report.full_report if hasattr(report, "full_report") else report

    print("=== CIRCL Passive DNS Analysis Result ===")
    print(f"Observable: {full.get('observable', 'N/A')}")
    print(f"Verdict: {full.get('verdict', 'N/A')}")
    print(f"Data Type: {full.get('data_type', 'N/A')}")

    details = full.get("details", {})
    print(f"Query: {details.get('query', 'N/A')}")
    print(f"Result Count: {details.get('result_count', 0)}")

    # Show taxonomy
    taxonomy = full.get("taxonomy", [])
    if taxonomy:
        print("Taxonomy:")
        for tax in taxonomy:
            print(
                f"  - {tax.get('namespace', 'N/A')}:{tax.get('predicate', 'N/A')} = {tax.get('value', 'N/A')} ({tax.get('level', 'N/A')})"
            )

    # Show sample results (first 3)
    results = details.get("results", [])
    if results:
        print(f"\nSample Results (showing first 3 of {len(results)}):")
        for i, result in enumerate(results[:3]):
            print(f"  {i + 1}. RR Type: {result.get('rrtype', 'N/A')}")
            print(f"     RR Name: {result.get('rrname', 'N/A')}")
            print(f"     RData: {result.get('rdata', 'N/A')}")
            print(f"     Count: {result.get('count', 'N/A')}")
            if result.get("time_first"):
                print(f"     First Seen: {result.get('time_first', 'N/A')}")
            if result.get("time_last"):
                print(f"     Last Seen: {result.get('time_last', 'N/A')}")
            print()

    print("=" * 50)


def _setup_argument_parser() -> argparse.ArgumentParser:
    """Set up the argument parser with all options."""
    parser = argparse.ArgumentParser(
        description="CIRCL Passive DNS Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--domain",
        help="Domain to analyze (e.g., example.com)",
    )
    input_group.add_argument(
        "--ip",
        help="IP address to analyze (e.g., 8.8.8.8)",
    )
    input_group.add_argument(
        "--url",
        help="URL to analyze (e.g., https://example.com/path)",
    )

    # Execution options
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real API calls (requires CIRCL credentials)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON result",
    )

    return parser


def _determine_input_type(args: argparse.Namespace) -> tuple[str, str]:
    """Determine data type and value from arguments."""
    if args.domain:
        return "domain", args.domain
    if args.ip:
        return "ip", args.ip
    if args.url:
        return "url", args.url
    raise ValueError("Must specify --domain, --ip, or --url")


def _print_execution_info(execute: bool) -> None:
    """Print execution mode information."""
    if execute:
        print("Running with real API calls")
        print("Make sure to configure CIRCL credentials in WorkerConfig.secrets:")
        print("  secrets = {")
        print("    'circl_passivedns': {")
        print("      'username': 'your_username',")
        print("      'password': 'your_password'")
        print("    }")
        print("  }")
        print()
    else:
        print("Running in dry-run mode (no real API calls)")
        print("Use --execute to make real API calls")
        print()


def main() -> None:
    """Run the CIRCL Passive DNS analyzer example."""
    parser = _setup_argument_parser()
    args = parser.parse_args()

    # Determine data type and value
    data_type, data = _determine_input_type(args)

    # Check for credentials if executing
    _print_execution_info(args.execute)

    try:
        # Create input data with secrets configuration
        secrets = {}
        if args.execute:
            # In real usage, you would set these from your secure configuration
            secrets = {
                "circl_passivedns": {
                    "username": "your_username",  # Replace with actual username
                    "password": "your_password",  # Replace with actual password
                }
            }
        else:
            # Dry run mode - dummy credentials
            secrets = {
                "circl_passivedns": {
                    "username": "dry_run_user",
                    "password": "dry_run_password",
                }
            }

        input_data = WorkerInput(
            data_type=data_type,  # type: ignore
            data=data,
            tlp=2,
            pap=2,
            config=WorkerConfig(
                check_tlp=True,
                max_tlp=2,
                check_pap=True,
                max_pap=2,
                auto_extract=True,
                secrets=secrets,
            ),
        )

        # Create and run analyzer
        analyzer = CirclPassivednsAnalyzer(input_data)

        if args.execute:
            # Real execution
            report = analyzer.execute()
        else:
            # Dry run - simulate the analysis
            print(f"Would analyze {data_type}: {data}")
            print("Dry run complete - no actual API calls made")
            return

        # Output results
        if args.json:
            print(json.dumps(report.full_report, indent=2, ensure_ascii=False))
        else:
            print_compact_result(report)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
