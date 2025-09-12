#!/usr/bin/env python3
"""EchoTrail Analyzer Example.

This example demonstrates how to use the EchoTrail analyzer to analyze file hashes.

Usage:
    python echotrail_example.py --data 5d41402abc4b2a76b9719d911017c592 --data-type hash --execute
    python echotrail_example.py \
        --data e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
        --data-type hash --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer


def main() -> None:
    """Demonstrate EchoTrailAnalyzer usage."""
    parser = argparse.ArgumentParser(
        description="Example usage of EchoTrailAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Data arguments
    parser.add_argument("--data", required=True, help="Hash to analyze (MD5 or SHA-256)")
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["hash"],
        help="Type of data to analyze (only hash supported)",
    )

    # Credentials
    parser.add_argument("--api-key", help="EchoTrail API key (or set ECHOTRAIL_API_KEY env var)")

    # Security gates
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real API calls (required for actual analysis)",
    )
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include potentially expensive API calls"
    )

    # Output options
    parser.add_argument(
        "--output-format", choices=["json", "summary"], default="summary", help="Output format"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Security check
    if not args.execute:
        print("🔒 Dry-run mode. Use --execute to perform real API calls.")
        print(f"Would analyze hash: {args.data}")
        return

    # Get credentials
    api_key = args.api_key or os.getenv("ECHOTRAIL_API_KEY")

    if not api_key:
        print("❌ Error: EchoTrail API key required.")
        print("Set --api-key or ECHOTRAIL_API_KEY env var.")
        sys.exit(1)

    # Prepare configuration
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        secrets={
            "echotrail": {
                "api_key": api_key,
            }
        },
    )

    # Create input
    worker_input = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        tlp=2,
        pap=2,
        config=config,
    )

    try:
        print(f"🔍 Analyzing hash {args.data} using EchoTrail...")

        # Create and run analyzer
        analyzer = EchoTrailAnalyzer(worker_input)
        report = analyzer.execute()

        # Output results
        if args.output_format == "json":
            print(json.dumps(report.full_report, indent=2, default=str))
        else:
            print_summary(report, args.verbose)

    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


def _print_header(data: dict) -> None:
    """Print report header information."""
    print("\n" + "=" * 60)
    print("📊 ECHOTRAIL ANALYSIS REPORT")
    print("=" * 60)
    print(f"🎯 Hash: {data.get('observable', 'N/A')}")
    print(f"📋 Data Type: {data.get('data_type', 'N/A')}")
    print(f"⚖️  Verdict: {data.get('verdict', 'N/A').upper()}")
    print(f"🏷️  Source: {data.get('source', 'N/A')}")


def _print_taxonomy(data: dict) -> None:
    """Print taxonomy information."""
    if not data.get("taxonomy"):
        return

    print("\n🏷️  TAXONOMY:")
    for tax in data["taxonomy"]:
        if isinstance(tax, dict):
            level = tax.get("level", "N/A")
            namespace = tax.get("namespace", "N/A")
            predicate = tax.get("predicate", "N/A")
            value = tax.get("value", "N/A")
            print(f"   • {level.upper()}: {namespace}.{predicate} = {value}")


def _print_basic_details(details: dict) -> None:
    """Print basic analysis details."""
    # Show match status
    if "matched" in details:
        status = "✅ Found" if details["matched"] else "❌ Not found"
        print(f"   • Match Status: {status}")

    # Show key metrics
    metrics = [
        ("rank", "Rank"),
        ("host_prev", "Host Prevalence"),
        ("eps", "Events Per Second"),
        ("description", "Description"),
        ("intel", "Intelligence"),
    ]

    for key, label in metrics:
        if key in details:
            print(f"   • {label}: {details[key]}")


def _print_related_counts(details: dict) -> None:
    """Print related data counts."""
    related_counts = []
    fields = ["paths", "parents", "children", "grandparents", "hashes", "network"]

    for field in fields:
        if field in details and isinstance(details[field], list):
            count = len(details[field])
            if count > 0:
                related_counts.append(f"{field}: {count}")

    if related_counts:
        print(f"   • Related Data: {', '.join(related_counts)}")


def print_summary(report, verbose: bool = False) -> None:
    """Print a human-readable summary of the analysis report."""
    data = report.to_dict()

    _print_header(data)
    _print_taxonomy(data)

    # Details summary
    if data.get("details"):
        details = data["details"]
        print("\n📋 ANALYSIS DETAILS:")
        _print_basic_details(details)
        _print_related_counts(details)

    # Verbose output
    if verbose and "details" in data:
        print("\n🔍 DETAILED RESULTS:")
        print(json.dumps(data["details"], indent=2, default=str))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
