#!/usr/bin/env python3
"""CrowdSec Analyzer Example.

This example demonstrates how to use the CrowdSec analyzer to get threat
intelligence data for IP addresses.

Usage:
    python crowdsec_example.py --help
    python crowdsec_example.py --ip 1.2.3.4 --execute
    python crowdsec_example.py --ip 1.2.3.4 --execute --include-dangerous
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer


def create_input_data(ip_address: str, api_key: str, execute: bool = False) -> WorkerInput:
    """Create WorkerInput for the CrowdSec analyzer.

    Args:
        ip_address: IP address to analyze
        api_key: CrowdSec API key
        execute: Whether to execute real API calls

    Returns
    -------
        Configured WorkerInput
    """
    # Use WorkerConfig.secrets for credentials (required by rules)
    secrets = {
        "crowdsec": {
            "api_key": api_key,
        }
    }

    config = WorkerConfig(
        secrets=secrets,
        auto_extract=True,
    )

    return WorkerInput(
        data_type="ip",
        data=ip_address,
        tlp=2,
        pap=2,
        config=config,
    )


def run_analysis(ip_address: str, api_key: str, execute: bool = False) -> dict[str, Any]:
    """Run CrowdSec analysis on an IP address.

    Args:
        ip_address: IP address to analyze
        api_key: CrowdSec API key
        execute: Whether to execute real API calls

    Returns
    -------
        Analysis results
    """
    if not execute:
        print("🔍 DRY RUN MODE - No real API calls will be made")
        print("Use --execute to make real API calls")
        print()

        # Return mock data for demonstration
        return {
            "observable": ip_address,
            "verdict": "safe",
            "taxonomy": [
                {
                    "level": "info",
                    "namespace": "CrowdSec",
                    "predicate": "Reputation",
                    "value": "safe",
                }
            ],
            "raw_data": {
                "reputation": "safe",
                "as_name": "Example AS",
                "ip_range_score": 0.1,
                "history": {"last_seen": "2024-01-01T00:00:00Z"},
            },
            "metadata": {
                "name": "CrowdSec CTI Analyzer",
                "description": "Analyzes IP addresses using CrowdSec's threat intelligence API",
                "version_stage": "TESTING",
            },
        }

    # Create input data
    input_data = create_input_data(ip_address, api_key, execute)

    # Run analyzer
    analyzer = CrowdSecAnalyzer(input_data=input_data)
    report = analyzer.execute()

    return report.full_report


def print_taxonomy_entries(taxonomy: list) -> None:
    """Print taxonomy entries with appropriate emojis."""
    for tax in taxonomy:
        level = tax.get("level", "info")
        predicate = tax.get("predicate", "Unknown")
        value = tax.get("value", "Unknown")

        # Color coding for levels
        if level == "malicious":
            emoji = "🔴"
        elif level == "suspicious":
            emoji = "🟡"
        elif level == "safe":
            emoji = "🟢"
        else:
            emoji = "ds"

        print(f"{emoji} {predicate}: {value}")


def print_raw_data_summary(raw_data: dict) -> None:
    """Print raw data summary."""
    if raw_data:
        print("\n📊 Raw Data Summary:")
        if "reputation" in raw_data:
            print(f"  Reputation: {raw_data['reputation']}")
        if "as_name" in raw_data:
            print(f"  AS Name: {raw_data['as_name']}")
        if "ip_range_score" in raw_data:
            print(f"  IP Range Score: {raw_data['ip_range_score']}")
        if "attack_details" in raw_data:
            print(f"  Attack Details: {len(raw_data['attack_details'])} found")
        if "behaviors" in raw_data:
            print(f"  Behaviors: {len(raw_data['behaviors'])} found")
        if "cves" in raw_data:
            print(f"  CVEs: {len(raw_data['cves'])} found")


def print_results(results: dict[str, Any], compact: bool = True) -> None:
    """Print analysis results.

    Args:
        results: Analysis results
        compact: Whether to print compact output
    """
    if compact:
        # Print compact summary
        observable = results.get("observable", "unknown")
        taxonomy = results.get("taxonomy", [])

        print(f"🔍 CrowdSec Analysis for {observable}")
        print("=" * 50)

        # Show taxonomy entries
        print_taxonomy_entries(taxonomy)

        # Show raw data summary
        raw_data = results.get("raw_data", {})
        print_raw_data_summary(raw_data)
    else:
        # Print full JSON
        print(json.dumps(results, indent=2, ensure_ascii=False))


def main() -> None:
    """Run the CrowdSec analyzer example."""
    parser = argparse.ArgumentParser(
        description="CrowdSec Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--ip",
        required=True,
        help="IP address to analyze",
    )

    parser.add_argument(
        "--api-key",
        help="CrowdSec API key (can also be set via CROWDSEC_API_KEY env var)",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real API calls (default: dry run)",
    )

    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (not applicable for this analyzer)",
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Print full JSON output instead of compact summary",
    )

    args = parser.parse_args()

    # Get API key
    api_key = args.api_key or os.environ.get("CROWDSEC_API_KEY")

    if not api_key and args.execute:
        print("❌ Error: API key is required for real execution")
        print("Provide --api-key or set CROWDSEC_API_KEY environment variable")
        sys.exit(1)

    if not api_key:
        api_key = "demo-key"  # For dry run mode

    # Validate IP address format (basic validation)
    # Constants for IP validation
    ipv4_parts = 4
    max_ipv4_octet = 255

    ip_parts = args.ip.split(".")
    if len(ip_parts) != ipv4_parts or not all(
        part.isdigit() and 0 <= int(part) <= max_ipv4_octet for part in ip_parts
    ):
        print("❌ Error: Invalid IP address format")
        sys.exit(1)

    try:
        # Run analysis
        results = run_analysis(args.ip, api_key, args.execute)

        # Print results
        print_results(results, compact=not args.full)

    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
