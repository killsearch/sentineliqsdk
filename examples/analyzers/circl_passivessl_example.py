#!/usr/bin/env python3
"""Example usage of CIRCL PassiveSSL Analyzer.

This example demonstrates how to use the CirclPassivesslAnalyzer to query
CIRCL PassiveSSL for certificate and IP relationships.

Prerequisites:
- Configure CIRCL PassiveSSL credentials in WorkerConfig.secrets
- Or use --execute flag to run with real credentials

Usage:
    python circl_passivessl_example.py --help
    python circl_passivessl_example.py --ip 1.2.3.4
    python circl_passivessl_example.py --hash a1b2c3d4e5f6789012345678901234567890abcd
    python circl_passivessl_example.py --execute --ip 1.2.3.4
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
from sentineliqsdk.analyzers.circl_passivessl import CirclPassivesslAnalyzer


def _print_taxonomy(taxonomy: list[dict]) -> None:
    """Print taxonomy information."""
    if not taxonomy:
        return
    print("Taxonomy:")
    for tax in taxonomy:
        print(
            f"  - {tax.get('namespace', 'N/A')}:{tax.get('predicate', 'N/A')} = {tax.get('value', 'N/A')} ({tax.get('level', 'N/A')})"
        )


def _print_certificates(certificates: list[dict]) -> None:
    """Print certificate information."""
    print(f"\nCertificates found: {len(certificates)}")
    if not certificates:
        return
    print("Certificate details:")
    for i, cert in enumerate(certificates[:5]):  # Show first 5
        print(f"  {i + 1}. Fingerprint: {cert.get('fingerprint', 'N/A')}")
        print(f"     Subject: {cert.get('subject', 'N/A')}")
        print()


def print_compact_result(report: Any) -> None:
    """Print a compact version of the analysis result."""
    full = report.full_report if hasattr(report, "full_report") else report

    print("=== CIRCL PassiveSSL Analysis Result ===")
    print(f"Observable: {full.get('observable', 'N/A')}")
    print(f"Verdict: {full.get('verdict', 'N/A')}")
    print(f"Data Type: {full.get('data_type', 'N/A')}")

    # Show taxonomy
    taxonomy = full.get("taxonomy", [])
    _print_taxonomy(taxonomy)

    details = full.get("details", {})

    # Handle IP query results
    if "certificates" in details:
        certificates = details.get("certificates", [])
        _print_certificates(certificates)

    # Handle certificate query results
    if "query" in details:
        query_data = details.get("query", {})
        hits = query_data.get("hits", 0)
        print(f"\nQuery hits: {hits}")

        if "seen" in query_data:
            seen_ips = query_data.get("seen", [])
            print(f"IPs seen with this certificate: {len(seen_ips)}")
            if seen_ips:
                print("Sample IPs:")
                for ip in seen_ips[:10]:  # Show first 10
                    print(f"  - {ip}")

    # Show certificate details if available
    if details.get("cert"):
        cert_data = details["cert"]
        print("\nCertificate details:")
        print(f"  Subject: {cert_data.get('subject', 'N/A')}")
        print(f"  Issuer: {cert_data.get('issuer', 'N/A')}")
        print(f"  Serial: {cert_data.get('serial', 'N/A')}")
        print(f"  Not Before: {cert_data.get('not_before', 'N/A')}")
        print(f"  Not After: {cert_data.get('not_after', 'N/A')}")

    print("=" * 50)


def main() -> None:
    """Run the CIRCL PassiveSSL analyzer example."""
    parser = argparse.ArgumentParser(
        description="CIRCL PassiveSSL Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--ip",
        help="IP address to analyze (e.g., 1.2.3.4)",
    )
    input_group.add_argument(
        "--hash",
        help="Certificate SHA1 hash to analyze (e.g., a1b2c3d4e5f6789012345678901234567890abcd)",
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

    args = parser.parse_args()

    # Determine data type and value
    if args.ip:
        data_type = "ip"
        data = args.ip
    elif args.hash:
        data_type = "hash"
        data = args.hash
    else:
        parser.error("Must specify --ip or --hash")

    # Check for credentials if executing
    if args.execute:
        print("Running with real API calls")
        print("Make sure to configure CIRCL credentials in WorkerConfig.secrets:")
        print("  secrets = {")
        print("    'circl_passivessl': {")
        print("      'username': 'your_username',")
        print("      'password': 'your_password'")
        print("    }")
        print("  }")
        print()
    else:
        print("Running in dry-run mode (no real API calls)")
        print("Use --execute to make real API calls")
        print()

    try:
        # Create input data with secrets configuration
        secrets = {}
        if args.execute:
            # In real usage, you would set these from your secure configuration
            secrets = {
                "circl_passivessl": {
                    "username": "your_username",  # Replace with actual username
                    "password": "your_password",  # Replace with actual password
                }
            }
        else:
            # Dry run mode - dummy credentials
            secrets = {
                "circl_passivessl": {
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
        analyzer = CirclPassivesslAnalyzer(input_data)

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
