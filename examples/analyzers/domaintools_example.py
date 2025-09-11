#!/usr/bin/env python3
"""Example usage of DomainToolsAnalyzer.

This example demonstrates how to use the DomainToolsAnalyzer to analyze domains,
IPs, and emails using the DomainTools API.

Usage:
    python domaintools_example.py --data example.com --data-type domain --execute
    python domaintools_example.py --data 8.8.8.8 --data-type ip --execute
    python domaintools_example.py --data admin@example.com --data-type mail --execute

    # Dynamic method calling
    python domaintools_example.py --data example.com --data-type domain --method iris_enrich --execute

    # JSON payload for advanced usage
    python domaintools_example.py --data '{"method":"iris_enrich","params":{"domains":["example.com"]}}' --data-type other --execute
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.domaintools import DomainToolsAnalyzer


def main() -> None:
    """Main function to demonstrate DomainToolsAnalyzer usage."""
    parser = argparse.ArgumentParser(
        description="Example usage of DomainToolsAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Data arguments
    parser.add_argument("--data", required=True, help="Data to analyze")
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["domain", "fqdn", "ip", "mail", "other"],
        help="Type of data to analyze",
    )

    # DomainTools specific arguments
    parser.add_argument("--method", help="Specific DomainTools API method to call (optional)")
    parser.add_argument("--params", help="JSON string of parameters for the method (optional)")

    # Credentials
    parser.add_argument(
        "--username", help="DomainTools API username (or set DOMAINTOOLS_USERNAME env var)"
    )
    parser.add_argument(
        "--api-key", help="DomainTools API key (or set DOMAINTOOLS_API_KEY env var)"
    )

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
        print(f"Would analyze: {args.data} (type: {args.data_type})")
        if args.method:
            print(f"Would call method: {args.method}")
        return

    # Get credentials
    import os

    username = args.username or os.getenv("DOMAINTOOLS_USERNAME")
    api_key = args.api_key or os.getenv("DOMAINTOOLS_API_KEY")

    if not username or not api_key:
        print("❌ Error: DomainTools credentials required.")
        print(
            "Set --username and --api-key, or DOMAINTOOLS_USERNAME and DOMAINTOOLS_API_KEY env vars."
        )
        sys.exit(1)

    # Prepare configuration
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        secrets={
            "domaintools": {
                "username": username,
                "api_key": api_key,
            }
        },
    )

    # Add method configuration if specified
    if args.method:
        # Create new config with method parameter
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            secrets=config.secrets,
            params={"domaintools": {"method": args.method}},
        )

        # Add params if specified
        if args.params:
            try:
                params_dict = json.loads(args.params)
                config.params["domaintools"]["params"] = params_dict
            except json.JSONDecodeError as e:
                print(f"❌ Error: Invalid JSON in --params: {e}")
                sys.exit(1)

    # Create input
    worker_input = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        tlp=2,
        pap=2,
        config=config,
    )

    try:
        print(f"🔍 Analyzing {args.data} using DomainTools...")

        # Create and run analyzer
        analyzer = DomainToolsAnalyzer(worker_input)
        report = analyzer.execute()

        # Output results
        if args.output_format == "json":
            print(json.dumps(report.full_report, indent=2, default=str))
        else:
            print_summary(report, args.verbose)

    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def print_summary(report, verbose: bool = False) -> None:
    """Print a human-readable summary of the analysis report."""
    data = report.to_dict()

    print("\n" + "=" * 60)
    print("📊 DOMAINTOOLS ANALYSIS REPORT")
    print("=" * 60)

    print(f"🎯 Observable: {data.get('observable', 'N/A')}")
    print(f"📋 Data Type: {data.get('data_type', 'N/A')}")
    print(f"⚖️  Verdict: {data.get('verdict', 'N/A').upper()}")
    print(f"🏷️  Source: {data.get('source', 'N/A')}")

    # Taxonomy information
    if data.get("taxonomy"):
        print("\n🏷️  TAXONOMY:")
        for tax in data["taxonomy"]:
            if isinstance(tax, dict):
                level = tax.get("level", "N/A")
                namespace = tax.get("namespace", "N/A")
                predicate = tax.get("predicate", "N/A")
                print(f"   • {level.upper()}: {namespace}.{predicate}")

    # Details summary
    if data.get("details"):
        details = data["details"]
        print("\n📋 ANALYSIS DETAILS:")

        # Show available endpoints
        endpoints = [k for k in details if k not in ["method", "params", "result"]]
        if endpoints:
            print(f"   • Endpoints queried: {', '.join(endpoints)}")

        # Show method if dynamic call
        if "method" in details:
            print(f"   • API Method: {details['method']}")

        # Show risk scores if available
        if "risk" in details and isinstance(details["risk"], dict):
            risk_data = details["risk"]
            if "risk_score" in risk_data:
                print(f"   • Risk Score: {risk_data['risk_score']}")

        # Show domain profile summary
        if "domain_profile" in details and isinstance(details["domain_profile"], dict):
            profile = details["domain_profile"]
            if "response" in profile and isinstance(profile["response"], dict):
                response = profile["response"]
                if "registrant" in response:
                    print("   • Domain profile data available")

        # Show reverse IP results
        if "reverse_ip" in details and isinstance(details["reverse_ip"], dict):
            reverse_ip = details["reverse_ip"]
            if "response" in reverse_ip and isinstance(reverse_ip["response"], dict):
                response = reverse_ip["response"]
                if "ip_addresses" in response:
                    ip_count = len(response["ip_addresses"])
                    print(f"   • Reverse IP: {ip_count} domains found")

    # Verbose output
    if verbose and "details" in data:
        print("\n🔍 DETAILED RESULTS:")
        print(json.dumps(data["details"], indent=2, default=str))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
