#!/usr/bin/env python3
"""
Cluster25 Analyzer Example.

This example demonstrates how to use the Cluster25 Analyzer to analyze
various types of indicators using the Cluster25 threat intelligence platform.

Usage:
    python cluster25_example.py --help
    python cluster25_example.py --execute --include-dangerous
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Literal

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cluster25 import Cluster25Analyzer


def create_config(secrets: dict[str, Any]) -> WorkerConfig:
    """Create WorkerConfig with Cluster25 settings."""
    return WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        # Cluster25 specific configuration
        params={
            "cluster25.base_url": "https://api.cluster25.com",
            "cluster25.timeout": 30,
            "cluster25.max_retries": 3,
        },
        secrets=secrets,
    )


def analyze_indicator(
    data_type: Literal[
        "ip",
        "url",
        "domain",
        "fqdn",
        "hash",
        "mail",
        "user-agent",
        "uri_path",
        "registry",
        "file",
        "other",
        "asn",
        "cve",
        "ip_port",
        "mac",
        "cidr",
    ],
    data: str,
    execute: bool = False,
    include_dangerous: bool = False,
) -> None:
    """Analyze a single indicator using Cluster25."""
    # Configuration for Cluster25 API
    secrets = {
        "cluster25": {"client_id": "your_client_id_here", "client_key": "your_client_key_here"}
    }

    if not execute:
        print("🔍 DRY RUN MODE - No actual API calls will be made")
        print("   Use --execute to make real API calls")
        print()

    if not include_dangerous:
        print("⚠️  SAFE MODE - Dangerous operations are disabled")
        print("   Use --include-dangerous to enable all operations")
        print()

    # Create input data
    input_data = WorkerInput(
        data_type=data_type, data=data, tlp=2, pap=2, config=create_config(secrets)
    )

    print(f"🔍 Analyzing {data_type}: {data}")
    print("=" * 50)

    try:
        # Create and run analyzer
        analyzer = Cluster25Analyzer(input_data)

        if execute:
            # Real execution
            report = analyzer.execute()
            print_result(report)
        else:
            # Dry run - show what would be analyzed
            print("📋 Analysis would include:")
            print(f"   • Observable: {data}")
            print(f"   • Data Type: {data_type}")
            print(f"   • TLP: {input_data.tlp}")
            print(f"   • PAP: {input_data.pap}")
            print(f"   • API Endpoint: {analyzer.base_url}/investigate")
            print(f"   • Client ID: {analyzer.client_id}")
            print()
            print("💡 Use --execute to perform actual analysis")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def print_basic_info(full_report: dict) -> None:
    """Print basic analysis information."""
    print(f"✅ Observable: {full_report.get('observable', 'N/A')}")


def print_indicator_data(indicator_data: dict) -> None:
    """Print indicator data if available."""
    if indicator_data and "error" not in indicator_data:
        print(f"📈 Score: {indicator_data.get('score', 'N/A')}")
        print(f"🏷️  Type: {indicator_data.get('indicator_type', 'N/A')}")
        print(f"🔍 Indicator: {indicator_data.get('indicator', 'N/A')}")
    elif "error" in indicator_data:
        print(f"❌ Error: {indicator_data['error']}")


def print_taxonomy(taxonomy: list) -> None:
    """Print taxonomy entries."""
    if taxonomy:
        print("\n📋 Taxonomy:")
        for tax in taxonomy:
            level = tax.get("level", "info")
            namespace = tax.get("namespace", "unknown")
            predicate = tax.get("predicate", "unknown")
            value = tax.get("value", "unknown")
            print(f"   • {level.upper()}: {namespace}/{predicate} = {value}")


def print_metadata(metadata: dict) -> None:
    """Print module metadata."""
    if metadata:
        print(f"\n📝 Module: {metadata.get('Name', 'Unknown')}")
        print(f"   Version: {metadata.get('VERSION', 'Unknown')}")
        print(f"   Author: {', '.join(metadata.get('Author', []))}")


def print_artifacts_and_operations(report) -> None:
    """Print artifacts and operations if any."""
    if report.artifacts:
        print(f"\n🔍 Artifacts found: {len(report.artifacts)}")
        for artifact in report.artifacts:
            print(f"   • {artifact.data_type}: {artifact.data}")

    if report.operations:
        print(f"\n⚡ Operations: {len(report.operations)}")
        for op in report.operations:
            print(f"   • {op.operation_type}: {op.parameters}")


def print_result(report) -> None:
    """Print analysis result in a compact format."""
    print("📊 Analysis Result:")
    print("=" * 30)

    if report.success:
        full_report = report.full_report
        print_basic_info(full_report)

        indicator_data = full_report.get("indicator_data", {})
        print_indicator_data(indicator_data)

        taxonomy = full_report.get("taxonomy", [])
        print_taxonomy(taxonomy)

        metadata = full_report.get("metadata", {})
        print_metadata(metadata)

        print_artifacts_and_operations(report)
    else:
        print("❌ Analysis failed")
        if hasattr(report, "error_message"):
            print(f"   Error: {report.error_message}")


def main() -> None:
    """Run the Cluster25 analyzer example."""
    parser = argparse.ArgumentParser(
        description="Cluster25 Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run analysis
  python cluster25_example.py

  # Real analysis with API calls
  python cluster25_example.py --execute

  # Enable dangerous operations
  python cluster25_example.py --execute --include-dangerous

  # Analyze specific indicator
  python cluster25_example.py --data-type ip --data 1.2.3.4 --execute
        """,
    )

    parser.add_argument(
        "--data-type",
        choices=[
            "ip",
            "url",
            "domain",
            "fqdn",
            "hash",
            "mail",
            "user-agent",
            "uri_path",
            "registry",
            "file",
            "other",
            "asn",
            "cve",
            "ip_port",
            "mac",
            "cidr",
        ],
        default="ip",
        help="Type of data to analyze (default: ip)",
    )

    parser.add_argument("--data", default="1.2.3.4", help="Data to analyze (default: 1.2.3.4)")

    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry run)"
    )

    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )

    parser.add_argument("--json", action="store_true", help="Output raw JSON result")

    args = parser.parse_args()

    if args.json:
        # JSON output mode
        secrets = {
            "cluster25": {"client_id": "your_client_id_here", "client_key": "your_client_key_here"}
        }

        input_data = WorkerInput(
            data_type=args.data_type, data=args.data, tlp=2, pap=2, config=create_config(secrets)
        )

        analyzer = Cluster25Analyzer(input_data)

        if args.execute:
            report = analyzer.execute()
            print(json.dumps(report.full_report, ensure_ascii=False, indent=2))
        else:
            # Dry run JSON
            dry_run_data = {
                "observable": args.data,
                "data_type": args.data_type,
                "mode": "dry_run",
                "message": "Use --execute to perform actual analysis",
            }
            print(json.dumps(dry_run_data, ensure_ascii=False, indent=2))
    else:
        # Human-readable output
        analyze_indicator(
            data_type=args.data_type,
            data=args.data,
            execute=args.execute,
            include_dangerous=args.include_dangerous,
        )


if __name__ == "__main__":
    main()
