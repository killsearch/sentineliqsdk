#!/usr/bin/env python3
"""Example usage of ElasticsearchAnalyzer.

This example demonstrates how to use the ElasticsearchAnalyzer to query
Elasticsearch clusters for security analysis and threat hunting.

Usage:
    python elasticsearch_example.py --data "192.168.1.100" --data-type ip --execute
    python elasticsearch_example.py --data "malicious.com" --data-type domain --execute
    python elasticsearch_example.py --data '{"endpoint": "_cluster/health"}' --data-type other --execute

Safety:
    - Uses --execute flag to prevent accidental execution
    - Supports dry-run mode by default
    - No dangerous operations (read-only queries)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add src to path for development
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.elasticsearch import ElasticsearchAnalyzer


def main() -> None:
    """Main function to demonstrate ElasticsearchAnalyzer usage."""
    parser = argparse.ArgumentParser(
        description="Example usage of ElasticsearchAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze an IP address
  python elasticsearch_example.py --data "192.168.1.100" --data-type ip --execute

  # Analyze a domain
  python elasticsearch_example.py --data "suspicious.com" --data-type domain --execute

  # Query cluster health
  python elasticsearch_example.py --data '{"endpoint": "_cluster/health"}' --data-type other --execute

  # Search with custom method via config
  python elasticsearch_example.py --data "malware.exe" --data-type hash --method "_search" --execute

Configuration:
  Set Elasticsearch connection details via environment or config:
  - ELASTICSEARCH_HOST: Elasticsearch host URL (required)
  - ELASTICSEARCH_USERNAME: Authentication username (optional)
  - ELASTICSEARCH_PASSWORD: Authentication password (optional)
  - ELASTICSEARCH_API_KEY: API key for authentication (optional)
        """,
    )

    # Data arguments
    parser.add_argument(
        "--data",
        required=True,
        help="Data to analyze (IP, domain, hash, etc. or JSON for custom queries)",
    )
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["ip", "domain", "url", "hash", "mail", "fqdn", "other"],
        help="Type of data being analyzed",
    )

    # Elasticsearch configuration
    parser.add_argument(
        "--host",
        help="Elasticsearch host URL (e.g., https://localhost:9200)",
    )
    parser.add_argument(
        "--username",
        help="Elasticsearch username for authentication",
    )
    parser.add_argument(
        "--password",
        help="Elasticsearch password for authentication",
    )
    parser.add_argument(
        "--api-key",
        help="Elasticsearch API key for authentication",
    )
    parser.add_argument(
        "--index",
        default="*",
        help="Elasticsearch index pattern to search (default: *)",
    )
    parser.add_argument(
        "--method",
        help="Elasticsearch API method to call dynamically",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=100,
        help="Maximum number of search results (default: 100)",
    )

    # Security and execution control
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute actual Elasticsearch queries (required for real execution)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=True,
        help="Verify SSL certificates (default: True)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # Output options
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output results in JSON format",
    )

    args = parser.parse_args()

    # Safety check
    if not args.execute:
        print("🔒 Dry-run mode. Use --execute to perform actual Elasticsearch queries.")
        print(f"Would analyze: {args.data} (type: {args.data_type})")
        if args.method:
            print(f"Would call method: {args.method}")
        return

    # Build secrets configuration
    secrets: dict[str, dict[str, str]] = {"elasticsearch": {}}

    # Host is required
    if args.host:
        secrets["elasticsearch"]["host"] = args.host
    else:
        # Try to get from environment or use default
        import os

        host = os.getenv("ELASTICSEARCH_HOST")
        if not host:
            print("❌ Error: Elasticsearch host is required. Use --host or set ELASTICSEARCH_HOST")
            sys.exit(1)
        secrets["elasticsearch"]["host"] = host

    # Optional authentication
    if args.username:
        secrets["elasticsearch"]["username"] = args.username
    if args.password:
        secrets["elasticsearch"]["password"] = args.password
    if args.api_key:
        secrets["elasticsearch"]["api_key"] = args.api_key

    # Build configuration
    config_dict = {
        "elasticsearch": {
            "index": args.index,
            "max_results": args.max_results,
            "timeout": args.timeout,
            "verify_ssl": args.verify_ssl and not args.no_verify_ssl,
        }
    }

    # Add method if specified
    if args.method:
        config_dict["elasticsearch"]["method"] = args.method

    # Create WorkerConfig
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        secrets=secrets,
        params=config_dict,
    )

    # Create WorkerInput
    worker_input = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        filename=None,
        tlp=2,
        pap=2,
        config=config,
    )

    try:
        print(f"🔍 Analyzing {args.data} (type: {args.data_type})...")

        # Create and run analyzer
        analyzer = ElasticsearchAnalyzer(worker_input)
        report = analyzer.execute()

        if args.json_output:
            # Output raw JSON
            print(json.dumps(report.full_report, indent=2, default=str))
        else:
            # Pretty print results
            print("\n📊 Analysis Results:")
            print(f"   Observable: {report.full_report['observable']}")
            print(f"   Verdict: {report.full_report['verdict']}")
            print(f"   Source: {report.full_report.get('source', 'N/A')}")

            if args.verbose and "details" in report.full_report:
                print("\n🔍 Detailed Results:")
                details = report.full_report["details"]

                if "analysis" in details:
                    analysis = details["analysis"]
                    print(f"   Total hits: {analysis.get('total_hits', 0)}")
                    print(f"   Analyzed hits: {analysis.get('analyzed_hits', 0)}")

                    indicators = analysis.get("security_indicators", {})
                    if any(indicators.values()):
                        print("\n⚠️  Security Indicators:")
                        for indicator, count in indicators.items():
                            if count > 0:
                                print(f"   {indicator.replace('_', ' ').title()}: {count}")

                if "result" in details:
                    print("\n📋 API Response:")
                    result = details["result"]
                    if isinstance(result, dict):
                        for key, value in list(result.items())[:5]:  # Show first 5 keys
                            print(
                                f"   {key}: {str(value)[:100]}{'...' if len(str(value)) > 100 else ''}"
                            )

            # Show taxonomy
            if hasattr(report, "taxonomy") and report.taxonomy:
                print("\n🏷️  Taxonomy:")
                for tax in report.taxonomy:
                    if isinstance(tax, dict):
                        level = tax.get("level", "unknown")
                        namespace = tax.get("namespace", "unknown")
                        predicate = tax.get("predicate", "unknown")
                        print(f"   {level}:{namespace}:{predicate}")

        print("\n✅ Analysis completed successfully!")

    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
