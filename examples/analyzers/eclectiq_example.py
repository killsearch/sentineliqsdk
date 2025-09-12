#!/usr/bin/env python3
r"""EclecticIQ Analyzer Example - Comprehensive demonstration of EclecticIQ Platform API methods.

This example demonstrates how to use the EclecticIQAnalyzer with various data types.
It supports both dry-run mode (default) and execution mode with --execute flag.

Usage:
    # Dry run (default) - shows what would be analyzed
    python examples/analyzers/eclectiq_example.py

    # Execute real API calls
    python examples/analyzers/eclectiq_example.py --execute

    # Include dangerous operations (if any)
    python examples/analyzers/eclectiq_example.py --execute --include-dangerous

    # Use specific data type
    python examples/analyzers/eclectiq_example.py --execute --data-type ip --data "1.2.3.4"

Examples
--------
    # Analyze IP address
    python examples/analyzers/eclectiq_example.py --execute --data-type ip --data "8.8.8.8"

    # Analyze domain
    python examples/analyzers/eclectiq_example.py --execute --data-type domain --data "example.com"

    # Analyze hash
    python examples/analyzers/eclectiq_example.py --execute --data-type hash \
        --data "d41d8cd98f00b204e9800998ecf8427e"

    # Analyze URL
    python examples/analyzers/eclectiq_example.py --execute --data-type url --data "https://example.com"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer


def create_sample_config() -> dict[str, Any]:
    """Create sample configuration for EclecticIQ API."""
    return {
        "eclectiq": {
            "name": "My EclecticIQ Instance",
            "url": "https://your-eclectiq-instance.com",
            "api_key": "your_api_key_here",
            "cert_check": True,
            "cert_path": "/path/to/cert.pem",  # Optional
            "proxy": {  # Optional
                "http": "http://proxy:8080",
                "https": "https://proxy:8080",
            },
        }
    }


def demonstrate_ip_analysis(execute: bool) -> None:
    """Demonstrate IP address analysis."""
    print("\n=== IP Address Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample IP addresses for analysis
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "192.168.1.1"]

    for ip in ips:
        print(f"\nAnalyzing IP: {ip}")
        input_data = WorkerInput(data_type="ip", data=ip, config=config)

        try:
            analyzer = EclecticIQAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if "results" in report.full_report and "entities" in report.full_report["results"]:
                    entities = report.full_report["results"]["entities"]
                    print(f"Entities found: {len(entities)}")
                    for entity in entities[:3]:  # Show first 3 entities
                        print(f"  - {entity.get('title', 'N/A')} ({entity.get('type', 'N/A')})")
            else:
                print("  [DRY RUN] Would search EclecticIQ for IP observables and related entities")
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_domain_analysis(execute: bool) -> None:
    """Demonstrate domain analysis."""
    print("\n=== Domain Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample domains for analysis
    domains = ["example.com", "google.com", "github.com", "malicious-domain.com"]

    for domain in domains:
        print(f"\nAnalyzing Domain: {domain}")
        input_data = WorkerInput(data_type="domain", data=domain, config=config)

        try:
            analyzer = EclecticIQAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if "results" in report.full_report and "entities" in report.full_report["results"]:
                    entities = report.full_report["results"]["entities"]
                    print(f"Entities found: {len(entities)}")
                    for entity in entities[:3]:  # Show first 3 entities
                        print(f"  - {entity.get('title', 'N/A')} ({entity.get('type', 'N/A')})")
            else:
                print(
                    "  [DRY RUN] Would search EclecticIQ for domain observables and related entities"
                )
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_hash_analysis(execute: bool) -> None:
    """Demonstrate hash analysis."""
    print("\n=== Hash Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample hashes for analysis
    hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty file
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty file
        "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",  # SHA256 hello world
    ]

    for hash_value in hashes:
        print(f"\nAnalyzing Hash: {hash_value}")
        input_data = WorkerInput(data_type="hash", data=hash_value, config=config)

        try:
            analyzer = EclecticIQAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if "results" in report.full_report and "entities" in report.full_report["results"]:
                    entities = report.full_report["results"]["entities"]
                    print(f"Entities found: {len(entities)}")
                    for entity in entities[:3]:  # Show first 3 entities
                        print(f"  - {entity.get('title', 'N/A')} ({entity.get('type', 'N/A')})")
            else:
                print(
                    "  [DRY RUN] Would search EclecticIQ for hash observables and related entities"
                )
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_url_analysis(execute: bool) -> None:
    """Demonstrate URL analysis."""
    print("\n=== URL Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample URLs for analysis
    urls = [
        "https://example.com",
        "http://malicious-site.com/payload",
        "https://github.com/user/repo",
        "ftp://files.example.com/download",
    ]

    for url in urls:
        print(f"\nAnalyzing URL: {url}")
        input_data = WorkerInput(data_type="url", data=url, config=config)

        try:
            analyzer = EclecticIQAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if "results" in report.full_report and "entities" in report.full_report["results"]:
                    entities = report.full_report["results"]["entities"]
                    print(f"Entities found: {len(entities)}")
                    for entity in entities[:3]:  # Show first 3 entities
                        print(f"  - {entity.get('title', 'N/A')} ({entity.get('type', 'N/A')})")
            else:
                print(
                    "  [DRY RUN] Would search EclecticIQ for URL observables and related entities"
                )
        except Exception as e:
            print(f"  Error: {e}")


def _setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="EclecticIQ Analyzer Example - Comprehensive EclecticIQ Platform API demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry run)"
    )

    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (if any)",
    )

    parser.add_argument(
        "--data-type",
        choices=["ip", "domain", "fqdn", "hash", "url", "other"],
        default="ip",
        help="Data type to analyze (default: ip)",
    )

    parser.add_argument("--data", help="Specific data to analyze (overrides default examples)")

    parser.add_argument(
        "--show-config", action="store_true", help="Show sample configuration and exit"
    )

    return parser


def _print_mode_info(execute: bool, include_dangerous: bool) -> None:
    """Print current execution mode information."""
    print("EclecticIQ Analyzer Example")
    print("=" * 30)

    if execute:
        print("🔴 EXECUTION MODE: Real API calls will be made")
        if include_dangerous:
            print("⚠️  DANGEROUS OPERATIONS: Enabled")
    else:
        print("🟡 DRY RUN MODE: No real API calls (use --execute for real calls)")

    print()


def _handle_special_commands(args: argparse.Namespace) -> bool:
    """Handle special commands that don't require analysis."""
    if args.show_config:
        print("Sample EclecticIQ Configuration:")
        print(json.dumps(create_sample_config(), indent=2))
        return True

    return False


def _analyze_data_type(args: argparse.Namespace) -> None:
    """Analyze data based on specified type."""
    if args.data:
        _analyze_custom_data(args)
    else:
        _analyze_sample_data(args)


def _analyze_sample_data(args: argparse.Namespace) -> None:
    """Analyze sample data for demonstration."""
    if args.data_type == "ip":
        demonstrate_ip_analysis(args.execute)
    elif args.data_type in {"domain", "fqdn"}:
        demonstrate_domain_analysis(args.execute)
    elif args.data_type == "hash":
        demonstrate_hash_analysis(args.execute)
    elif args.data_type == "url":
        demonstrate_url_analysis(args.execute)
    else:
        print(f"Sample analysis not implemented for data type: {args.data_type}")
        print("Use --data to specify custom data to analyze")


def _analyze_custom_data(args: argparse.Namespace) -> None:
    """Analyze custom data provided by user."""
    print(f"\n=== Custom {args.data_type.upper()} Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    input_data = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        config=config,
    )

    analyzer = EclecticIQAnalyzer(input_data)

    if args.execute:
        report = analyzer.execute()
        print("\nAnalysis Result:")
        print(f"Observable: {report.full_report['observable']}")
        print(f"Verdict: {report.full_report['verdict']}")
        print(f"Taxonomy: {json.dumps(report.full_report['taxonomy'], indent=2)}")

        if "results" in report.full_report:
            results = report.full_report["results"]
            print("\nEclecticIQ Results:")
            print(f"Instance: {results.get('name', 'N/A')}")
            print(f"URL: {results.get('url', 'N/A')}")
            print(f"Observable Type: {results.get('obs_type', 'N/A')}")
            print(f"Observable Score: {results.get('obs_score', 'N/A')}")

            if "entities" in results:
                entities = results["entities"]
                print(f"Entities found: {len(entities)}")
                for i, entity in enumerate(entities[:5], 1):  # Show first 5 entities
                    print(f"  {i}. {entity.get('title', 'N/A')} ({entity.get('type', 'N/A')})")
                    print(f"     Confidence: {entity.get('confidence', 'N/A')}")
                    print(f"     Source: {entity.get('source_name', 'N/A')}")
                    if entity.get("tags"):
                        print(f"     Tags: {', '.join(entity['tags'])}")
    else:
        print(f"\n[DRY RUN] Would analyze {args.data_type}: {args.data}")


def _print_completion_message() -> None:
    """Print completion message and usage examples."""
    print("\n" + "=" * 50)
    print("Example completed successfully!")
    print("\nFor more examples, run:")
    print("  python examples/analyzers/eclectiq_example.py --show-config")
    print(
        "  python examples/analyzers/eclectiq_example.py --execute --data-type domain --data example.com"
    )
    print(
        "  python examples/analyzers/eclectiq_example.py --execute --data-type hash --data d41d8cd98f00b204e9800998ecf8427e"
    )


def main() -> None:
    """Run the EclecticIQ analyzer example."""
    parser = _setup_argument_parser()
    args = parser.parse_args()

    _print_mode_info(args.execute, args.include_dangerous)

    if _handle_special_commands(args):
        return

    try:
        _analyze_data_type(args)
    except Exception as e:
        print(f"Error: {e}")
        if not args.execute:
            print("Note: This might be due to missing API credentials in dry run mode")
        sys.exit(1)

    _print_completion_message()


if __name__ == "__main__":
    main()
