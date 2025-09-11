#!/usr/bin/env python3
r"""Censys Analyzer Example - Comprehensive demonstration of all Censys Platform API methods.

This example demonstrates how to use the CensysAnalyzer with various data types and methods.
It supports both dry-run mode (default) and execution mode with --execute flag.

Usage:
    # Dry run (default) - shows what would be analyzed
    python examples/analyzers/censys_example.py

    # Execute real API calls
    python examples/analyzers/censys_example.py --execute

    # Include dangerous operations (scans, etc.)
    python examples/analyzers/censys_example.py --execute --include-dangerous

    # Use specific method via configuration
    python examples/analyzers/censys_example.py --execute --method global_data_search

    # Use custom query
    python examples/analyzers/censys_example.py --execute --query "services.port:80"

Examples
--------
    # Analyze IP address
    python examples/analyzers/censys_example.py --execute --data-type ip --data "8.8.8.8"

    # Analyze domain
    python examples/analyzers/censys_example.py --execute --data-type domain --data "example.com"

    # Analyze certificate hash
    python examples/analyzers/censys_example.py --execute --data-type hash --data "sha256_hash_here"

    # Use collections API
    python examples/analyzers/censys_example.py --execute --method collections_list

    # Search with custom query
    python examples/analyzers/censys_example.py --execute --method global_data_search \\
        --query "services.port:443"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.censys import CensysAnalyzer


def create_sample_config() -> dict[str, Any]:
    """Create sample configuration for Censys API."""
    return {
        "censys": {
            "personal_access_token": "your_censys_token_here",
            "organization_id": "your_organization_id_here",
        }
    }


def demonstrate_ip_analysis(execute: bool) -> None:
    """Demonstrate IP address analysis."""
    print("\n=== IP Address Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample IP addresses for analysis
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

    for ip in ips:
        print(f"\nAnalyzing IP: {ip}")
        input_data = WorkerInput(data_type="ip", data=ip, config=config)

        try:
            analyzer = CensysAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if report.artifacts:
                    print(f"Artifacts found: {len(report.artifacts)}")
            else:
                print("  [DRY RUN] Would analyze IP with Censys host data and timeline")
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_domain_analysis(execute: bool) -> None:
    """Demonstrate domain analysis."""
    print("\n=== Domain Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample domains for analysis
    domains = ["example.com", "google.com", "github.com"]

    for domain in domains:
        print(f"\nAnalyzing Domain: {domain}")
        input_data = WorkerInput(data_type="domain", data=domain, config=config)

        try:
            analyzer = CensysAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
                if report.artifacts:
                    print(f"Artifacts found: {len(report.artifacts)}")
            else:
                print(
                    "  [DRY RUN] Would analyze domain with Censys web properties and certificates"
                )
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_certificate_analysis(execute: bool) -> None:
    """Demonstrate certificate analysis."""
    print("\n=== Certificate Analysis ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    # Sample certificate hashes (these are examples - real hashes would be longer)
    cert_hashes = ["sha256_example_hash_1", "sha256_example_hash_2"]

    for cert_hash in cert_hashes:
        print(f"\nAnalyzing Certificate: {cert_hash}")
        input_data = WorkerInput(data_type="hash", data=cert_hash, config=config)

        try:
            analyzer = CensysAnalyzer(input_data)
            if execute:
                report = analyzer.execute()
                print(f"Verdict: {report.full_report['verdict']}")
                print(f"Taxonomy: {report.full_report['taxonomy']}")
            else:
                print("  [DRY RUN] Would analyze certificate with Censys certificate data")
        except Exception as e:
            print(f"  Error: {e}")


def demonstrate_collections_api(execute: bool) -> None:
    """Demonstrate Collections API methods."""
    print("\n=== Collections API Methods ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets, params={"censys": {"method": "collections_list"}})

    input_data = WorkerInput(data_type="other", data="{}", config=config)

    try:
        analyzer = CensysAnalyzer(input_data)
        if execute:
            report = analyzer.execute()
            print(f"Method: {report.full_report['details']['method']}")
            print(f"Result: {type(report.full_report['details']['result'])}")
        else:
            print("  [DRY RUN] Would list collections")
    except Exception as e:
        print(f"  Error: {e}")


def demonstrate_global_data_search(execute: bool, query: str = "services.port:80") -> None:
    """Demonstrate Global Data Search API."""
    print(f"\n=== Global Data Search (query: {query}) ===")

    secrets = create_sample_config()
    config = WorkerConfig(
        secrets=secrets,
        params={
            "censys": {
                "method": "global_data_search",
                "params": {"search_query_input_body": {"query": query}},
            }
        },
    )

    input_data = WorkerInput(data_type="other", data="{}", config=config)

    try:
        analyzer = CensysAnalyzer(input_data)
        if execute:
            report = analyzer.execute()
            print(f"Method: {report.full_report['details']['method']}")
            print(f"Query: {query}")
            result = report.full_report["details"]["result"]
            if hasattr(result, "hits"):
                print(f"Results found: {len(result.hits)}")
            else:
                print(f"Result type: {type(result)}")
        else:
            print(f"  [DRY RUN] Would search with query: {query}")
    except Exception as e:
        print(f"  Error: {e}")


def demonstrate_dynamic_method_call(
    execute: bool, method: str, params: dict[str, Any] | None = None
) -> None:
    """Demonstrate dynamic method call via JSON payload."""
    print(f"\n=== Dynamic Method Call: {method} ===")

    secrets = create_sample_config()
    config = WorkerConfig(secrets=secrets)

    payload: dict[str, Any] = {"method": method}
    if params:
        payload["params"] = params

    input_data = WorkerInput(data_type="other", data=json.dumps(payload), config=config)

    try:
        analyzer = CensysAnalyzer(input_data)
        if execute:
            report = analyzer.execute()
            print(f"Method: {report.full_report['details']['method']}")
            print(f"Params: {report.full_report['details']['params']}")
            result = report.full_report["details"]["result"]
            print(f"Result type: {type(result)}")
        else:
            print(f"  [DRY RUN] Would call method: {method}")
            if params:
                print(f"  [DRY RUN] With params: {params}")
    except Exception as e:
        print(f"  Error: {e}")


def demonstrate_all_methods(execute: bool) -> None:
    """Demonstrate all available Censys API methods."""
    print("\n=== All Available Methods ===")

    # Collections methods
    collections_methods = [
        "collections_list",
        "collections_create",
        "collections_delete",
        "collections_get",
        "collections_update",
        "collections_list_events",
        "collections_aggregate",
        "collections_search",
    ]

    # Global data methods
    global_data_methods = [
        "global_data_get_certificates",
        "global_data_get_certificate",
        "global_data_get_hosts",
        "global_data_get_host",
        "global_data_get_host_timeline",
        "global_data_get_web_properties",
        "global_data_get_web_property",
        "global_data_aggregate",
        "global_data_search",
    ]

    print("\nCollections Methods:")
    for method in collections_methods:
        print(f"  - {method}")

    print("\nGlobal Data Methods:")
    for method in global_data_methods:
        print(f"  - {method}")

    if execute:
        print("\n[EXECUTE MODE] Use --method <method_name> to test specific methods")
    else:
        print("\n[DRY RUN] Use --execute --method <method_name> to test specific methods")


def _setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Censys Analyzer Example - Comprehensive Censys Platform API demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry run)"
    )

    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (scans, etc.)",
    )

    parser.add_argument(
        "--data-type",
        choices=["ip", "domain", "fqdn", "hash", "other"],
        default="ip",
        help="Data type to analyze (default: ip)",
    )

    parser.add_argument("--data", default="8.8.8.8", help="Data to analyze (default: 8.8.8.8)")

    parser.add_argument("--method", help="Specific Censys method to call")

    parser.add_argument(
        "--query",
        default="services.port:80",
        help="Search query for global_data_search (default: services.port:80)",
    )

    parser.add_argument(
        "--show-all-methods", action="store_true", help="Show all available Censys API methods"
    )

    return parser


def _print_mode_info(execute: bool, include_dangerous: bool) -> None:
    """Print information about current execution mode."""
    print("Censys Analyzer Example")
    print("=" * 50)

    if not execute:
        print("Running in DRY RUN mode - no actual API calls will be made")
        print("Use --execute to make real API calls")
    else:
        print("Running in EXECUTE mode - making real API calls")
        if not include_dangerous:
            print("Use --include-dangerous for potentially impactful operations")


def _handle_special_commands(args: argparse.Namespace) -> bool:
    """Handle special commands like show-all-methods and method calls. Returns True if handled."""
    if args.show_all_methods:
        demonstrate_all_methods(args.execute)
        return True

    if args.method:
        if args.method.startswith("global_data_search"):
            demonstrate_global_data_search(args.execute, args.query)
        else:
            demonstrate_dynamic_method_call(args.execute, args.method)
        return True

    return False


def _analyze_data_type(args: argparse.Namespace) -> None:
    """Analyze data based on data type."""
    config = WorkerConfig(secrets=create_sample_config())

    if args.data_type == "ip":
        _analyze_ip(args, config)
    elif args.data_type in ("domain", "fqdn"):
        _analyze_domain(args, config)
    elif args.data_type == "hash":
        _analyze_hash(args, config)
    else:  # other
        print(f"\n[DRY RUN] Would analyze {args.data_type}: {args.data}")
        print("For 'other' data type, provide JSON with 'method' and 'params' keys")


def _analyze_ip(args: argparse.Namespace, config: WorkerConfig) -> None:
    """Analyze IP address."""
    input_data = WorkerInput(data_type="ip", data=args.data, config=config)
    analyzer = CensysAnalyzer(input_data)
    if args.execute:
        report = analyzer.execute()
        print("\nAnalysis Result:")
        print(f"Observable: {report.full_report['observable']}")
        print(f"Verdict: {report.full_report['verdict']}")
        print(f"Source: {report.full_report['source']}")
        print(f"Taxonomy: {json.dumps(report.full_report['taxonomy'], indent=2)}")
        if report.artifacts:
            print(f"Artifacts: {len(report.artifacts)} found")
    else:
        print(f"\n[DRY RUN] Would analyze IP: {args.data}")


def _analyze_domain(args: argparse.Namespace, config: WorkerConfig) -> None:
    """Analyze domain or FQDN."""
    input_data = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        config=config,
    )
    analyzer = CensysAnalyzer(input_data)
    if args.execute:
        report = analyzer.execute()
        print("\nAnalysis Result:")
        print(f"Observable: {report.full_report['observable']}")
        print(f"Verdict: {report.full_report['verdict']}")
        print(f"Source: {report.full_report['source']}")
        print(f"Taxonomy: {json.dumps(report.full_report['taxonomy'], indent=2)}")
    else:
        print(f"\n[DRY RUN] Would analyze {args.data_type}: {args.data}")


def _analyze_hash(args: argparse.Namespace, config: WorkerConfig) -> None:
    """Analyze certificate hash."""
    input_data = WorkerInput(
        data_type="hash",
        data=args.data,
        config=config,
    )
    analyzer = CensysAnalyzer(input_data)
    if args.execute:
        report = analyzer.execute()
        print("\nAnalysis Result:")
        print(f"Observable: {report.full_report['observable']}")
        print(f"Verdict: {report.full_report['verdict']}")
        print(f"Source: {report.full_report['source']}")
        print(f"Taxonomy: {json.dumps(report.full_report['taxonomy'], indent=2)}")
    else:
        print(f"\n[DRY RUN] Would analyze certificate hash: {args.data}")


def _print_completion_message() -> None:
    """Print completion message and usage examples."""
    print("\n" + "=" * 50)
    print("Example completed successfully!")
    print("\nFor more examples, run:")
    print("  python examples/analyzers/censys_example.py --show-all-methods")
    print("  python examples/analyzers/censys_example.py --execute --method global_data_search")
    print(
        "  python examples/analyzers/censys_example.py --execute --data-type domain --data example.com"
    )


def main() -> None:
    """Run the Censys analyzer example."""
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
