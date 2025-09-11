#!/usr/bin/env python3
"""AutoFocus Analyzer Example.

This example demonstrates how to use the AutoFocus analyzer to query Palo Alto Networks
AutoFocus for threat intelligence and sample analysis.

Usage:
    python autofocus_example.py --help
    python autofocus_example.py --data-type ip --data 1.2.3.4 --service search_ioc
    python autofocus_example.py --data-type hash --data abc123... --service get_sample_analysis
    python autofocus_example.py --execute  # Use real API calls (requires API key)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import cast

# Add the src directory to the path so we can import the SDK
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer
from sentineliqsdk.models import DataType


def create_input_data(
    data_type: str,
    data: str,
    service: str,
    apikey: str | None = None,
    execute: bool = False,
) -> WorkerInput:
    """Create WorkerInput with AutoFocus configuration."""
    config_params = {"autofocus": {"service": service}}
    config_secrets = {}

    if apikey:
        config_secrets["autofocus"] = {"apikey": apikey}
    elif execute:
        print("Warning: No API key provided. Use --apikey to provide the API key")
        print("Example: python autofocus_example.py --apikey YOUR_KEY --execute")

    config = WorkerConfig(
        params=config_params,
        secrets=config_secrets,
    )

    if data_type == "file":
        return WorkerInput(
            data_type=cast(DataType, data_type),
            data="",
            filename=data,
            config=config,
        )
    return WorkerInput(
        data_type=cast(DataType, data_type),
        data=data,
        filename=None,
        config=config,
    )


def main() -> None:
    """Run the AutoFocus analyzer example."""
    parser = argparse.ArgumentParser(
        description="AutoFocus Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--data-type",
        choices=[
            "ip",
            "domain",
            "fqdn",
            "hash",
            "url",
            "user-agent",
            "other",
        ],
        default="ip",
        help="Type of observable to analyze (default: ip)",
    )

    parser.add_argument(
        "--data",
        default="1.2.3.4",
        help="Observable value to analyze (default: 1.2.3.4)",
    )

    parser.add_argument(
        "--service",
        choices=["search_ioc", "get_sample_analysis", "search_json"],
        default="search_ioc",
        help="AutoFocus service to use (default: search_ioc)",
    )

    parser.add_argument(
        "--apikey",
        help="AutoFocus API key (or set AUTOFOCUS_API_KEY env var)",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real API calls (default: dry-run mode)",
    )

    args = parser.parse_args()

    # Validate service and data type combination
    if args.service == "get_sample_analysis" and args.data_type != "hash":
        print("Error: get_sample_analysis service only supports 'hash' data type")
        sys.exit(1)

    if args.service == "search_json" and args.data_type != "other":
        print("Error: search_json service only supports 'other' data type")
        sys.exit(1)

    # Create input data
    try:
        input_data = create_input_data(
            data_type=args.data_type,
            data=args.data,
            service=args.service,
            apikey=args.apikey,
            execute=args.execute,
        )
    except Exception as e:
        print(f"Error creating input data: {e}")
        sys.exit(1)

    # Run the analyzer
    try:
        if args.execute:
            print(f"Executing AutoFocus analysis for {args.data_type}: {args.data}")
            analyzer = AutoFocusAnalyzer(input_data)
            report = analyzer.execute()

            # Print compact result
            print("\n=== AutoFocus Analysis Result ===")
            print(json.dumps(report.full_report, indent=2, ensure_ascii=False))
        else:
            print("Dry-run mode: AutoFocus analyzer would analyze:")
            print(f"  Data Type: {args.data_type}")
            print(f"  Data: {args.data}")
            print(f"  Service: {args.service}")
            print(f"  API Key: {'Provided' if args.apikey else 'Not provided'}")
            print("\nUse --execute to perform real analysis (requires API key)")

            # Show what the result structure would look like
            mock_result = {
                "observable": args.data,
                "data_type": args.data_type,
                "service": args.service,
                "result": {"records": [], "search": "mock_search_query"},
                "taxonomy": [
                    {
                        "level": "info",
                        "namespace": "PaloAltoNetworks",
                        "predicate": "AutoFocus",
                        "value": "No results",
                    }
                ],
                "metadata": {
                    "Name": "AutoFocus Analyzer",
                    "Description": "Query Palo Alto Networks AutoFocus for threat intelligence and sample analysis",
                    "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
                    "License": "SentinelIQ License",
                    "pattern": "threat-intel",
                    "doc_pattern": "MkDocs module page; programmatic usage",
                    "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/autofocus/",
                    "VERSION": "TESTING",
                },
            }
            print("\n=== Mock Result Structure ===")
            print(json.dumps(mock_result, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"Error running analyzer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
