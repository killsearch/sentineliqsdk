#!/usr/bin/env python3

"""MCAP Analyzer Example - Demonstrates how to use the MCAP analyzer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.mcap import MCAPAnalyzer


def _create_argument_parser():
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(description="MCAP Analyzer Example")
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["ip", "hash", "url", "domain", "fqdn", "file"],
        help="Type of observable to analyze",
    )
    parser.add_argument("--data", help="Observable data (not needed for file type)")
    parser.add_argument("--file", help="File path (for file type)")
    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry-run)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (file submission)",
    )
    parser.add_argument("--api-key", help="MCAP API key")
    parser.add_argument("--private-samples", action="store_true", help="Mark samples as private")
    parser.add_argument(
        "--minimum-confidence",
        type=int,
        default=80,
        help="Minimum confidence threshold (default: 80)",
    )
    parser.add_argument(
        "--minimum-severity", type=int, default=80, help="Minimum severity threshold (default: 80)"
    )
    parser.add_argument(
        "--polling-interval", type=int, default=60, help="Polling interval in seconds (default: 60)"
    )
    parser.add_argument(
        "--max-wait", type=int, default=1000, help="Maximum wait time in seconds (default: 1000)"
    )
    return parser


def _validate_arguments(args):
    """Validate command line arguments."""
    if args.data_type == "file" and not args.file:
        print("Error: --file is required for file data type", file=sys.stderr)
        sys.exit(1)
    elif args.data_type != "file" and not args.data:
        print("Error: --data is required for non-file data types", file=sys.stderr)
        sys.exit(1)


def _check_safety_requirements(args):
    """Check safety requirements for execution."""
    if not args.execute:
        print("Running in dry-run mode. Use --execute to make real API calls.", file=sys.stderr)
        if args.data_type == "file":
            print("File submission requires --include-dangerous flag.", file=sys.stderr)
        return False

    if args.data_type == "file" and not args.include_dangerous:
        print(
            "File submission is a dangerous operation. Use --include-dangerous to enable.",
            file=sys.stderr,
        )
        return False

    return True


def _get_api_key(args):
    """Get API key from arguments or user input."""
    api_key = args.api_key
    if not api_key:
        api_key = input("Enter MCAP API key: ").strip()
        if not api_key:
            print("Error: API key is required", file=sys.stderr)
            sys.exit(1)
    return api_key


def _create_worker_config(args, api_key):
    """Create WorkerConfig with MCAP settings."""
    secrets = {"mcap": {"api_key": api_key}}

    return WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        # MCAP-specific settings
        mcap_private_samples=args.private_samples,
        mcap_minimum_confidence=args.minimum_confidence,
        mcap_minimum_severity=args.minimum_severity,
        mcap_polling_interval=args.polling_interval,
        mcap_max_sample_result_wait=args.max_wait,
        secrets=secrets,
    )


def _create_input_data(args, config):
    """Create WorkerInput based on arguments."""
    if args.data_type == "file":
        if not Path(args.file).exists():
            print(f"Error: File {args.file} does not exist", file=sys.stderr)
            sys.exit(1)
        return WorkerInput(data_type="file", data=args.file, tlp=2, pap=2, config=config)

    return WorkerInput(data_type=args.data_type, data=args.data, tlp=2, pap=2, config=config)


def _run_dry_mode(args, api_key):
    """Run in dry-run mode."""
    print("Dry-run mode - would analyze:")
    print(f"  Data type: {args.data_type}")
    if args.data_type == "file":
        print(f"  File: {args.file}")
    else:
        print(f"  Data: {args.data}")
    print(f"  API key: {api_key[:8]}...")
    print(f"  Private samples: {args.private_samples}")
    print(f"  Min confidence: {args.minimum_confidence}")
    print(f"  Min severity: {args.minimum_severity}")


def main():
    """Execute MCAP analyzer example."""
    parser = _create_argument_parser()
    args = parser.parse_args()

    _validate_arguments(args)

    if not _check_safety_requirements(args):
        return

    api_key = _get_api_key(args)
    config = _create_worker_config(args, api_key)
    input_data = _create_input_data(args, config)

    try:
        analyzer = MCAPAnalyzer(input_data)

        if not args.execute:
            _run_dry_mode(args, api_key)
            return

        # Execute real analysis
        report = analyzer.execute()
        print(json.dumps(report.full_report, ensure_ascii=False, indent=2))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
