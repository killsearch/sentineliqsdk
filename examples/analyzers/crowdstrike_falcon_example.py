#!/usr/bin/env python3
"""
CrowdStrike Falcon Analyzer Example.

This example demonstrates how to use the CrowdStrike Falcon analyzer
for analyzing files and hostnames using the CrowdStrike Falcon API.

Usage:
    python crowdstrike_falcon_example.py --help
    python crowdstrike_falcon_example.py --hostname example.com
    python crowdstrike_falcon_example.py --file /path/to/file.exe --execute
    python crowdstrike_falcon_example.py --hostname example.com --include-dangerous
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.crowdstrike_falcon import CrowdStrikeFalconAnalyzer


def main():
    """Run the CrowdStrike Falcon analyzer example CLI."""
    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--hostname", help="Hostname to analyze (e.g., example.com)")
    input_group.add_argument("--file", help="File path to analyze (e.g., /path/to/file.exe)")

    # Execution options
    parser.add_argument(
        "--execute", action="store_true", help="Execute real API calls (default: dry-run)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (file uploads, etc.)",
    )

    # Configuration options
    parser.add_argument(
        "--base-url",
        default="https://api.crowdstrike.com",
        help="CrowdStrike Falcon base URL (default: https://api.crowdstrike.com)",
    )
    parser.add_argument(
        "--environment", type=int, default=160, help="Sandbox environment ID (default: 160)"
    )
    parser.add_argument(
        "--days-before", type=int, default=7, help="Days to look back for alerts (default: 7)"
    )

    args = parser.parse_args()

    # Validate file path if provided
    if args.file and not Path(args.file).exists():
        print(
            json.dumps({"success": False, "error": f"File not found: {args.file}"}), file=sys.stderr
        )
        sys.exit(1)

    # Check if execution is allowed
    if not args.execute:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": "This example requires --execute flag for real API calls",
                    "note": "Add --execute to perform actual CrowdStrike Falcon API calls",
                }
            )
        )
        return

    # Check for dangerous operations
    if args.file and not args.include_dangerous:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": "File analysis requires --include-dangerous flag",
                    "note": "Add --include-dangerous to enable file upload and sandbox analysis",
                }
            )
        )
        return

    # Configure secrets (in real usage, these would come from secure storage)
    secrets = {
        "crowdstrike_falcon": {
            "client_id": "your_client_id_here",
            "client_secret": "your_client_secret_here",
        }
    }

    # Configure settings
    config = WorkerConfig(
        check_tlp=True, max_tlp=2, check_pap=True, max_pap=2, auto_extract=True, secrets=secrets
    )

    # Create input data
    if args.hostname:
        input_data = WorkerInput(
            data_type="hostname", data=args.hostname, tlp=2, pap=2, config=config
        )
    else:
        input_data = WorkerInput(
            data_type="file",
            data=args.file,
            filename=Path(args.file).name,
            tlp=2,
            pap=2,
            config=config,
        )

    try:
        # Run analyzer
        analyzer = CrowdStrikeFalconAnalyzer(input_data)
        report = analyzer.execute()

        # Print compact result
        print(json.dumps(report.full_report, ensure_ascii=False, indent=2))

    except Exception as e:
        print(json.dumps({"success": False, "error": f"Analysis failed: {e!s}"}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
