#!/usr/bin/env python3
"""AnyRun Analyzer Example

This example demonstrates how to use the AnyRun analyzer to submit files and URLs
for sandbox analysis. The analyzer supports both file uploads and URL analysis
with configurable environment settings.

Usage:
    # File analysis (dry-run by default)
    python anyrun_example.py --file /path/to/sample.exe

    # URL analysis (dry-run by default)
    python anyrun_example.py --url "https://example.com/malware.exe"

    # Execute real analysis (requires valid API token)
    python anyrun_example.py --url "https://example.com/malware.exe" --execute

    # Include dangerous operations (file uploads, real analysis)
    python anyrun_example.py --file /path/to/sample.exe --execute --include-dangerous

Configuration:
    Set environment variables:
    - ANYRUN_TOKEN: Your AnyRun API token
    - ANYRUN_PRIVACY_TYPE: Privacy type (public, private, etc.)

Or use WorkerConfig with secrets and params.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Add the src directory to the path so we can import the SDK
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.anyrun import AnyRunAnalyzer


def create_sample_file() -> str:
    """Create a small sample file for testing."""
    sample_path = "/tmp/anyrun_sample.txt"
    with open(sample_path, "w") as f:
        f.write("This is a test file for AnyRun analysis.\n")
    return sample_path


def main() -> None:
    """Main function to run the AnyRun analyzer example."""
    parser = argparse.ArgumentParser(description="AnyRun Analyzer Example")
    parser.add_argument("--file", help="Path to file to analyze")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument(
        "--execute", action="store_true", help="Execute real analysis (not dry-run)"
    )
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )
    parser.add_argument("--token", help="AnyRun API token (or set ANYRUN_TOKEN env var)")
    parser.add_argument("--privacy-type", default="public", help="Privacy type (default: public)")
    parser.add_argument("--env-bitness", help="Environment bitness (32, 64)")
    parser.add_argument("--env-version", help="Environment version")
    parser.add_argument("--env-type", help="Environment type")
    parser.add_argument("--timeout", type=int, help="Analysis timeout in seconds")

    args = parser.parse_args()

    # Validate arguments
    if not args.file and not args.url:
        print("Error: Must specify either --file or --url")
        sys.exit(1)

    if args.file and args.url:
        print("Error: Cannot specify both --file and --url")
        sys.exit(1)

    # Check for dangerous operations
    if args.file and not args.include_dangerous:
        print("Warning: File analysis requires --include-dangerous flag")
        print("This is a safety measure to prevent accidental file uploads")
        sys.exit(1)

    # Get API token
    token = args.token or os.getenv("ANYRUN_TOKEN")
    if not token and args.execute:
        print("Error: API token required for real analysis")
        print("Set ANYRUN_TOKEN environment variable or use --token")
        sys.exit(1)

    # Build configuration
    secrets = {}
    params = {}

    if token:
        secrets["anyrun"] = {"token": token}

    anyrun_params = {"privacy_type": args.privacy_type}
    if args.env_bitness:
        anyrun_params["env_bitness"] = args.env_bitness
    if args.env_version:
        anyrun_params["env_version"] = args.env_version
    if args.env_type:
        anyrun_params["env_type"] = args.env_type
    if args.timeout:
        anyrun_params["opt_timeout"] = args.timeout

    if anyrun_params:
        params["anyrun"] = anyrun_params

    config = WorkerConfig(secrets=secrets, params=params)

    # Prepare input data
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            sys.exit(1)

        input_data = WorkerInput(
            data_type="file",
            data=args.file,
            filename=args.file,
            config=config,
        )
    else:
        input_data = WorkerInput(
            data_type="url",
            data=args.url,
            config=config,
        )

    # Show what we're about to do
    print("AnyRun Analyzer Example")
    print("=" * 50)
    print(f"Data type: {input_data.data_type}")
    if input_data.data_type == "file":
        print(f"File: {input_data.filename}")
    else:
        print(f"URL: {input_data.data}")
    print(f"Privacy type: {args.privacy_type}")
    print(f"Execute: {args.execute}")
    print()

    if not args.execute:
        print("DRY RUN MODE - No actual analysis will be performed")
        print("Use --execute flag to perform real analysis")
        print()

        # Show what the configuration would look like
        print("Configuration that would be used:")
        print(
            json.dumps(
                {"secrets": {"anyrun": {"token": "***" if token else "NOT_SET"}}, "params": params},
                indent=2,
            )
        )
        return

    # Execute the analyzer
    try:
        print("Submitting to AnyRun for analysis...")
        analyzer = AnyRunAnalyzer(input_data)
        report = analyzer.execute()

        print("Analysis completed!")
        print("=" * 50)

        # Print a compact summary
        full_report = report.full_report
        print(f"Observable: {full_report.get('observable')}")
        print(f"Verdict: {full_report.get('verdict')}")
        print(f"Task ID: {full_report.get('task_id')}")

        # Print taxonomy
        taxonomy = full_report.get("taxonomy", [])
        if taxonomy:
            print("\nTaxonomy:")
            for tax in taxonomy:
                print(f"  {tax['level']}: {tax['namespace']}/{tax['predicate']} = {tax['value']}")

        # Print analysis summary if available
        analysis = full_report.get("analysis", {})
        if analysis:
            scores = analysis.get("scores", {})
            if scores:
                print("\nScores:")
                for score_type, score_data in scores.items():
                    if isinstance(score_data, dict) and "score" in score_data:
                        print(f"  {score_type}: {score_data['score']}")

        print(
            f"\nFull report available in: {full_report.get('metadata', {}).get('Name', 'AnyRun')}"
        )

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
