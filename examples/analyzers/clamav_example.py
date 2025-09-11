#!/usr/bin/env python3
"""
ClamAV Analyzer Example.

This example demonstrates how to use the ClamAV analyzer to scan files for malware.
The analyzer connects to a local ClamAV daemon and scans files for known threats.

Usage:
    python examples/analyzers/clamav_example.py --help
    python examples/analyzers/clamav_example.py --file /path/to/file
    python examples/analyzers/clamav_example.py --data "file content as string"
    python examples/analyzers/clamav_example.py --execute --file /path/to/file
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.clamav import ClamavAnalyzer


def create_test_file(
    content: str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
) -> str:
    """Create a temporary test file with EICAR test content."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write(content)
        return f.name


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="ClamAV Analyzer Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", help="Path to file to scan")
    input_group.add_argument("--data", help="File content as string to scan")
    input_group.add_argument(
        "--test-eicar",
        action="store_true",
        help="Test with EICAR test file (creates temporary file)",
    )

    # Configuration options
    parser.add_argument(
        "--socket-path",
        default="/var/run/clamav/clamd.ctl",
        help="ClamAV daemon socket path (default: /var/run/clamav/clamd.ctl)",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)"
    )

    # Execution options
    parser.add_argument(
        "--execute", action="store_true", help="Execute real ClamAV scan (default: dry-run mode)"
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include dangerous operations (same as --execute for this analyzer)",
    )

    # Output options
    parser.add_argument("--compact", action="store_true", help="Print compact JSON output")
    parser.add_argument("--pretty", action="store_true", help="Print pretty JSON output")

    return parser


def create_worker_config(socket_path: str, timeout: int) -> WorkerConfig:
    """Create WorkerConfig with ClamAV settings."""
    return WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        params={
            "clamav.socket_path": socket_path,
            "clamav.timeout": timeout,
        },
    )


def prepare_eicar_input(execute_mode: bool, socket_path: str, timeout: int) -> WorkerInput:
    """Prepare input data for EICAR test."""
    if execute_mode:
        test_file = create_test_file()
        print(f"📁 Created test file: {test_file}")
        try:
            return WorkerInput(
                data_type="file",
                data="test content",
                filename=test_file,
                tlp=2,
                pap=2,
                config=create_worker_config(socket_path, timeout),
            )
        finally:
            # Clean up test file
            with contextlib.suppress(OSError):
                os.unlink(test_file)
    else:
        # Dry-run mode - just show what would be scanned
        return WorkerInput(
            data_type="file",
            data="EICAR test content",
            filename="/tmp/eicar_test.txt",
            tlp=2,
            pap=2,
            config=create_worker_config(socket_path, timeout),
        )


def prepare_file_input(
    file_path: str, execute_mode: bool, socket_path: str, timeout: int
) -> WorkerInput:
    """Prepare input data for file scanning."""
    if not execute_mode:
        print(f"📁 Would scan file: {file_path}")

    if execute_mode and not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")

    return WorkerInput(
        data_type="file",
        data="file content",
        filename=file_path if execute_mode else "/path/to/file",
        tlp=2,
        pap=2,
        config=create_worker_config(socket_path, timeout),
    )


def prepare_data_input(
    data: str, execute_mode: bool, socket_path: str, timeout: int
) -> WorkerInput:
    """Prepare input data for string data scanning."""
    if not execute_mode:
        # Constants for data preview
        max_preview_length = 50
        print(
            f"📄 Would scan data: {data[:max_preview_length]}{'...' if len(data) > max_preview_length else ''}"
        )

    return WorkerInput(
        data_type="file",
        data=data if execute_mode else "sample data",
        tlp=2,
        pap=2,
        config=create_worker_config(socket_path, timeout),
    )


def create_dry_run_report(input_data: WorkerInput) -> dict:
    """Create mock report for dry-run mode."""
    return {
        "success": True,
        "summary": {},
        "artifacts": [],
        "operations": [],
        "full_report": {
            "observable": input_data.data,
            "verdict": "safe",
            "malware_name": None,
            "taxonomy": [
                {
                    "level": "safe",
                    "namespace": "ClamAV",
                    "predicate": "detection",
                    "value": "No threats detected (dry-run)",
                }
            ],
            "metadata": {
                "name": "ClamAV Analyzer",
                "description": "Scans files for malware using ClamAV antivirus engine",
                "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
                "pattern": "antivirus",
                "doc_pattern": "MkDocs module page; programmatic usage",
                "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/clamav/",
                "version_stage": "TESTING",
            },
        },
    }


def print_results(report, args) -> None:
    """Print analysis results in the requested format."""
    if args.compact:
        print(
            json.dumps(
                report.full_report if hasattr(report, "full_report") else report,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    elif args.pretty:
        print(
            json.dumps(
                report.full_report if hasattr(report, "full_report") else report,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        # Default output
        full_report = report.full_report if hasattr(report, "full_report") else report

        print("🔍 ClamAV Analysis Results:")
        print(f"   Observable: {full_report.get('observable', 'N/A')}")
        print(f"   Verdict: {full_report.get('verdict', 'N/A')}")

        if full_report.get("malware_name"):
            print(f"   🚨 Malware Detected: {full_report['malware_name']}")
        else:
            print("   ✅ No threats detected")

        taxonomy = full_report.get("taxonomy", [])
        if taxonomy:
            print(
                f"   Taxonomy: {taxonomy[0].get('level', 'N/A')} - {taxonomy[0].get('value', 'N/A')}"
            )

        if not (args.execute or args.include_dangerous):
            print("\n💡 Use --execute to perform real ClamAV scans")
            print("   Use --pretty for detailed JSON output")


def main() -> int:
    """Run the ClamAV analyzer example."""
    parser = create_parser()
    args = parser.parse_args()

    # Determine execution mode
    execute_mode = args.execute or args.include_dangerous

    if not execute_mode:
        print("🔍 DRY-RUN MODE: No actual ClamAV scan will be performed")
        print("   Use --execute to perform real scans")
        print()

    # Prepare input data
    try:
        if args.test_eicar:
            input_data = prepare_eicar_input(execute_mode, args.socket_path, args.timeout)
        elif args.file:
            input_data = prepare_file_input(args.file, execute_mode, args.socket_path, args.timeout)
        else:  # args.data
            input_data = prepare_data_input(args.data, execute_mode, args.socket_path, args.timeout)

        # Run analyzer
        report: Any
        if execute_mode:
            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.execute()
        else:
            # Dry-run mode - create mock report
            mock_data = create_dry_run_report(input_data)

            # Create a mock AnalyzerReport-like object
            class MockReport:
                def __init__(self, data):
                    self.full_report = data

            report = MockReport(mock_data)

        # Print results
        print_results(report, args)
        return 0

    except FileNotFoundError:
        return 1
    except Exception as e:
        error_report = {
            "success": False,
            "error": str(e),
            "input": {
                "data_type": input_data.data_type,
                "data": input_data.data,
                "filename": getattr(input_data, "filename", None),
            },
        }

        if args.compact:
            print(json.dumps(error_report, ensure_ascii=False, separators=(",", ":")))
        else:
            print(f"❌ Error: {e}")
            if args.pretty:
                print(json.dumps(error_report, ensure_ascii=False, indent=2))

        return 1


if __name__ == "__main__":
    sys.exit(main())
