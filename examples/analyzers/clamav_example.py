#!/usr/bin/env python3
"""
ClamAV Analyzer Example

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
import json
import os
import tempfile

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.clamav import ClamavAnalyzer


def create_test_file(
    content: str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
) -> str:
    """Create a temporary test file with EICAR test content."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write(content)
        return f.name


def main():
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

    args = parser.parse_args()

    # Determine execution mode
    execute_mode = args.execute or args.include_dangerous

    if not execute_mode:
        print("🔍 DRY-RUN MODE: No actual ClamAV scan will be performed")
        print("   Use --execute to perform real scans")
        print()

    # Prepare input data
    if args.test_eicar:
        if execute_mode:
            test_file = create_test_file()
            print(f"📁 Created test file: {test_file}")
            try:
                input_data = WorkerInput(
                    data_type="file",
                    data="test content",
                    filename=test_file,
                    tlp=2,
                    pap=2,
                    config=WorkerConfig(
                        check_tlp=True,
                        max_tlp=2,
                        check_pap=True,
                        max_pap=2,
                        auto_extract=True,
                        params={
                            "clamav.socket_path": args.socket_path,
                            "clamav.timeout": args.timeout,
                        },
                    ),
                )
            finally:
                # Clean up test file
                try:
                    os.unlink(test_file)
                except OSError:
                    pass
        else:
            # Dry-run mode - just show what would be scanned
            input_data = WorkerInput(
                data_type="file",
                data="EICAR test content",
                filename="/tmp/eicar_test.txt",
                tlp=2,
                pap=2,
                config=WorkerConfig(
                    check_tlp=True,
                    max_tlp=2,
                    check_pap=True,
                    max_pap=2,
                    auto_extract=True,
                    params={"clamav.socket_path": args.socket_path, "clamav.timeout": args.timeout},
                ),
            )
    elif args.file:
        if not execute_mode:
            print(f"📁 Would scan file: {args.file}")

        if execute_mode and not os.path.exists(args.file):
            print(f"❌ Error: File not found: {args.file}")
            return 1

        input_data = WorkerInput(
            data_type="file",
            data="file content",
            filename=args.file if execute_mode else "/path/to/file",
            tlp=2,
            pap=2,
            config=WorkerConfig(
                check_tlp=True,
                max_tlp=2,
                check_pap=True,
                max_pap=2,
                auto_extract=True,
                params={"clamav.socket_path": args.socket_path, "clamav.timeout": args.timeout},
            ),
        )
    else:  # args.data
        if not execute_mode:
            print(f"📄 Would scan data: {args.data[:50]}{'...' if len(args.data) > 50 else ''}")

        input_data = WorkerInput(
            data_type="file",
            data=args.data if execute_mode else "sample data",
            tlp=2,
            pap=2,
            config=WorkerConfig(
                check_tlp=True,
                max_tlp=2,
                check_pap=True,
                max_pap=2,
                auto_extract=True,
                params={"clamav.socket_path": args.socket_path, "clamav.timeout": args.timeout},
            ),
        )

    # Run analyzer
    try:
        if execute_mode:
            analyzer = ClamavAnalyzer(input_data)
            report = analyzer.execute()
        else:
            # Dry-run mode - create mock report
            report = {
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

        # Print results
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
            if hasattr(report, "full_report"):
                full_report = report.full_report
            else:
                full_report = report

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

            if not execute_mode:
                print("\n💡 Use --execute to perform real ClamAV scans")
                print("   Use --pretty for detailed JSON output")

        return 0

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
    exit(main())
