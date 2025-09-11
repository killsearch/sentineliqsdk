"""Minimal DNS Lookingglass analyzer example.

Run with a domain or FQDN and print a compact JSON result.
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer


def main() -> None:
    """Parse CLI args, run analyzer, and print the result."""
    parser = argparse.ArgumentParser(description="Run DNS Lookingglass analyzer example")
    parser.add_argument("domain", help="Domain or FQDN to query (e.g., example.com)")
    parser.add_argument(
        "--data", help="Domain data to analyze (alternative to positional argument)"
    )
    parser.add_argument(
        "--data-type",
        default="domain",
        choices=["domain", "fqdn"],
        help="Type of data being analyzed (default: domain)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real HTTP calls to DNS Lookingglass API",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Include potentially dangerous operations (no-op for this analyzer)",
    )
    args = parser.parse_args()

    # Security check - require --execute flag
    if not args.execute:
        print("Modo dry-run. Use --execute para operações reais.")
        return

    # Determine data to analyze
    data = args.data if args.data else args.domain

    input_data = WorkerInput(
        data_type=args.data_type,
        data=data,
        config=WorkerConfig(
            auto_extract=True,
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
        ),
    )

    try:
        report = DnsLookingglassAnalyzer(input_data).execute()
        print(json.dumps(report.full_report, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"Erro ao executar analyzer: {e}")
        return


if __name__ == "__main__":
    main()
