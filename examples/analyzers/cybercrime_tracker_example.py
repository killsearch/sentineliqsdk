"""CyberCrime Tracker analyzer example.

Run with an observable and print the result (requires --execute).
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cybercrime_tracker import CyberCrimeTrackerAnalyzer


def main() -> None:
    """Parse CLI args, run analyzer, and print compact JSON result."""
    parser = argparse.ArgumentParser(description="Run CyberCrime Tracker analyzer example")
    parser.add_argument("observable", help="Observable to search (ip/domain/url/other)")
    parser.add_argument("--execute", action="store_true", help="Execute real HTTP calls")
    parser.add_argument("--limit", type=int, default=40, help="Page size (default: 40)")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds")
    args = parser.parse_args()

    params: dict[str, object] = {
        "cct.limit": args.limit,
        "cct.timeout": args.timeout,
    }

    input_data = WorkerInput(
        data_type="other",
        data=args.observable,
        config=WorkerConfig(params=params),
    )

    analyzer = CyberCrimeTrackerAnalyzer(input_data)

    if not args.execute:
        print(json.dumps({"success": False, "errorMessage": "Use --execute to run"}))
        return

    report = analyzer.execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
