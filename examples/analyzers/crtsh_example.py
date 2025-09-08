from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.crtsh import CrtshAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run crt.sh analyzer example")
    parser.add_argument("domain", help="Domain or FQDN to query (e.g., example.com)")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute real HTTP calls (no-op flag for consistency)",
    )
    args = parser.parse_args()

    input_data = WorkerInput(
        data_type="domain",
        data=args.domain,
        config=WorkerConfig(auto_extract=True),
    )

    report = CrtshAnalyzer(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
