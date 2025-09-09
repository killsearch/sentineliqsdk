"""Cuckoo Sandbox analyzer example.

Submit a URL or file to Cuckoo and print the JSON report (requires --execute).
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cuckoo import CuckooSandboxAnalyzer


def main() -> None:
    """Parse CLI flags, build WorkerInput, run analyzer, and print result."""
    parser = argparse.ArgumentParser(description="Run CuckooSandboxAnalyzer example")
    parser.add_argument("data_type", choices=["file", "url"], help="Type of observable")
    parser.add_argument("data", help="File path (for file) or URL (for url)")
    parser.add_argument("--execute", action="store_true", help="Actually call Cuckoo API")
    parser.add_argument("--url", dest="base_url", help="Cuckoo base API URL")
    parser.add_argument("--token", dest="token", help="API token (optional)")
    parser.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", default=True)
    parser.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false")
    args = parser.parse_args()

    secrets: dict[str, dict[str, str]] = {"cuckoo": {}}
    if args.token:
        secrets["cuckoo"]["token"] = args.token

    params: dict[str, object] = {"cuckoo.verify_ssl": bool(args.verify_ssl)}
    if args.base_url:
        params["cuckoo.url"] = args.base_url

    input_data = WorkerInput(
        data_type=args.data_type,
        data=args.data,
        config=WorkerConfig(secrets=secrets, params=params),
    )

    analyzer = CuckooSandboxAnalyzer(input_data)
    if not args.execute:
        print(json.dumps({"success": False, "errorMessage": "Use --execute to run"}))
        return
    report = analyzer.execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
