"""Runnable example for AbuseIPDBAnalyzer.

Defaults to dry‑run (plan only). Use --execute to perform the real API call.

Usage:
  python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key KEY           # plan only
  python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key KEY --execute  # perform call
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.abuseipdb import AbuseIPDBAnalyzer


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run AbuseIPDBAnalyzer for a given IP")
    ap.add_argument("--ip", required=True, help="IP address to check")
    ap.add_argument("--api-key", dest="api_key", required=True)
    ap.add_argument("--days", type=int, default=30, help="max age in days (default: 30)")
    ap.add_argument("--execute", action="store_true", help="perform API call (else dry-run)")
    args = ap.parse_args(argv)

    # Prepare input with API key and optional days
    cfg = WorkerConfig(
        secrets={"abuseipdb": {"api_key": args.api_key}},
        params={"abuseipdb": {"days": args.days}},
    )
    input_data = WorkerInput(data_type="ip", data=args.ip, config=cfg)

    if not args.execute:
        payload = {
            "action": "plan",
            "provider": "abuseipdb",
            "ip": args.ip,
            "params": {"days": args.days},
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    analyzer = AbuseIPDBAnalyzer(input_data)
    report = analyzer.execute()
    # Print a compact result
    full = report.full_report
    compact = {
        "verdict": full.get("verdict"),
        "score": ((full.get("values") or [{}])[0].get("data", {}).get("abuseConfidenceScore")),
        "totalReports": ((full.get("values") or [{}])[0].get("data", {}).get("totalReports")),
        "ip": args.ip,
    }
    print(json.dumps(compact, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
