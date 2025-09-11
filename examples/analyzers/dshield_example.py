"""Runnable example for DShieldAnalyzer.

Defaults to dry-run (plan only). Use --execute to perform the real API call.

Usage:
  python examples/analyzers/dshield_example.py --ip 1.2.3.4           # plan only
  python examples/analyzers/dshield_example.py --ip 1.2.3.4 --execute
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.dshield import DShieldAnalyzer


def main(argv: list[str]) -> int:
    """Run the DShield analyzer example with command line arguments."""
    ap = argparse.ArgumentParser(description="Run DShieldAnalyzer for a given IP")
    ap.add_argument("--ip", required=True, help="IP address to check")
    ap.add_argument("--timeout", type=int, default=30, help="timeout in seconds (default: 30)")
    ap.add_argument("--execute", action="store_true", help="perform API call (else dry-run)")
    args = ap.parse_args(argv)

    # Prepare input with optional timeout configuration
    cfg = WorkerConfig(
        params={"dshield": {"timeout": args.timeout}},
    )
    input_data = WorkerInput(data_type="ip", data=args.ip, config=cfg)

    if not args.execute:
        payload = {
            "action": "plan",
            "provider": "dshield",
            "ip": args.ip,
            "params": {"timeout": args.timeout},
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    analyzer = DShieldAnalyzer(input_data)
    report = analyzer.execute()

    # Print a compact result
    full = report.full_report
    values = full.get("values", {})
    compact = {
        "verdict": full.get("verdict"),
        "ip": args.ip,
        "attacks": values.get("attacks", 0),
        "count": values.get("count", 0),
        "reputation": values.get("reputation", "unknown"),
        "maxrisk": values.get("maxrisk", 0),
        "threatfeedscount": values.get("threatfeedscount", 0),
        "lastseen": values.get("lastseen", "None"),
        "as": values.get("as"),
        "asname": values.get("asname"),
        "ascountry": values.get("ascountry"),
        "asabusecontact": values.get("asabusecontact"),
    }
    print(json.dumps(compact, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
