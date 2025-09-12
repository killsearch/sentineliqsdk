"""Runnable example for EmailRepAnalyzer.

Defaults to dry-run (plan only). Use --execute to perform the real API call.

Usage:
  python examples/analyzers/emailrep_example.py --email test@example.com                    # plan only
  python examples/analyzers/emailrep_example.py --email test@example.com --execute
  python examples/analyzers/emailrep_example.py --email test@example.com --api-key KEY --execute
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.emailrep import EmailRepAnalyzer


def main(argv: list[str]) -> int:
    """Run the EmailRep analyzer example with command line arguments."""
    ap = argparse.ArgumentParser(description="Run EmailRepAnalyzer for a given email")
    ap.add_argument("--email", required=True, help="Email address to check")
    ap.add_argument(
        "--api-key", dest="api_key", help="EmailRep API key (optional for basic queries)"
    )
    ap.add_argument("--execute", action="store_true", help="perform API call (else dry-run)")
    ap.add_argument(
        "--include-dangerous", action="store_true", help="include potentially dangerous operations"
    )
    args = ap.parse_args(argv)

    # Prepare input with optional API key
    secrets = {}
    if args.api_key:
        secrets["emailrep"] = {"api_key": args.api_key}

    cfg = WorkerConfig(secrets=secrets)
    input_data = WorkerInput(data_type="mail", data=args.email, config=cfg)

    if not args.execute:
        payload = {
            "action": "plan",
            "provider": "emailrep",
            "email": args.email,
            "has_api_key": bool(args.api_key),
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    # Security gate: check for dangerous operations
    if not args.include_dangerous:
        print("EmailRep queries are generally safe. Use --include-dangerous if needed.")

    analyzer = EmailRepAnalyzer(input_data)
    report = analyzer.execute()

    # Print a compact result
    full = report.full_report
    values = full.get("values", [{}])
    result_data = values[0] if values else {}

    compact = {
        "verdict": full.get("verdict"),
        "suspicious": result_data.get("suspicious", False),
        "references": result_data.get("references", 0),
        "reputation": result_data.get("reputation", "unknown"),
        "email": args.email,
    }
    print(json.dumps(compact, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
