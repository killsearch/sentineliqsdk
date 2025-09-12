"""Runnable example for EmergingThreatsAnalyzer.

Defaults to dry-run (plan only). Use --execute to perform the real API call.

Usage:
  python examples/analyzers/emergingthreats_example.py --data malicious.com --data-type domain                    # plan only
  python examples/analyzers/emergingthreats_example.py --data malicious.com --data-type domain --execute
  python examples/analyzers/emergingthreats_example.py --data 1.2.3.4 --data-type ip --api-key KEY --execute
  python examples/analyzers/emergingthreats_example.py --data hash123 --data-type hash --api-key KEY --execute
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.emergingthreats import EmergingThreatsAnalyzer


def main(argv: list[str]) -> int:
    """Run the EmergingThreats analyzer example with command line arguments."""
    ap = argparse.ArgumentParser(description="Run EmergingThreatsAnalyzer for threat intelligence")
    ap.add_argument("--data", required=True, help="Data to analyze (domain, IP, hash, etc.)")
    ap.add_argument(
        "--data-type",
        dest="data_type",
        required=True,
        choices=["domain", "fqdn", "ip", "hash", "file"],
        help="Type of data to analyze",
    )
    ap.add_argument(
        "--api-key", dest="api_key", required=True, help="EmergingThreats API key (required)"
    )
    ap.add_argument("--execute", action="store_true", help="perform API call (else dry-run)")
    ap.add_argument(
        "--include-dangerous", action="store_true", help="include potentially dangerous operations"
    )
    args = ap.parse_args(argv)

    # Prepare input with API key
    secrets = {"emergingthreats": {"api_key": args.api_key}}
    cfg = WorkerConfig(secrets=secrets)
    input_data = WorkerInput(data_type=args.data_type, data=args.data, config=cfg)

    if not args.execute:
        payload = {
            "action": "plan",
            "provider": "emergingthreats",
            "data": args.data,
            "data_type": args.data_type,
            "has_api_key": bool(args.api_key),
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    # Security gate: check for dangerous operations
    if not args.include_dangerous:
        print("EmergingThreats queries are generally safe. Use --include-dangerous if needed.")

    try:
        analyzer = EmergingThreatsAnalyzer(input_data)
        report = analyzer.execute()

        # Print a compact result
        full = report.full_report
        values = full.get("values", [{}])
        result_data = values[0] if values else {}

        # Extract key information from the result
        reputation_info = []
        if "reputation" in result_data and result_data["reputation"] not in ["-", "Error"]:
            reputation_data = result_data["reputation"]
            if isinstance(reputation_data, list):
                for rep in reputation_data:
                    if isinstance(rep, dict):
                        category = rep.get("category", "unknown")
                        score = rep.get("score", 0)
                        reputation_info.append(f"{category}={score}")

        events_count = 0
        if "events" in result_data and result_data["events"] not in ["-", "Error"]:
            events_data = result_data["events"]
            if isinstance(events_data, list):
                events_count = len(events_data)

        compact = {
            "verdict": full.get("verdict"),
            "data": args.data,
            "data_type": args.data_type,
            "reputation": reputation_info,
            "events_count": events_count,
            "taxonomies": len(full.get("taxonomy", [])),
        }
        print(json.dumps(compact, ensure_ascii=False, indent=2))
        return 0

    except Exception as exc:
        error_payload = {
            "error": str(exc),
            "data": args.data,
            "data_type": args.data_type,
        }
        print(json.dumps(error_payload, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(main(_sys.argv[1:]))
