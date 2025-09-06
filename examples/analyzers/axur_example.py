"""Axur Analyzer example: generic caller for Axur API routes.

Defaults to dry-run (prints the planned request). Use --execute to perform real calls.
Requires AXUR_API_TOKEN (or pass --token).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.axur import AxurAnalyzer


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Axur Analyzer example (generic API caller)")
    ap.add_argument("--token", default=os.getenv("AXUR_API_TOKEN"))
    ap.add_argument(
        "--method",
        default="call",
        help=(
            "AxurClient method to invoke (e.g. 'customers', 'tickets_search', 'call').\n"
            "Use 'call' for arbitrary HTTP path; see --path/--query/--json."
        ),
    )
    ap.add_argument("--path", help="API path for method 'call', e.g. tickets-api/tickets")
    ap.add_argument("--query", help="JSON object with query parameters", default=None)
    ap.add_argument("--json", dest="json_body", help="JSON object body", default=None)
    ap.add_argument("--headers", help="JSON object with extra headers", default=None)
    ap.add_argument(
        "--http-method",
        dest="http_method",
        default="GET",
        help="HTTP method for 'call' (GET/POST/PUT/DELETE)",
    )
    ap.add_argument("--execute", action="store_true", help="perform the HTTP call")
    args = ap.parse_args(argv)

    if not args.token:
        print("Missing AXUR_API_TOKEN (env or --token)", file=sys.stderr)
        return 2

    # Prepare payload for analyzer (data_type=other with JSON payload)
    method = args.method
    params: dict[str, Any] = {}
    if method == "call":
        if not args.path:
            print("--path is required when --method=call", file=sys.stderr)
            return 2
        params["http_method"] = args.http_method
        params["path"] = args.path
        params["dry_run"] = not args.execute
        if args.query:
            try:
                params["query"] = json.loads(args.query)
            except json.JSONDecodeError:
                print("--query must be a valid JSON object", file=sys.stderr)
                return 2
        if args.json_body:
            try:
                params["json"] = json.loads(args.json_body)
            except json.JSONDecodeError:
                print("--json must be a valid JSON object", file=sys.stderr)
                return 2
        if args.headers:
            try:
                params["headers"] = json.loads(args.headers)
            except json.JSONDecodeError:
                print("--headers must be a valid JSON object", file=sys.stderr)
                return 2
    else:
        # Wrapper methods: pass through query/json when applicable
        if args.query:
            try:
                q = json.loads(args.query)
            except json.JSONDecodeError:
                print("--query must be a valid JSON object", file=sys.stderr)
                return 2
            if not isinstance(q, dict):
                print("--query must be a JSON object", file=sys.stderr)
                return 2
            params.update(q)
        if args.json_body:
            try:
                jb = json.loads(args.json_body)
            except json.JSONDecodeError:
                print("--json must be a valid JSON object", file=sys.stderr)
                return 2
            if not isinstance(jb, dict):
                print("--json must be a JSON object", file=sys.stderr)
                return 2
            # Many wrappers accept a single dict payload (e.g., ticket_create, filter_create)
            # We place it under a conventional key if the wrapper expects a single positional
            # parameter; analyzer will pass kwargs unchanged.
            # For example: --method=ticket_create --json '{"reference": ..., ...}'
            params = jb

    # Inject token into env for the analyzer
    os.environ["AXUR_API_TOKEN"] = args.token

    payload = {"method": method, "params": params}
    input_data = WorkerInput(data_type="other", data=json.dumps(payload))
    # For programmatic result, call execute(); run() performs side-effect only
    report = AxurAnalyzer(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
