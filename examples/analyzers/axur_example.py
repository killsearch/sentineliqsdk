"""Axur Analyzer example: generic caller for Axur API routes.

Defaults to dry-run (prints the planned request). Use --execute to perform real calls.
Requires --token (no environment fallback).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.axur import AxurAnalyzer


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    ap = argparse.ArgumentParser(description="Axur Analyzer example (generic API caller)")
    ap.add_argument("--token", required=True)
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
    return ap


def parse_json_argument(value: str, arg_name: str) -> dict[str, Any] | None:
    """Parse a JSON argument and return the parsed dict or None if empty."""
    if not value:
        return None

    try:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            print(f"--{arg_name} must be a JSON object", file=sys.stderr)
            return None
        return parsed
    except json.JSONDecodeError:
        print(f"--{arg_name} must be a valid JSON object", file=sys.stderr)
        return None


def build_call_params(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build parameters for the 'call' method."""
    if not args.path:
        print("--path is required when --method=call", file=sys.stderr)
        return None

    params = {
        "http_method": args.http_method,
        "path": args.path,
        "dry_run": not args.execute,
    }

    if args.query:
        query_params = parse_json_argument(args.query, "query")
        if query_params is None:
            return None
        params["query"] = query_params

    if args.json_body:
        json_params = parse_json_argument(args.json_body, "json")
        if json_params is None:
            return None
        params["json"] = json_params

    if args.headers:
        headers_params = parse_json_argument(args.headers, "headers")
        if headers_params is None:
            return None
        params["headers"] = headers_params

    return params


def build_wrapper_params(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build parameters for wrapper methods."""
    params: dict[str, Any] = {}

    if args.query:
        query_params = parse_json_argument(args.query, "query")
        if query_params is None:
            return None
        params.update(query_params)

    if args.json_body:
        json_params = parse_json_argument(args.json_body, "json")
        if json_params is None:
            return None
        # Many wrappers accept a single dict payload (e.g., ticket_create, filter_create)
        # We place it under a conventional key if the wrapper expects a single positional
        # parameter; analyzer will pass kwargs unchanged.
        # For example: --method=ticket_create --json '{"reference": ..., ...}'
        params = json_params

    return params


def build_payload(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build the complete payload for the analyzer."""
    method = args.method

    params = build_call_params(args) if method == "call" else build_wrapper_params(args)

    if params is None:
        return None

    return {"method": method, "params": params}


def main(argv: list[str]) -> int:
    """Run the Axur analyzer example."""
    ap = create_argument_parser()
    args = ap.parse_args(argv)

    payload = build_payload(args)
    if payload is None:
        return 2

    input_data = WorkerInput(
        data_type="other",
        data=json.dumps(payload),
        config=WorkerConfig(secrets={"axur": {"api_token": args.token}}),
    )

    # For programmatic result, call execute(); run() performs side-effect only
    report = AxurAnalyzer(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
