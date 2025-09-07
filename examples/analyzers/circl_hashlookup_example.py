"""Execute CirclHashlookupAnalyzer for all supported methods.

This example demonstrates the CIRCL hashlookup analyzer capabilities including
basic hash lookups, bulk operations, parent/child relationships, and session
management.

Usage:
  python examples/analyzers/circl_hashlookup_example.py --execute           # perform calls
  python examples/analyzers/circl_hashlookup_example.py                     # dry-run (plan only)

Flags:
  --only method1,method2     run a subset
  --skip method1,method2     skip some methods
  --include-dangerous        include session creation methods
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import ALLOWED_METHODS, CirclHashlookupAnalyzer

# Sample hashes for testing
SAMPLE_HASHES = {
    "md5": "5d41402abc4b2a76b9719d911017c592",  # "hello"
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # "hello"
    "sha256": "2cf24dba4f21a03f4b3d914f42305d25206eaf64a81f73b3e4e5b9bd3e978038",  # "hello"
}

SAFE_DEFAULT_PARAMS: dict[str, dict[str, Any]] = {
    # Basic lookups
    "lookup_md5": {"hash": SAMPLE_HASHES["md5"]},
    "lookup_sha1": {"hash": SAMPLE_HASHES["sha1"]},
    "lookup_sha256": {"hash": SAMPLE_HASHES["sha256"]},
    # Bulk operations
    "bulk_md5": {"hashes": [SAMPLE_HASHES["md5"], "d41d8cd98f00b204e9800998ecf8427e"]},
    "bulk_sha1": {"hashes": [SAMPLE_HASHES["sha1"], "da39a3ee5e6b4b0d3255bfef95601890afd80709"]},
    # Relationships (using SHA1)
    "get_children": {"sha1": SAMPLE_HASHES["sha1"], "count": 5, "cursor": "0"},
    "get_parents": {"sha1": SAMPLE_HASHES["sha1"], "count": 5, "cursor": "0"},
    # Utility methods
    "get_info": {},
    "get_stats_top": {},
    # Session methods (potentially dangerous as they create state)
    "create_session": {"name": "test-session"},
    "get_session": {"name": "test-session"},
}

DANGEROUS_METHODS = {
    "create_session",
    "get_session",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Run CirclHashlookupAnalyzer for all supported methods"
    )
    ap.add_argument("--execute", action="store_true", help="perform API calls (else dry-run)")
    ap.add_argument("--only", default=None, help="comma-separated methods to include")
    ap.add_argument("--skip", default=None, help="comma-separated methods to skip")
    ap.add_argument(
        "--include-dangerous",
        action="store_true",
        help="include session creation methods",
    )
    args = ap.parse_args(argv)

    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()

    # Prepare a base input (no API key needed for CIRCL)
    input_data = WorkerInput(
        data_type="other",
        data="{}",
    )

    total = 0
    ok = 0
    for method in sorted(ALLOWED_METHODS):
        if only and method not in only:
            continue
        if method in skip:
            continue
        if not args.include_dangerous and method in DANGEROUS_METHODS:
            continue

        params = SAFE_DEFAULT_PARAMS.get(method, {})
        total += 1
        print(f"==> run {method} with params={params}")

        # Inject dynamic method/params via config
        input_data = WorkerInput(
            data_type="other",
            data="{}",
            config=WorkerConfig(
                params={"circl": {"method": method, "params": params}},
            ),
        )

        if not args.execute:
            continue

        try:
            # For programmatic result, use execute(); run() performs side-effects only
            analyzer = CirclHashlookupAnalyzer(input_data)
            report = analyzer.execute()
            payload = {
                "success": report.success,
                "verdict": report.full_report.get("verdict"),
                "method": report.full_report.get("details", {}).get("method"),
                "result_type": type(report.full_report.get("details", {}).get("result")).__name__,
            }
            print(json.dumps(payload, ensure_ascii=False))
            ok += 1
        except Exception as e:
            print(f"ERROR: {e}")

    print(f"\nPlanned: {total} | Executed OK: {ok if args.execute else 0}")
    return 0


def demo_basic_hash_lookup():
    """Demonstrate basic hash lookup functionality."""
    print("\n=== Basic Hash Lookup Demo ===")

    # Test with a known hash
    input_data = WorkerInput(
        data_type="hash",
        data=SAMPLE_HASHES["md5"],
    )

    analyzer = CirclHashlookupAnalyzer(input_data)
    report = analyzer.execute()

    print(f"Hash: {SAMPLE_HASHES['md5']}")
    print(f"Verdict: {report.full_report.get('verdict')}")
    print(f"Taxonomy: {report.full_report.get('taxonomy', [])}")
    print(f"Details: {json.dumps(report.full_report.get('details', {}), indent=2)}")


def demo_bulk_lookup():
    """Demonstrate bulk hash lookup functionality."""
    print("\n=== Bulk Hash Lookup Demo ===")

    # Test bulk MD5 lookup
    input_data = WorkerInput(
        data_type="other",
        data=json.dumps(
            {
                "method": "bulk_md5",
                "params": {"hashes": [SAMPLE_HASHES["md5"], "d41d8cd98f00b204e9800998ecf8427e"]},
            }
        ),
    )

    analyzer = CirclHashlookupAnalyzer(input_data)
    report = analyzer.execute()

    print(f"Bulk lookup result: {json.dumps(report.full_report.get('details', {}), indent=2)}")


def demo_relationships():
    """Demonstrate parent/child relationship lookup."""
    print("\n=== Relationship Lookup Demo ===")

    # Test children lookup
    input_data = WorkerInput(
        data_type="other",
        data=json.dumps(
            {
                "method": "get_children",
                "params": {"sha1": SAMPLE_HASHES["sha1"], "count": 3, "cursor": "0"},
            }
        ),
    )

    analyzer = CirclHashlookupAnalyzer(input_data)
    report = analyzer.execute()

    print(f"Children lookup result: {json.dumps(report.full_report.get('details', {}), indent=2)}")


if __name__ == "__main__":
    import sys as _sys

    if len(_sys.argv) == 1:
        # Run demos if no arguments provided
        demo_basic_hash_lookup()
        demo_bulk_lookup()
        demo_relationships()
    else:
        raise SystemExit(main(_sys.argv[1:]))
