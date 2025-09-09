"""CyberChef analyzer example.

Send input to a CyberChef server and print the result (requires --execute).
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cyberchef import CyberchefAnalyzer


def main() -> None:
    """Parse CLI args, run analyzer, and print compact JSON result."""
    parser = argparse.ArgumentParser(description="Run CyberchefAnalyzer example")
    parser.add_argument("data", help="Input string to process (e.g., 666f6f)")
    parser.add_argument(
        "--service",
        required=True,
        choices=["FromHex", "FromBase64", "FromCharCode"],
        help="CyberChef recipe/service to use",
    )
    parser.add_argument(
        "--url", required=True, help="CyberChef base URL (e.g., http://localhost:8000)"
    )
    parser.add_argument("--execute", action="store_true", help="Actually call CyberChef server")
    args = parser.parse_args()

    params: dict[str, object] = {
        "cyberchef.url": args.url,
        "cyberchef.service": args.service,
    }

    input_data = WorkerInput(
        data_type="other",
        data=args.data,
        config=WorkerConfig(params=params),
    )

    analyzer = CyberchefAnalyzer(input_data)
    if not args.execute:
        print(json.dumps({"success": False, "errorMessage": "Use --execute to run"}))
        return
    report = analyzer.execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
