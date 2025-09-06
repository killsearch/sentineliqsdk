from __future__ import annotations

import argparse
import json
import os

from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.webhook import WebhookResponder


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger a webhook (Responder)")
    parser.add_argument("--url", required=True, help="Webhook URL")
    parser.add_argument(
        "--method",
        default="POST",
        choices=["GET", "POST"],
        help="HTTP method (default POST)",
    )
    parser.add_argument("--headers", default=None, help="JSON headers for request")
    parser.add_argument("--body", default=None, help="Body (string or JSON)")
    parser.add_argument("--execute", action="store_true", help="Perform the request")
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Acknowledge impactful action",
    )

    args = parser.parse_args()
    os.environ["SENTINELIQ_EXECUTE"] = "1" if args.execute else "0"
    os.environ["SENTINELIQ_INCLUDE_DANGEROUS"] = "1" if args.include_dangerous else "0"
    os.environ["WEBHOOK_METHOD"] = args.method
    if args.headers:
        os.environ["WEBHOOK_HEADERS"] = args.headers
    if args.body is not None:
        os.environ["WEBHOOK_BODY"] = args.body

    input_data = WorkerInput(data_type="url", data=args.url)
    report = WebhookResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
