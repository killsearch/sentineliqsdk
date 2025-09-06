from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
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

    headers = json.loads(args.headers) if args.headers else {}
    body = None
    if args.body is not None:
        # Try to parse JSON, fallback to plain string
        try:
            body = json.loads(args.body)
        except Exception:
            body = args.body

    params = {
        "webhook": {"url": args.url, "method": args.method, "headers": headers, "body": body},
        "execute": bool(args.execute),
        "include_dangerous": bool(args.include_dangerous),
    }

    input_data = WorkerInput(data_type="url", data=args.url, config=WorkerConfig(params=params))
    report = WebhookResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
