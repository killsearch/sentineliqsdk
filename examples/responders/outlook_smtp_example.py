from __future__ import annotations

import argparse
import json
import os

from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.smtp_outlook import OutlookSmtpResponder


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send an email via Outlook/Office365 SMTP (Responder)"
    )
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--subject", default="SentinelIQ Notification")
    parser.add_argument("--body", default="Hello from SentinelIQ SDK.")
    parser.add_argument("--from_", dest="from_addr", default=None, help="From address")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform the SMTP send (otherwise dry-run)",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Acknowledge impactful action (required to actually send)",
    )

    # Credentials via env: OUTLOOK_SMTP_USER, OUTLOOK_SMTP_PASSWORD
    args = parser.parse_args()

    os.environ["SENTINELIQ_EXECUTE"] = "1" if args.execute else "0"
    os.environ["SENTINELIQ_INCLUDE_DANGEROUS"] = "1" if args.include_dangerous else "0"
    os.environ["EMAIL_SUBJECT"] = args.subject
    os.environ["EMAIL_BODY"] = args.body
    if args.from_addr:
        os.environ["EMAIL_FROM"] = args.from_addr

    input_data = WorkerInput(data_type="mail", data=args.to)
    report = OutlookSmtpResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
