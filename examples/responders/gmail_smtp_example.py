from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.responders.smtp_gmail import GmailSmtpResponder


def main() -> None:
    parser = argparse.ArgumentParser(description="Send an email via Gmail SMTP (Responder)")
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

    parser.add_argument("--username", default=None, help="Gmail username (optional; else env)")
    parser.add_argument("--password", default=None, help="Gmail app password (optional; else env)")
    # Credentials via env still supported: GMAIL_SMTP_USER, GMAIL_SMTP_PASSWORD
    args = parser.parse_args()

    # Prefer programmatic config via WorkerConfig
    secrets: dict[str, dict[str, str]] = {}
    if args.username:
        secrets.setdefault("gmail", {})["username"] = args.username
    if args.password:
        secrets.setdefault("gmail", {})["password"] = args.password

    params = {
        "email": {"from": args.from_addr, "subject": args.subject, "body": args.body},
        "execute": bool(args.execute),
        "include_dangerous": bool(args.include_dangerous),
    }

    input_data = WorkerInput(
        data_type="mail",
        data=args.to,
        config=WorkerConfig(params=params, secrets=secrets),
    )
    report = GmailSmtpResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
