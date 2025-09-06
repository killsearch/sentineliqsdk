from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.responders.kafka_rest import KafkaResponder


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish to Kafka via REST Proxy (Responder)")
    parser.add_argument("--rest-url", required=True, help="REST proxy base URL")
    parser.add_argument("--topic", required=True, help="Topic name")
    parser.add_argument("--message", required=True, help="Message value (string)")
    parser.add_argument("--headers", default=None, help="JSON headers")
    parser.add_argument(
        "--auth",
        default=None,
        help="Basic auth as user:pass (optional)",
    )
    parser.add_argument("--execute", action="store_true", help="Perform the publish")
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Acknowledge impactful action",
    )

    args = parser.parse_args()

    params = {
        "kafka": {
            "base_url": args.rest_url,
            "topic": args.topic,
            "value": args.message,
            "headers": json.loads(args.headers) if args.headers else {},
        },
        "execute": bool(args.execute),
        "include_dangerous": bool(args.include_dangerous),
    }
    secrets: dict[str, dict[str, str]] = {}
    if args.auth:
        secrets.setdefault("kafka", {})["basic_auth"] = args.auth

    input_data = WorkerInput(
        data_type="other",
        data=args.message,
        config=WorkerConfig(params=params, secrets=secrets),
    )
    report = KafkaResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
