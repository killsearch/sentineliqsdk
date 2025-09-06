from __future__ import annotations

import argparse
import json
import os

from sentineliqsdk import WorkerInput
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
    os.environ["SENTINELIQ_EXECUTE"] = "1" if args.execute else "0"
    os.environ["SENTINELIQ_INCLUDE_DANGEROUS"] = "1" if args.include_dangerous else "0"
    os.environ["KAFKA_REST_URL"] = args.rest_url
    os.environ["KAFKA_TOPIC"] = args.topic
    os.environ["KAFKA_VALUE"] = args.message
    if args.headers:
        os.environ["KAFKA_HEADERS"] = args.headers
    if args.auth:
        os.environ["KAFKA_REST_AUTH"] = args.auth

    input_data = WorkerInput(data_type="other", data=args.message)
    report = KafkaResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
