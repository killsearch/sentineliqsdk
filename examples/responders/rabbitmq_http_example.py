from __future__ import annotations

import argparse
import json
import os

from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish to RabbitMQ via HTTP API (Responder)")
    parser.add_argument("--api-url", required=True, help="RabbitMQ HTTP API base URL")
    parser.add_argument("--vhost", default="/", help="RabbitMQ vhost (default /)")
    parser.add_argument("--exchange", required=True, help="Exchange name")
    parser.add_argument("--routing-key", default="", help="Routing key (default empty)")
    parser.add_argument("--message", required=True, help="Message value (string)")
    parser.add_argument("--properties", default=None, help="JSON properties (optional)")
    parser.add_argument("--username", default=None, help="Basic auth username")
    parser.add_argument("--password", default=None, help="Basic auth password")
    parser.add_argument("--execute", action="store_true", help="Perform the publish")
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Acknowledge impactful action",
    )

    args = parser.parse_args()
    os.environ["SENTINELIQ_EXECUTE"] = "1" if args.execute else "0"
    os.environ["SENTINELIQ_INCLUDE_DANGEROUS"] = "1" if args.include_dangerous else "0"
    os.environ["RABBITMQ_API_URL"] = args.api_url
    os.environ["RABBITMQ_VHOST"] = args.vhost
    os.environ["RABBITMQ_EXCHANGE"] = args.exchange
    os.environ["RABBITMQ_ROUTING_KEY"] = args.routing_key
    os.environ["RABBITMQ_MESSAGE"] = args.message
    if args.properties:
        os.environ["RABBITMQ_PROPERTIES"] = args.properties
    if args.username:
        os.environ["RABBITMQ_USERNAME"] = args.username
    if args.password:
        os.environ["RABBITMQ_PASSWORD"] = args.password

    input_data = WorkerInput(data_type="other", data=args.message)
    report = RabbitMqResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
