"""RabbitMQ HTTP Responder Example.

This example demonstrates how to use the RabbitMQ HTTP Responder to publish
messages to RabbitMQ exchanges via HTTP API.
"""

from __future__ import annotations

import argparse
import json

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder


def main() -> None:
    """Run the RabbitMQ HTTP Responder example."""
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

    params = {
        "rabbitmq": {
            "api_url": args.api_url,
            "vhost": args.vhost,
            "exchange": args.exchange,
            "routing_key": args.routing_key,
            "message": args.message,
            "properties": json.loads(args.properties) if args.properties else {},
        },
        "execute": bool(args.execute),
        "include_dangerous": bool(args.include_dangerous),
    }
    secrets: dict[str, dict[str, str]] = {}
    if args.username:
        secrets.setdefault("rabbitmq", {})["username"] = args.username
    if args.password:
        secrets.setdefault("rabbitmq", {})["password"] = args.password

    input_data = WorkerInput(
        data_type="other",
        data=args.message,
        config=WorkerConfig(params=params, secrets=secrets),
    )
    report = RabbitMqResponder(input_data).execute()
    print(json.dumps(report.full_report, ensure_ascii=False))


if __name__ == "__main__":
    main()
