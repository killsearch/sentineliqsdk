"""Kafka Producer example for SentinelIQ SDK."""

from __future__ import annotations

import argparse
import json
import sys

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.messaging import MessageConfig, QueueConfig
from sentineliqsdk.producers import KafkaProducer


def main() -> None:
    """Run Kafka Producer example."""
    parser = argparse.ArgumentParser(description="Kafka Producer Example")
    parser.add_argument("--data", default="Hello from SentinelIQ!", help="Data to publish")
    parser.add_argument("--topic", default="sentineliq-events", help="Kafka topic")
    parser.add_argument("--execute", action="store_true", help="Execute real publishing")
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )

    args = parser.parse_args()

    # Create input data
    input_data = WorkerInput(
        data_type="other",
        data=args.data,
        config=WorkerConfig(
            secrets={
                "kafka.bootstrap_servers": "localhost:9092",
                "kafka.security_protocol": "PLAINTEXT",
            }
        ),
    )

    # Create producer
    producer = KafkaProducer(input_data)

    # Configure queue
    queue_config = QueueConfig(
        queue_name=args.topic,
        durable=True,
        auto_delete=False,
    )
    producer.configure_queue(queue_config)

    # Configure messaging
    message_config = MessageConfig(
        delivery_mode="persistent",
        mandatory=True,
    )
    producer.configure_messaging(message_config)

    if args.execute:
        try:
            # Publish message
            report = producer.run()

            # Print result
            result = {
                "success": report.success,
                "message_id": report.message_id,
                "queue_name": report.queue_name,
                "delivery_confirmed": report.delivery_confirmed,
                "full_report": report.full_report,
            }

            print(json.dumps(result, ensure_ascii=False, indent=2))

        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "message": "Failed to publish message",
            }
            print(json.dumps(error_result, ensure_ascii=False, indent=2))
            sys.exit(1)

        finally:
            producer.close()
    else:
        # Dry run - show what would be published
        dry_run_result = {
            "mode": "dry_run",
            "message": "Would publish the following message:",
            "data": args.data,
            "topic": args.topic,
            "note": "Use --execute to actually publish the message",
        }
        print(json.dumps(dry_run_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
