"""Kafka Consumer example for SentinelIQ SDK."""

from __future__ import annotations

import argparse
import json
import sys

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.consumers import KafkaConsumer
from sentineliqsdk.messaging import MessageConfig, QueueConfig


def main() -> None:
    """Run Kafka Consumer example."""
    parser = argparse.ArgumentParser(description="Kafka Consumer Example")
    parser.add_argument("--topic", default="sentineliq-events", help="Kafka topic to consume")
    parser.add_argument("--group-id", default="sentineliq-consumer", help="Consumer group ID")
    parser.add_argument("--max-messages", type=int, default=5, help="Maximum messages to consume")
    parser.add_argument("--execute", action="store_true", help="Execute real consumption")
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )

    args = parser.parse_args()

    # Create input data
    input_data = WorkerInput(
        data_type="other",
        data="consumer_data",
        config=WorkerConfig(
            params={
                "max_messages": args.max_messages,
                "timeout_ms": 5000,
            },
            secrets={
                "kafka.bootstrap_servers": "localhost:9092",
                "kafka.security_protocol": "PLAINTEXT",
                "kafka.group_id": args.group_id,
            },
        ),
    )

    # Create consumer
    consumer = KafkaConsumer(input_data)

    # Configure queue
    queue_config = QueueConfig(
        queue_name=args.topic,
        durable=True,
        auto_delete=False,
    )
    consumer.configure_queue(queue_config)

    # Configure messaging
    message_config = MessageConfig(
        auto_ack=False,
        prefetch_count=1,
    )
    consumer.configure_messaging(message_config)

    if args.execute:
        try:
            # Start consuming messages
            report = consumer.start_consuming()

            # Print result
            result = {
                "success": report.success,
                "messages_processed": report.messages_processed,
                "messages_failed": report.messages_failed,
                "processing_time": report.processing_time,
                "full_report": report.full_report,
            }

            print(json.dumps(result, ensure_ascii=False, indent=2))

        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "message": "Failed to consume messages",
            }
            print(json.dumps(error_result, ensure_ascii=False, indent=2))
            sys.exit(1)

        finally:
            consumer.stop()
    else:
        # Dry run - show what would be consumed
        dry_run_result = {
            "mode": "dry_run",
            "message": "Would consume messages from the following topic:",
            "topic": args.topic,
            "group_id": args.group_id,
            "max_messages": args.max_messages,
            "note": "Use --execute to actually consume messages",
        }
        print(json.dumps(dry_run_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
