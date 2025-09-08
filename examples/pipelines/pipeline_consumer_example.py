"""Pipeline Consumer example for SentinelIQ SDK."""

from __future__ import annotations

import argparse
import json
import sys

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.consumers import PipelineConsumer
from sentineliqsdk.messaging import MessageConfig, QueueConfig
from sentineliqsdk.pipelines import SecurityPipeline


def main() -> None:
    """Run Pipeline Consumer example."""
    parser = argparse.ArgumentParser(description="Pipeline Consumer Example")
    parser.add_argument("--topic", default="security-events", help="Kafka topic to consume")
    parser.add_argument("--group-id", default="pipeline-consumer", help="Consumer group ID")
    parser.add_argument("--max-messages", type=int, default=5, help="Maximum messages to consume")
    parser.add_argument("--execute", action="store_true", help="Execute real consumption")
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )

    args = parser.parse_args()

    # Create pipeline
    pipeline_input = WorkerInput(
        data_type="other",
        data="security_pipeline",
        config=WorkerConfig(
            params={
                "auto_respond": args.include_dangerous,
                "response_threshold": "suspicious",
            },
            secrets={
                "kafka.bootstrap_servers": "localhost:9092",
                "kafka.security_protocol": "PLAINTEXT",
                "kafka.group_id": args.group_id,
                "shodan.api_key": "your_shodan_api_key",
            },
        ),
    )

    pipeline = SecurityPipeline(pipeline_input)

    # Create consumer with pipeline
    consumer_input = WorkerInput(
        data_type="other",
        data="pipeline_consumer",
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

    consumer = PipelineConsumer(consumer_input, pipeline=pipeline)

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
                "pipeline_type": pipeline.__class__.__name__,
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
        # Dry run
        dry_run_result = {
            "mode": "dry_run",
            "message": "Would consume messages from the following topic:",
            "topic": args.topic,
            "group_id": args.group_id,
            "max_messages": args.max_messages,
            "pipeline_type": pipeline.__class__.__name__,
            "note": "Use --execute to actually consume messages",
        }
        print(json.dumps(dry_run_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
