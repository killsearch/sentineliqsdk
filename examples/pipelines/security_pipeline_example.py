"""Security Pipeline example for SentinelIQ SDK."""

from __future__ import annotations

import argparse
import json
import sys
import time

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.messaging import Message, MessageMetadata
from sentineliqsdk.pipelines import SecurityPipeline


def main() -> None:
    """Run Security Pipeline example."""
    parser = argparse.ArgumentParser(description="Security Pipeline Example")
    parser.add_argument("--data", default="192.168.1.100", help="IP address to analyze")
    parser.add_argument("--topic", default="security-events", help="Kafka topic")
    parser.add_argument("--execute", action="store_true", help="Execute real processing")
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
                "shodan.api_key": "your_shodan_api_key",
            },
        ),
    )

    pipeline = SecurityPipeline(pipeline_input)

    if args.execute:
        try:
            # Create test message
            message = Message(
                message_type="event",
                data_type="ip",
                data=args.data,
                metadata=MessageMetadata(
                    message_id=f"test_{int(time.time())}",
                    priority="high",
                    tags={"source": "example", "event_type": "threat_detected"},
                ),
                payload={"secrets": {"shodan.api_key": "your_shodan_api_key"}},
            )

            # Process through pipeline
            result = pipeline.process_message(message)

            print(json.dumps(result, ensure_ascii=False, indent=2))

        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "message": "Failed to process security event",
            }
            print(json.dumps(error_result, ensure_ascii=False, indent=2))
            sys.exit(1)
    else:
        # Dry run
        dry_run_result = {
            "mode": "dry_run",
            "message": "Would process security event through pipeline:",
            "data": args.data,
            "topic": args.topic,
            "pipeline": "SecurityPipeline",
            "note": "Use --execute to actually process the event",
        }
        print(json.dumps(dry_run_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
