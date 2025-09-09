"""Complete Threat Detection System example for SentinelIQ SDK."""

from __future__ import annotations

import argparse
import json
import sys

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.consumers import PipelineConsumer
from sentineliqsdk.messaging import MessageConfig, QueueConfig
from sentineliqsdk.pipelines import SecurityPipeline
from sentineliqsdk.producers import KafkaProducer


class ThreatDetectionSystem:
    """Complete threat detection system using Producer/Consumer + Pipeline."""

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self.setup_pipeline()
        self.setup_producer()
        self.setup_consumer()

    def setup_pipeline(self):
        """Set up security pipeline."""
        pipeline_input = WorkerInput(
            data_type="other",
            data="security_pipeline",
            config=WorkerConfig(
                params={
                    "auto_respond": True,
                    "response_threshold": "suspicious",
                },
                secrets={
                    "kafka.bootstrap_servers": self.bootstrap_servers,
                    "kafka.security_protocol": "PLAINTEXT",
                    "shodan.api_key": "your_shodan_api_key",
                },
            ),
        )

        self.pipeline = SecurityPipeline(pipeline_input)

    def setup_producer(self):
        """Set up event producer."""
        producer_input = WorkerInput(
            data_type="other",
            data="threat_detector",
            config=WorkerConfig(
                secrets={
                    "kafka.bootstrap_servers": self.bootstrap_servers,
                    "kafka.security_protocol": "PLAINTEXT",
                }
            ),
        )

        self.producer = KafkaProducer(producer_input)
        self.producer.configure_queue(QueueConfig(queue_name="security-events"))
        self.producer.configure_messaging(MessageConfig(delivery_mode="persistent"))

    def setup_consumer(self):
        """Set up event consumer."""
        consumer_input = WorkerInput(
            data_type="other",
            data="threat_processor",
            config=WorkerConfig(
                params={"max_messages": 100},
                secrets={
                    "kafka.bootstrap_servers": self.bootstrap_servers,
                    "kafka.security_protocol": "PLAINTEXT",
                    "kafka.group_id": "threat-processor",
                },
            ),
        )

        self.consumer = PipelineConsumer(consumer_input, pipeline=self.pipeline)
        self.consumer.configure_queue(QueueConfig(queue_name="security-events"))
        self.consumer.configure_messaging(MessageConfig(auto_ack=False))

    def detect_threat(self, ip: str, source: str = "unknown") -> str | None:
        """Detect and respond to a threat."""
        # Create threat event message
        threat_event = self.producer.build_message(
            message_type="event",
            data_type="ip",
            data=ip,
            priority="high",
            tags={"source": source, "event_type": "threat_detected"},
        )

        producer_report = self.producer.publish(threat_event)

        if producer_report.success:
            print(f"Threat event published for IP: {ip}")
            return producer_report.message_id
        print(f"Failed to publish threat event: {producer_report.error_message}")
        return None

    def process_threat_events(self):
        """Process threat events from the queue."""
        print("Starting threat event processing...")

        try:
            report = self.consumer.start_consuming()

            if report.success:
                print(f"Processed {report.messages_processed} threat events")
                print(f"Failed: {report.messages_failed}")
                print(f"Processing time: {report.processing_time:.2f}s")
            else:
                print(f"Consumer failed: {report.error_message}")

        except Exception as e:
            print(f"Error processing threats: {e}")
        finally:
            self.consumer.stop()

    def close(self):
        """Close all connections."""
        self.producer.close()
        self.consumer.stop()


def main() -> None:
    """Run Complete Threat Detection System example."""
    parser = argparse.ArgumentParser(description="Complete Threat Detection System Example")
    parser.add_argument(
        "--bootstrap-servers", default="localhost:9092", help="Kafka bootstrap servers"
    )
    parser.add_argument(
        "--threats",
        nargs="+",
        default=["192.168.1.100", "10.0.0.50", "172.16.0.25"],
        help="IP addresses to analyze as threats",
    )
    parser.add_argument("--execute", action="store_true", help="Execute real processing")
    parser.add_argument(
        "--include-dangerous", action="store_true", help="Include dangerous operations"
    )

    args = parser.parse_args()

    if args.execute:
        try:
            # Initialize threat detection system
            tds = ThreatDetectionSystem(args.bootstrap_servers)

            # Detect some threats
            print("Detecting threats...")
            message_ids = []

            for threat_ip in args.threats:
                message_id = tds.detect_threat(threat_ip, "firewall")
                if message_id:
                    message_ids.append(message_id)
                    print(f"Threat detection initiated: {message_id}")

            if message_ids:
                print(f"\nPublished {len(message_ids)} threat events")

                # Process the threats
                print("\nProcessing threats...")
                tds.process_threat_events()
            else:
                print("No threats were published successfully")

            # Close connections
            tds.close()

        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "message": "Failed to run threat detection system",
            }
            print(json.dumps(error_result, ensure_ascii=False, indent=2))
            sys.exit(1)
    else:
        # Dry run
        dry_run_result = {
            "mode": "dry_run",
            "message": "Would run complete threat detection system:",
            "bootstrap_servers": args.bootstrap_servers,
            "threats": args.threats,
            "components": {
                "producer": "KafkaProducer",
                "consumer": "PipelineConsumer",
                "pipeline": "SecurityPipeline",
            },
            "note": "Use --execute to actually run the system",
        }
        print(json.dumps(dry_run_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
