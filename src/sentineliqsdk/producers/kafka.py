"""Kafka Producer implementation for SentinelIQ SDK."""

from __future__ import annotations

import json
import time
from typing import Any

from sentineliqsdk.constants import REQUEST_TIMEOUT_MS
from sentineliqsdk.messaging import Message, ProducerReport
from sentineliqsdk.models import ModuleMetadata, WorkerInput
from sentineliqsdk.producers.base import Producer


class KafkaProducer(Producer):
    """Kafka message producer with delivery confirmation and error handling."""

    METADATA = ModuleMetadata(
        name="Kafka Producer",
        description="Produces messages to Kafka topics with delivery confirmation",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="kafka",
        doc_pattern="Kafka producer with topic management and delivery confirmation",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/producers/kafka_producer/",
        version_stage="TESTING",
    )

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self._kafka_client: Any | None = None
        self._producer: Any | None = None

    def _get_kafka_config(self) -> dict[str, Any]:
        """Get Kafka configuration from secrets."""
        return {
            "bootstrap_servers": self.get_secret("kafka.bootstrap_servers", "localhost:9092"),
            "security_protocol": self.get_secret("kafka.security_protocol", "PLAINTEXT"),
            "sasl_mechanism": self.get_secret("kafka.sasl_mechanism"),
            "sasl_username": self.get_secret("kafka.sasl_username"),
            "sasl_password": self.get_secret("kafka.sasl_password"),
            "ssl_cafile": self.get_secret("kafka.ssl_cafile"),
            "ssl_certfile": self.get_secret("kafka.ssl_certfile"),
            "ssl_keyfile": self.get_secret("kafka.ssl_keyfile"),
        }

    def _ensure_producer(self) -> None:
        """Ensure Kafka producer is initialized."""
        if self._producer is None:
            try:
                from kafka import KafkaProducer  # type: ignore  # noqa: PLC0415

                config = self._get_kafka_config()
                # Remove None values
                config = {k: v for k, v in config.items() if v is not None}

                self._producer = KafkaProducer(
                    bootstrap_servers=config["bootstrap_servers"],
                    security_protocol=config.get("security_protocol", "PLAINTEXT"),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    acks="all",  # Wait for all replicas to acknowledge
                    retries=3,
                    retry_backoff_ms=1000,
                    request_timeout_ms=REQUEST_TIMEOUT_MS,
                    **{k: v for k, v in config.items() if k.startswith(("sasl_", "ssl_"))},
                )
            except ImportError:
                self.error("kafka-python package is required for KafkaProducer")

    def publish(self, message: Message) -> ProducerReport:
        """Publish message to Kafka topic."""
        if not self.queue_config:
            self.error("Queue configuration is required")

        self._ensure_producer()

        try:
            # Prepare message payload
            payload = {
                "message_type": message.message_type,
                "data_type": message.data_type,
                "data": message.data,
                "metadata": {
                    "message_id": message.metadata.message_id,
                    "correlation_id": message.metadata.correlation_id,
                    "timestamp": message.metadata.timestamp or time.time(),
                    "priority": message.metadata.priority,
                    "tags": dict(message.metadata.tags),
                },
                "payload": dict(message.payload),
            }

            # Send message
            future = self._producer.send(  # type: ignore
                self.queue_config.queue_name,  # Use queue_name as topic
                value=payload,
                key=message.metadata.message_id,
            )

            # Wait for delivery confirmation
            record_metadata = future.get(timeout=30)

            full_report = {
                "message_id": message.metadata.message_id,
                "topic": record_metadata.topic,
                "partition": record_metadata.partition,
                "offset": record_metadata.offset,
                "delivery_confirmed": True,
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

        except Exception as e:
            full_report = {
                "message_id": message.metadata.message_id,
                "delivery_confirmed": False,
                "error_message": str(e),
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

    def run(self) -> ProducerReport:
        """Publish the input data as a message."""
        data = self.get_data()

        message = self.build_message(
            message_type="event",
            data_type=self.data_type,
            data=str(data),
            correlation_id=self.get_config("correlation_id"),
        )

        return self.publish(message)

    def close(self) -> None:
        """Close the Kafka producer."""
        if self._producer:
            self._producer.close()
            self._producer = None
