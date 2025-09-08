"""Pipeline Consumer implementation for SentinelIQ SDK."""

from __future__ import annotations

import json
import time
from typing import Any

from sentineliqsdk.consumers.base import Consumer
from sentineliqsdk.messaging import ConsumerReport, Message, MessageMetadata
from sentineliqsdk.models import ModuleMetadata, WorkerInput
from sentineliqsdk.pipelines.base import Pipeline


class PipelineConsumer(Consumer):
    """Consumer that processes messages through a pipeline."""

    METADATA = ModuleMetadata(
        name="Pipeline Consumer",
        description="Consumer that processes messages through configurable pipelines",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="pipeline",
        doc_pattern="Consumer with pipeline integration for message processing",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/consumers/pipeline_consumer/",
        version_stage="TESTING",
    )

    def __init__(
        self,
        input_data: WorkerInput,
        pipeline: Pipeline | None = None,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.pipeline: Pipeline | None = pipeline
        self._consumer: Any | None = None
        self._running: bool = False

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
            "group_id": self.get_secret("kafka.group_id", "pipeline-consumer"),
        }

    def _ensure_consumer(self) -> None:
        """Ensure Kafka consumer is initialized."""
        if self._consumer is None:
            try:
                from kafka import KafkaConsumer  # type: ignore  # noqa: PLC0415

                config = self._get_kafka_config()
                # Remove None values
                config = {k: v for k, v in config.items() if v is not None}

                if self.queue_config is None:
                    self.error("Queue configuration is required for pipeline consumer")

                self._consumer = KafkaConsumer(
                    self.queue_config.queue_name,  # Use queue_name as topic
                    bootstrap_servers=config["bootstrap_servers"],
                    security_protocol=config.get("security_protocol", "PLAINTEXT"),
                    group_id=config.get("group_id", "pipeline-consumer"),
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    key_deserializer=lambda m: m.decode("utf-8") if m else None,
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    auto_commit_interval_ms=1000,
                    **{k: v for k, v in config.items() if k.startswith(("sasl_", "ssl_"))},
                )
            except ImportError:
                self.error("kafka-python package is required for PipelineConsumer")

    def _kafka_message_to_message(self, kafka_msg: Any) -> Message:
        """Convert Kafka message to internal Message format."""
        payload = kafka_msg.value
        metadata_dict = payload.get("metadata", {})

        metadata = MessageMetadata(
            message_id=metadata_dict.get("message_id", f"kafka_{kafka_msg.offset}"),
            correlation_id=metadata_dict.get("correlation_id"),
            timestamp=metadata_dict.get("timestamp"),
            priority=metadata_dict.get("priority", "normal"),
            tags=metadata_dict.get("tags", {}),
        )

        return Message(
            message_type=payload.get("message_type", "event"),
            data_type=payload.get("data_type", "other"),
            data=payload.get("data", ""),
            metadata=metadata,
            payload=payload.get("payload", {}),
        )

    def consume(self, message: Message) -> ConsumerReport:
        """Process a consumed message through the pipeline."""
        try:
            if not self.pipeline:
                self._record_failure()
                full_report = {
                    "message_id": message.metadata.message_id,
                    "error_message": "No pipeline configured",
                    "metadata": self.METADATA.to_dict(),
                }
                return self.report(full_report)

            # Process through pipeline
            result = self.pipeline.process_message(message)

            self._record_success()

            full_report = {
                "message_id": message.metadata.message_id,
                "data_type": message.data_type,
                "data": message.data,
                "pipeline_result": result,
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

        except Exception as e:
            self._record_failure()

            full_report = {
                "message_id": message.metadata.message_id,
                "error_message": str(e),
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

    def _process_message(self, message: Message) -> dict[str, Any]:
        """Process message through pipeline."""
        if not self.pipeline:
            return {
                "error": "No pipeline configured",
                "processed_at": time.time(),
            }

        result = self.pipeline.process_message(message)
        return {
            "processed_at": time.time(),
            "pipeline_result": result,
            "status": "completed" if result.get("pipeline_status") == "completed" else "failed",
        }

    def start_consuming(self) -> ConsumerReport:
        """Start consuming messages from Kafka topic."""
        if not self.queue_config:
            self.error("Queue configuration is required")

        self._ensure_consumer()
        self._running = True

        try:
            max_messages = self.get_config("max_messages", 10)

            messages_processed = 0

            consumer = self._consumer
            if consumer is None:
                self.error("Consumer is not initialized")

            for kafka_msg in consumer:
                if not self._running or messages_processed >= max_messages:
                    break

                message = self._kafka_message_to_message(kafka_msg)
                self.consume(message)
                messages_processed += 1

            full_report = {
                "messages_processed": messages_processed,
                "topic": self.queue_config.queue_name,
                "pipeline_type": self.pipeline.__class__.__name__ if self.pipeline else "none",
                "metadata": self.METADATA.to_dict(),
            }

            return self.report(full_report)

        except Exception as e:
            full_report = {
                "error_message": str(e),
                "metadata": self.METADATA.to_dict(),
            }
            return self.report(full_report)

    def run(self) -> ConsumerReport:
        """Start consuming messages."""
        return self.start_consuming()

    def stop(self) -> None:
        """Stop consuming messages."""
        self._running = False
        if self._consumer:
            self._consumer.close()
            self._consumer = None
