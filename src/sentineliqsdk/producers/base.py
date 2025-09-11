"""Base Producer class for SentinelIQ SDK (producers.base)."""

from __future__ import annotations

import time
from abc import abstractmethod
from typing import Any

from sentineliqsdk.core import Worker
from sentineliqsdk.messaging import (
    Message,
    MessageConfig,
    MessageMetadata,
    MessageType,
    ProducerReport,
    QueueConfig,
)
from sentineliqsdk.models import DataType, WorkerInput


class Producer(Worker):
    """Base class for message producers with queue management and delivery confirmation."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.queue_config: QueueConfig | None = None
        self.message_config: MessageConfig | None = None

    def configure_queue(self, queue_config: QueueConfig) -> None:
        """Configure the message queue settings."""
        self.queue_config = queue_config

    def configure_messaging(self, message_config: MessageConfig) -> None:
        """Configure message processing settings."""
        self.message_config = message_config

    def get_data(self) -> Any:
        """Return the data to be published."""
        return self._input.data

    def build_message(
        self,
        message_type: MessageType,
        data_type: DataType,
        data: str,
        message_id: str | None = None,
        correlation_id: str | None = None,
        **metadata: Any,
    ) -> Message:
        """Build a message for publishing."""
        if message_id is None:
            message_id = f"msg_{int(time.time() * 1000)}"

        metadata_obj = MessageMetadata(
            message_id=message_id,
            correlation_id=correlation_id,
            **metadata,
        )

        return Message(
            message_type=message_type,
            data_type=data_type,
            data=data,
            metadata=metadata_obj,
        )

    def summary(self, raw: Any) -> dict:
        """Return producer-specific short summary."""
        return {}

    def operations(self, raw: Any) -> list:
        """Return list of operations to execute after publishing."""
        return []

    def _build_envelope(self, full_report: dict) -> ProducerReport:
        """Build the producer envelope with delivery confirmation."""
        return ProducerReport(
            success=True,
            message_id=full_report.get("message_id"),
            queue_name=self.queue_config.queue_name if self.queue_config else None,
            delivery_confirmed=full_report.get("delivery_confirmed", False),
            full_report=full_report,
        )

    def report(self, full_report: dict) -> ProducerReport:
        """Wrap full report with producer envelope and return ProducerReport."""
        return self._build_envelope(full_report)

    @abstractmethod
    def publish(self, message: Message) -> ProducerReport:
        """Publish a message to the configured queue.

        :param message: Message to publish
        :return: ProducerReport with delivery status
        """

    def run(self) -> ProducerReport:  # pragma: no cover - to be overridden
        """Override in subclasses to implement publishing logic."""
        raise NotImplementedError("Subclasses must implement run() method")
