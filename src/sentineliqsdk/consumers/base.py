"""Base Consumer class for SentinelIQ SDK (consumers.base)."""

from __future__ import annotations

import time
from abc import abstractmethod
from typing import Any

from sentineliqsdk.core import Worker
from sentineliqsdk.messaging import ConsumerReport, Message, MessageConfig, QueueConfig
from sentineliqsdk.models import WorkerInput


class Consumer(Worker):
    """Base class for message consumers with queue management and message processing."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.queue_config: QueueConfig | None = None
        self.message_config: MessageConfig | None = None
        self._processing_stats = {
            "messages_processed": 0,
            "messages_failed": 0,
            "start_time": time.time(),
        }

    def configure_queue(self, queue_config: QueueConfig) -> None:
        """Configure the message queue settings."""
        self.queue_config = queue_config

    def configure_messaging(self, message_config: MessageConfig) -> None:
        """Configure message processing settings."""
        self.message_config = message_config

    def get_data(self) -> Any:
        """Return the data from the consumed message."""
        return self._input.data

    def summary(self, raw: Any) -> dict:
        """Return consumer-specific short summary."""
        return {
            "messages_processed": self._processing_stats["messages_processed"],
            "messages_failed": self._processing_stats["messages_failed"],
            "processing_time": time.time() - self._processing_stats["start_time"],
        }

    def operations(self, raw: Any) -> list:
        """Return list of operations to execute after processing."""
        return []

    def _build_envelope(self, full_report: dict) -> ConsumerReport:
        """Build the consumer envelope with processing statistics."""
        return ConsumerReport(
            success=True,
            messages_processed=int(self._processing_stats["messages_processed"]),
            messages_failed=int(self._processing_stats["messages_failed"]),
            processing_time=time.time() - self._processing_stats["start_time"],
            full_report=full_report,
        )

    def report(self, full_report: dict) -> ConsumerReport:
        """Wrap full report with consumer envelope and return ConsumerReport."""
        return self._build_envelope(full_report)

    def _record_success(self) -> None:
        """Record successful message processing."""
        self._processing_stats["messages_processed"] += 1

    def _record_failure(self) -> None:
        """Record failed message processing."""
        self._processing_stats["messages_failed"] += 1

    @abstractmethod
    def consume(self, message: Message) -> ConsumerReport:
        """Process a consumed message.

        :param message: Message to process
        :return: ConsumerReport with processing status
        """

    @abstractmethod
    def start_consuming(self) -> ConsumerReport:
        """Start consuming messages from the configured queue.

        :return: ConsumerReport with consumption statistics
        """

    def run(self) -> ConsumerReport:  # pragma: no cover - to be overridden
        """Override in subclasses to implement consumption logic."""
        raise NotImplementedError("Subclasses must implement run() method")
