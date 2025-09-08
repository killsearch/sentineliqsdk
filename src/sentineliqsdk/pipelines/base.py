"""Base Pipeline class for SentinelIQ SDK (pipelines.base)."""

from __future__ import annotations

import time
from abc import abstractmethod
from collections.abc import Callable
from typing import Any

from sentineliqsdk.core import Worker
from sentineliqsdk.messaging import Message
from sentineliqsdk.models import PipelineReport, WorkerInput


class Pipeline(Worker):
    """Base class for processing pipelines that orchestrate Analyzers and Responders."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.analyzers: dict[str, type] = {}
        self.responders: dict[str, type] = {}
        self.routing_rules: list[Callable] = []
        self._processing_stats = {
            "messages_processed": 0,
            "messages_failed": 0,
            "start_time": time.time(),
        }

    def register_analyzer(self, data_type: str, analyzer_class: type) -> None:
        """Register an analyzer for a specific data type."""
        self.analyzers[data_type] = analyzer_class

    def register_responder(self, action_type: str, responder_class: type) -> None:
        """Register a responder for a specific action type."""
        self.responders[action_type] = responder_class

    def add_routing_rule(self, rule: Callable) -> None:
        """Add a routing rule for message processing."""
        self.routing_rules.append(rule)

    def get_data(self) -> Any:
        """Return the data to be processed."""
        return self._input.data

    def summary(self, raw: Any) -> dict:
        """Return pipeline-specific short summary."""
        return {
            "messages_processed": self._processing_stats["messages_processed"],
            "messages_failed": self._processing_stats["messages_failed"],
            "processing_time": time.time() - self._processing_stats["start_time"],
            "registered_analyzers": len(self.analyzers),
            "registered_responders": len(self.responders),
        }

    def operations(self, raw: Any) -> list:
        """Return list of operations to execute after processing."""
        return []

    def _record_success(self) -> None:
        """Record successful message processing."""
        self._processing_stats["messages_processed"] += 1

    def _record_failure(self) -> None:
        """Record failed message processing."""
        self._processing_stats["messages_failed"] += 1

    def report(self, full_report: dict) -> PipelineReport:
        """Wrap full report with pipeline envelope and return PipelineReport."""
        summary = self.summary(full_report)
        operation_list = self.operations(full_report)

        return PipelineReport(
            success=True,
            messages_processed=summary.get("messages_processed", 0),
            messages_failed=summary.get("messages_failed", 0),
            processing_time=summary.get("processing_time", 0.0),
            registered_analyzers=summary.get("registered_analyzers", 0),
            registered_responders=summary.get("registered_responders", 0),
            full_report=full_report,
            operations=operation_list,
        )

    @abstractmethod
    def process_message(self, message: Message) -> dict[str, Any]:
        """Process a message through the pipeline.

        :param message: Message to process
        :return: Processing result dictionary
        """

    def run(self) -> PipelineReport:  # pragma: no cover - to be overridden
        """Override in subclasses to implement pipeline logic."""
        raise NotImplementedError("Subclasses must implement run() method")
