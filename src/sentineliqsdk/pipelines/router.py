"""Message Router for directing messages to appropriate pipelines."""

from __future__ import annotations

from typing import Any

from sentineliqsdk.messaging import Message
from sentineliqsdk.models import ModuleMetadata, PipelineReport, WorkerInput
from sentineliqsdk.pipelines.base import Pipeline


class MessageRouter(Pipeline):
    """Routes messages to appropriate processing pipelines."""

    METADATA = ModuleMetadata(
        name="Message Router",
        description="Routes messages to appropriate processing pipelines",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="router",
        doc_pattern="Message routing with pipeline selection",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/pipelines/router/",
        version_stage="TESTING",
    )

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.routes: dict[str, str] = {}
        self.pipelines: dict[str, Pipeline] = {}

    def add_route(self, data_type: str, pipeline_name: str) -> None:
        """Add a route for a data type to a pipeline."""
        self.routes[data_type] = pipeline_name

    def register_pipeline(self, pipeline_name: str, pipeline: Pipeline) -> None:
        """Register a pipeline instance."""
        self.pipelines[pipeline_name] = pipeline

    def route_message(self, message: Message) -> str:
        """Route a message to the appropriate pipeline."""
        # Check explicit routes first
        pipeline_name = self.routes.get(message.data_type)

        if not pipeline_name:
            # Apply routing rules
            for rule in self.routing_rules:
                try:
                    pipeline_name = rule(message)  # type: ignore
                    if pipeline_name:
                        break
                except Exception:
                    continue

        # Default pipeline
        return pipeline_name or "default"

    def process_message(self, message: Message) -> dict[str, Any]:
        """Process a message through the appropriate pipeline."""
        try:
            pipeline_name = self.route_message(message)
            pipeline = self.pipelines.get(pipeline_name)

            if not pipeline:
                self._record_failure()
                return {
                    "error": f"No pipeline found for: {pipeline_name}",
                    "message_id": message.metadata.message_id,
                    "routed_to": pipeline_name,
                }

            # Process through the selected pipeline
            result = pipeline.process_message(message)

            # Add routing information
            result["routed_to"] = pipeline_name
            result["router_metadata"] = self.METADATA.to_dict()

            self._record_success()
            return result

        except Exception as e:
            self._record_failure()
            return {
                "error": str(e),
                "message_id": message.metadata.message_id,
                "metadata": self.METADATA.to_dict(),
            }

    def run(self) -> PipelineReport:
        """Run the router and return PipelineReport."""
        # For testing purposes, create a basic report
        full_report = {
            "router_status": "ready",
            "registered_routes": len(self.routing_rules),
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)
