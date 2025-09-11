"""Pipeline Orchestrator for coordinating Analyzers and Responders."""

from __future__ import annotations

import time
from typing import Any

from sentineliqsdk.messaging import Message
from sentineliqsdk.models import (
    AnalyzerReport,
    ModuleMetadata,
    PipelineReport,
    WorkerConfig,
    WorkerInput,
)
from sentineliqsdk.pipelines.base import Pipeline


class PipelineOrchestrator(Pipeline):
    """Orchestrates the flow between Analyzers and Responders."""

    METADATA = ModuleMetadata(
        name="Pipeline Orchestrator",
        description="Orchestrates processing flow between Analyzers and Responders",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="pipeline",
        doc_pattern="Pipeline orchestration with analyzer and responder coordination",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/pipelines/orchestrator/",
        version_stage="TESTING",
    )

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.auto_respond: bool = self.get_config("auto_respond", True)
        self.response_threshold: str = self.get_config("response_threshold", "suspicious")

    def process_message(self, message: Message) -> dict[str, Any]:
        """Process a message through the pipeline."""
        try:
            # 1. Route to appropriate analyzer
            analyzer_class = self.analyzers.get(message.data_type)
            if not analyzer_class:
                self._record_failure()
                return {
                    "error": f"No analyzer registered for data_type: {message.data_type}",
                    "message_id": message.metadata.message_id,
                    "pipeline_status": "failed",
                    "metadata": self.METADATA.to_dict(),
                }

            # 2. Analyze the data
            analyzer_input = WorkerInput(
                data_type=message.data_type,
                data=message.data,
                config=WorkerConfig(
                    secrets=message.payload.get("secrets", {}),
                    params=message.payload.get("params", {}),
                ),
            )
            analyzer = analyzer_class(analyzer_input)
            analysis_report = analyzer.execute()

            # 3. Determine response actions
            actions = self._determine_actions(analysis_report, message)

            # 4. Execute responders if enabled
            responder_results = []
            if self.auto_respond and actions:
                responder_results = self._execute_responders(actions, message)

            # 5. Record success
            self._record_success()

            return {
                "message_id": message.metadata.message_id,
                "data_type": message.data_type,
                "data": message.data,
                "analysis": analysis_report.full_report,
                "actions": actions,
                "responder_results": responder_results,
                "pipeline_status": "completed",
                "processing_time": time.time(),
                "metadata": self.METADATA.to_dict(),
            }

        except Exception as e:
            self._record_failure()
            return {
                "message_id": message.metadata.message_id,
                "error_message": str(e),
                "pipeline_status": "failed",
                "metadata": self.METADATA.to_dict(),
            }

    def _determine_actions(
        self, analysis_report: AnalyzerReport, message: Message
    ) -> list[tuple[str, dict]]:
        """Determine what actions to take based on analysis results."""
        actions = []

        # Check taxonomy for threat indicators
        for taxonomy in analysis_report.full_report.get("taxonomy", []):
            level = taxonomy.get("level", "info")

            if level == "malicious":
                actions.append(
                    (
                        "block",
                        {
                            "target": message.data,
                            "reason": "malicious",
                            "confidence": "high",
                            "source": taxonomy.get("namespace", "unknown"),
                        },
                    )
                )
            elif level == "suspicious" and self.response_threshold in ["suspicious", "info"]:
                actions.append(
                    (
                        "alert",
                        {
                            "target": message.data,
                            "reason": "suspicious",
                            "confidence": "medium",
                            "source": taxonomy.get("namespace", "unknown"),
                        },
                    )
                )
            elif level == "info" and self.response_threshold == "info":
                actions.append(
                    (
                        "log",
                        {
                            "target": message.data,
                            "reason": "info",
                            "confidence": "low",
                            "source": taxonomy.get("namespace", "unknown"),
                        },
                    )
                )

        return actions

    def _execute_responders(self, actions: list[tuple[str, dict]], message: Message) -> list[dict]:
        """Execute responders for the determined actions."""
        results = []

        for action_type, action_data in actions:
            responder_class = self.responders.get(action_type)
            if responder_class:
                try:
                    responder_input = WorkerInput(
                        data_type=message.data_type,
                        data=message.data,
                        config=WorkerConfig(
                            secrets=message.payload.get("secrets", {}),
                            params=action_data,
                        ),
                    )
                    responder = responder_class(responder_input)
                    responder_report = responder.execute()

                    results.append(
                        {
                            "action": action_type,
                            "success": responder_report.success,
                            "report": responder_report.full_report,
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "action": action_type,
                            "success": False,
                            "error": str(e),
                        }
                    )

        return results

    def run(self) -> PipelineReport:
        """Run the orchestrator and return PipelineReport."""
        # For testing purposes, create a basic report
        full_report = {
            "orchestrator_status": "ready",
            "registered_analyzers": len(self.analyzers),
            "registered_responders": len(self.responders),
            "metadata": self.METADATA.to_dict(),
        }
        return self.report(full_report)
