"""Security Pipeline for threat detection and response."""

from __future__ import annotations

from sentineliqsdk.analyzers.shodan import ShodanAnalyzer
from sentineliqsdk.messaging import Message
from sentineliqsdk.models import ModuleMetadata, WorkerInput
from sentineliqsdk.pipelines.orchestrator import PipelineOrchestrator


class SecurityPipeline(PipelineOrchestrator):
    """Specialized pipeline for security event processing."""

    METADATA = ModuleMetadata(
        name="Security Pipeline",
        description="Pipeline for security threat detection and automated response",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="security",
        doc_pattern="Security pipeline with threat detection and response",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/pipelines/security/",
        version_stage="TESTING",
    )

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self._setup_security_analyzers()
        self._setup_security_responders()
        self._setup_routing_rules()

    def _setup_security_analyzers(self) -> None:
        """Set up security-focused analyzers."""
        # Register analyzers for different data types
        self.register_analyzer("ip", ShodanAnalyzer)
        self.register_analyzer("domain", ShodanAnalyzer)
        # Add more analyzers as they become available
        # self.register_analyzer("hash", VirusTotalAnalyzer)
        # self.register_analyzer("url", VirusTotalAnalyzer)

    def _setup_security_responders(self) -> None:
        """Set up security-focused responders."""
        # Register responders for different actions
        # Note: BlockIPResponder would need to be implemented
        # self.register_responder("block", BlockIPResponder)
        # Add more responders as they become available
        # self.register_responder("alert", NotifyResponder)
        # self.register_responder("quarantine", QuarantineResponder)

    def _setup_routing_rules(self) -> None:
        """Set up routing rules for security events."""

        def security_routing_rule(message: Message) -> str:
            """Route based on data type and priority."""
            if message.metadata.priority == "critical":
                return "immediate_response"
            if message.data_type in ["ip", "domain"]:
                return "threat_intel"
            return "standard_analysis"

        self.add_routing_rule(security_routing_rule)

    def _determine_actions(self, analysis_report, message: Message):
        """Override to add security-specific action determination."""
        actions = super()._determine_actions(analysis_report, message)

        # Add security-specific logic
        if message.metadata.priority == "critical":
            # For critical events, always add immediate response
            actions.append(
                (
                    "escalate",
                    {
                        "target": message.data,
                        "reason": "critical_priority",
                        "confidence": "high",
                        "source": "security_pipeline",
                    },
                )
            )

        return actions
