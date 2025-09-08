"""Tests for Security Pipeline."""

from __future__ import annotations

from unittest.mock import Mock, patch

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.messaging import Message, MessageMetadata
from sentineliqsdk.pipelines import SecurityPipeline


class TestSecurityPipeline:
    """Test cases for SecurityPipeline."""

    def setup_method(self):
        """Setup test fixtures."""
        self.input_data = WorkerInput(
            data_type="other",
            data="test_security_pipeline",
            config=WorkerConfig(
                params={
                    "auto_respond": True,
                    "response_threshold": "suspicious",
                },
                secrets={
                    "kafka.bootstrap_servers": "localhost:9092",
                    "kafka.security_protocol": "PLAINTEXT",
                    "shodan.api_key": "test_api_key",
                },
            ),
        )
        self.pipeline = SecurityPipeline(self.input_data)

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        assert self.pipeline is not None
        assert self.pipeline.auto_respond is True
        assert self.pipeline.response_threshold == "suspicious"
        assert "ip" in self.pipeline.analyzers
        assert "domain" in self.pipeline.analyzers

    def test_pipeline_metadata(self):
        """Test pipeline metadata."""
        assert self.pipeline.METADATA.name == "Security Pipeline"
        assert self.pipeline.METADATA.pattern == "security"
        assert self.pipeline.METADATA.version_stage == "TESTING"

    def test_process_message_success(self):
        """Test successful message processing."""
        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(
                message_id="test_msg_001", priority="normal", tags={"source": "test"}
            ),
            payload={"secrets": {"shodan.api_key": "test_api_key"}},
        )

        with patch.object(self.pipeline, "_execute_responders") as mock_responders:
            mock_responders.return_value = []

            # Mock the analyzer to avoid SystemExit
            mock_analyzer = Mock()
            mock_report = Mock()
            mock_report.full_report = {
                "observable": "192.168.1.100",
                "verdict": "safe",
                "taxonomy": [],
            }
            mock_analyzer.execute.return_value = mock_report

            # Replace the analyzer class in the pipeline's analyzers dict
            original_analyzer = self.pipeline.analyzers["ip"]
            self.pipeline.analyzers["ip"] = Mock(return_value=mock_analyzer)

            result = self.pipeline.process_message(message)

            # Restore original analyzer
            self.pipeline.analyzers["ip"] = original_analyzer

            assert result["pipeline_status"] == "completed"
            assert result["message_id"] == "test_msg_001"
            assert result["data_type"] == "ip"
            assert result["data"] == "192.168.1.100"
            assert "analysis" in result
            assert "actions" in result
            assert "responder_results" in result

    def test_process_message_no_analyzer(self):
        """Test message processing with unsupported data type."""
        message = Message(
            message_type="event",
            data_type="unsupported_type",
            data="test_data",
            metadata=MessageMetadata(message_id="test_msg_002"),
            payload={},
        )

        result = self.pipeline.process_message(message)

        assert result["pipeline_status"] == "failed"
        assert "No analyzer registered" in result["error"]
        assert result["message_id"] == "test_msg_002"

    def test_determine_actions_malicious(self):
        """Test action determination for malicious threats."""
        # Mock analysis report with malicious taxonomy
        mock_report = Mock()
        mock_report.full_report = {
            "taxonomy": [
                {
                    "level": "malicious",
                    "namespace": "shodan",
                    "predicate": "reputation",
                    "value": "192.168.1.100",
                }
            ]
        }

        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_003"),
            payload={},
        )

        actions = self.pipeline._determine_actions(mock_report, message)

        assert len(actions) == 1
        assert actions[0][0] == "block"
        assert actions[0][1]["target"] == "192.168.1.100"
        assert actions[0][1]["reason"] == "malicious"
        assert actions[0][1]["confidence"] == "high"

    def test_determine_actions_suspicious(self):
        """Test action determination for suspicious threats."""
        # Mock analysis report with suspicious taxonomy
        mock_report = Mock()
        mock_report.full_report = {
            "taxonomy": [
                {
                    "level": "suspicious",
                    "namespace": "shodan",
                    "predicate": "reputation",
                    "value": "192.168.1.100",
                }
            ]
        }

        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_004"),
            payload={},
        )

        actions = self.pipeline._determine_actions(mock_report, message)

        assert len(actions) == 1
        assert actions[0][0] == "alert"
        assert actions[0][1]["target"] == "192.168.1.100"
        assert actions[0][1]["reason"] == "suspicious"
        assert actions[0][1]["confidence"] == "medium"

    def test_determine_actions_critical_priority(self):
        """Test action determination for critical priority events."""
        # Mock analysis report with info taxonomy
        mock_report = Mock()
        mock_report.full_report = {
            "taxonomy": [
                {
                    "level": "info",
                    "namespace": "shodan",
                    "predicate": "reputation",
                    "value": "192.168.1.100",
                }
            ]
        }

        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_005", priority="critical"),
            payload={},
        )

        actions = self.pipeline._determine_actions(mock_report, message)

        # Should have escalate action for critical priority (info level doesn't trigger log action with suspicious threshold)
        assert len(actions) == 1
        assert actions[0][0] == "escalate"  # critical priority action
        assert actions[0][1]["reason"] == "critical_priority"

    def test_execute_responders_success(self):
        """Test successful responder execution."""
        actions = [
            ("block", {"target": "192.168.1.100", "reason": "malicious"}),
            ("alert", {"target": "192.168.1.100", "reason": "suspicious"}),
        ]

        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_006"),
            payload={"secrets": {"shodan.api_key": "test_api_key"}},
        )

        # Mock responder classes
        mock_responder = Mock()
        mock_report = Mock()
        mock_report.success = True
        mock_report.full_report = {"action": "block", "status": "success"}
        mock_responder.execute.return_value = mock_report

        with patch.dict(self.pipeline.responders, {"block": Mock(return_value=mock_responder)}):
            results = self.pipeline._execute_responders(actions, message)

            assert len(results) == 1  # Only block responder is registered
            assert results[0]["action"] == "block"
            assert results[0]["success"] is True

    def test_execute_responders_failure(self):
        """Test responder execution failure."""
        actions = [("block", {"target": "192.168.1.100", "reason": "malicious"})]

        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_007"),
            payload={"secrets": {"shodan.api_key": "test_api_key"}},
        )

        # Mock responder that raises exception
        mock_responder = Mock()
        mock_responder.execute.side_effect = Exception("Responder failed")

        with patch.dict(self.pipeline.responders, {"block": Mock(return_value=mock_responder)}):
            results = self.pipeline._execute_responders(actions, message)

            assert len(results) == 1
            assert results[0]["action"] == "block"
            assert results[0]["success"] is False
            assert "Responder failed" in results[0]["error"]

    def test_statistics_tracking(self):
        """Test pipeline statistics tracking."""
        # Initial stats
        summary = self.pipeline.summary({})
        assert summary["messages_processed"] == 0
        assert summary["messages_failed"] == 0
        assert summary["registered_analyzers"] == 2  # ip, domain
        assert summary["registered_responders"] == 0  # none registered by default

        # Process a message
        message = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_msg_008"),
            payload={"secrets": {"shodan.api_key": "test_api_key"}},
        )

        with patch.object(self.pipeline, "_execute_responders") as mock_responders:
            mock_responders.return_value = []

            # Mock the analyzer to avoid SystemExit
            mock_analyzer = Mock()
            mock_report = Mock()
            mock_report.full_report = {
                "observable": "192.168.1.100",
                "verdict": "safe",
                "taxonomy": [],
            }
            mock_analyzer.execute.return_value = mock_report

            # Replace the analyzer class in the pipeline's analyzers dict
            original_analyzer = self.pipeline.analyzers["ip"]
            self.pipeline.analyzers["ip"] = Mock(return_value=mock_analyzer)

            self.pipeline.process_message(message)

            # Restore original analyzer
            self.pipeline.analyzers["ip"] = original_analyzer

        # Check updated stats
        summary = self.pipeline.summary({})
        assert summary["messages_processed"] == 1
        assert summary["messages_failed"] == 0

    def test_routing_rules(self):
        """Test routing rules setup."""
        assert len(self.pipeline.routing_rules) == 1

        # Test routing rule function
        routing_rule = self.pipeline.routing_rules[0]

        # Test critical priority
        message_critical = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_critical", priority="critical"),
            payload={},
        )
        assert routing_rule(message_critical) == "immediate_response"

        # Test threat intel data type
        message_threat = Message(
            message_type="event",
            data_type="ip",
            data="192.168.1.100",
            metadata=MessageMetadata(message_id="test_threat", priority="normal"),
            payload={},
        )
        assert routing_rule(message_threat) == "threat_intel"

        # Test standard analysis
        message_standard = Message(
            message_type="event",
            data_type="other",
            data="test_data",
            metadata=MessageMetadata(message_id="test_standard", priority="normal"),
            payload={},
        )
        assert routing_rule(message_standard) == "standard_analysis"
