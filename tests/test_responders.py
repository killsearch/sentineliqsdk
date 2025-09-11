"""Tests for sentineliqsdk.responders module."""

from __future__ import annotations

from unittest.mock import MagicMock

from sentineliqsdk.models import (
    Operation,
    ProxyConfig,
    ResponderReport,
    WorkerConfig,
    WorkerInput,
)
from sentineliqsdk.responders import Responder


class ConcreteResponder(Responder):
    """Concrete implementation of Responder for testing."""

    def run(self) -> ResponderReport:
        """Test implementation of run method."""
        return self.report({"action": "noop", "target": self.get_data()})


class TestResponder:
    """Test Responder base class."""

    def test_init(self):
        """Test Responder initialization."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        assert responder.data_type == "ip"
        assert responder.tlp == 2
        assert responder.pap == 2

    def test_init_with_custom_config(self):
        """Test Responder initialization with custom configuration."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=3,
            check_pap=True,
            max_pap=3,
            proxy=ProxyConfig(http="http://proxy:8080"),
        )
        input_data = WorkerInput(
            data_type="url", data="https://example.com", tlp=3, pap=3, config=config
        )
        responder = ConcreteResponder(input_data)

        assert responder.data_type == "url"
        assert responder.tlp == 3
        assert responder.pap == 3
        assert responder.enable_check_tlp is True
        assert responder.max_tlp == 3
        assert responder.enable_check_pap is True
        assert responder.max_pap == 3
        assert responder.http_proxy == "http://proxy:8080"

    def test_get_data(self):
        """Test get_data method returns the data field."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        assert responder.get_data() == "1.2.3.4"

    def test_build_operation(self):
        """Test build_operation method inherited from Worker."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        operation = responder.build_operation("block", target="1.2.3.4", duration="24h")

        assert isinstance(operation, Operation)
        assert operation.operation_type == "block"
        assert operation.parameters == {"target": "1.2.3.4", "duration": "24h"}

    def test_operations_default(self):
        """Test default operations method returns empty list."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        assert responder.operations({"test": "data"}) == []

    def test_build_envelope_success(self):
        """Test _build_envelope method with successful operations."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Override operations method to return specific values
        responder.operations = lambda x: [MagicMock(operation_type="block", parameters={})]

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        envelope = responder._build_envelope(full_report)

        assert envelope.success is True
        assert envelope.full_report == full_report
        assert len(envelope.operations) == 1

    def test_build_envelope_with_exception(self):
        """Test _build_envelope method handles exceptions in operations."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Override operations method to raise exception
        responder.operations = lambda x: (_ for _ in ()).throw(Exception("Operations error"))

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        envelope = responder._build_envelope(full_report)

        # Should handle exception gracefully
        assert envelope.success is True
        assert envelope.full_report == full_report
        assert envelope.operations == []

    def test_report_returns_responder_report(self):
        """Test report method returns ResponderReport."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        result = responder.report(full_report)

        assert hasattr(result, "success")
        assert hasattr(result, "full_report")
        assert hasattr(result, "operations")

    def test_report_success_true(self):
        """Test that report always sets success to True."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        full_report = {"action": "failed", "error": "Something went wrong"}
        result = responder.report(full_report)

        assert result.success is True

    def test_run_abstract(self):
        """Test that run method is abstract and must be overridden."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Should not raise any exception since it's implemented in ConcreteResponder
        responder.run()

    def test_inherits_from_worker(self):
        """Test that Responder inherits from Worker."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Should have all Worker methods
        assert hasattr(responder, "get_data")
        assert hasattr(responder, "build_operation")
        assert hasattr(responder, "operations")
        assert hasattr(responder, "get_env")
        assert hasattr(responder, "error")
        assert hasattr(responder, "summary")
        assert hasattr(responder, "artifacts")
        assert hasattr(responder, "report")
        assert hasattr(responder, "run")

    def test_operations_called_with_full_report(self):
        """Test that operations method is called with the full report."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Mock the operations method
        mock_operations = MagicMock(return_value=[])
        responder.operations = mock_operations

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        responder._build_envelope(full_report)

        # Verify operations was called with the full report
        mock_operations.assert_called_once_with(full_report)

    def test_build_envelope_with_empty_operations(self):
        """Test _build_envelope method with empty operations list."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Override operations method to return empty list
        responder.operations = lambda x: []

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        envelope = responder._build_envelope(full_report)

        assert envelope.success is True
        assert envelope.full_report == full_report
        assert envelope.operations == []

    def test_build_envelope_with_multiple_operations(self):
        """Test _build_envelope method with multiple operations."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = ConcreteResponder(input_data)

        # Override operations method to return multiple operations
        operation1 = MagicMock(operation_type="block", parameters={})
        operation2 = MagicMock(operation_type="alert", parameters={})
        responder.operations = lambda x: [operation1, operation2]

        full_report = {"action": "blocked", "target": "1.2.3.4"}
        envelope = responder._build_envelope(full_report)

        assert envelope.success is True
        assert envelope.full_report == full_report
        assert len(envelope.operations) == 2
        assert envelope.operations == [operation1, operation2]
