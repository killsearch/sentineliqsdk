"""Tests for sentineliqsdk.core.worker module."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from sentineliqsdk.core.worker import Worker
from sentineliqsdk.models import (
    Operation,
    ProxyConfig,
    WorkerConfig,
    WorkerInput,
)


class ConcreteWorker(Worker):
    """Concrete implementation of Worker for testing."""

    def run(self) -> None:
        """Test implementation of run method."""


class TestWorker:
    """Test Worker base class."""

    def test_init_with_minimal_input(self):
        """Test Worker initialization with minimal input."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.data_type == "ip"
        assert worker.tlp == 2
        assert worker.pap == 2
        assert worker.enable_check_tlp is False
        assert worker.max_tlp == 2
        assert worker.enable_check_pap is False
        assert worker.max_pap == 2
        assert worker.http_proxy is None
        assert worker.https_proxy is None

    def test_init_with_custom_config(self):
        """Test Worker initialization with custom configuration."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=3,
            check_pap=True,
            max_pap=3,
            auto_extract=False,
            proxy=ProxyConfig(http="http://proxy:8080", https="https://proxy:8080"),
        )
        input_data = WorkerInput(
            data_type="url", data="https://example.com", tlp=3, pap=3, config=config
        )
        worker = ConcreteWorker(input_data)

        assert worker.data_type == "url"
        assert worker.tlp == 3
        assert worker.pap == 3
        assert worker.enable_check_tlp is True
        assert worker.max_tlp == 3
        assert worker.enable_check_pap is True
        assert worker.max_pap == 3
        assert worker.http_proxy == "http://proxy:8080"
        assert worker.https_proxy == "https://proxy:8080"

    def test_init_with_custom_secret_phrases(self):
        """Test Worker initialization with custom secret phrases."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        custom_phrases = ("custom", "secret")
        worker = ConcreteWorker(input_data, secret_phrases=custom_phrases)

        assert worker.secret_phrases == custom_phrases

    def test_init_with_default_secret_phrases(self):
        """Test Worker initialization with default secret phrases."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.secret_phrases == ("key", "password", "secret", "token")

    def test_tlp_validation_fails(self):
        """Test that TLP validation fails when TLP exceeds max."""
        config = WorkerConfig(check_tlp=True, max_tlp=2)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=3, config=config)

        with pytest.raises(RuntimeError) as exc_info:
            ConcreteWorker(input_data)
        assert "TLP is higher than allowed." in str(exc_info.value)

    def test_pap_validation_fails(self):
        """Test that PAP validation fails when PAP exceeds max."""
        config = WorkerConfig(check_pap=True, max_pap=2)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", pap=3, config=config)

        with pytest.raises(RuntimeError) as exc_info:
            ConcreteWorker(input_data)
        assert "PAP is higher than allowed." in str(exc_info.value)

    def test_tlp_validation_passes(self):
        """Test that TLP validation passes when TLP is within limits."""
        config = WorkerConfig(check_tlp=True, max_tlp=3)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, config=config)

        # Should not raise any exception
        worker = ConcreteWorker(input_data)
        assert worker.tlp == 2

    def test_pap_validation_passes(self):
        """Test that PAP validation passes when PAP is within limits."""
        config = WorkerConfig(check_pap=True, max_pap=3)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", pap=2, config=config)

        # Should not raise any exception
        worker = ConcreteWorker(input_data)
        assert worker.pap == 2

    def test_get_data(self):
        """Test get_data method."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.get_data() == "1.2.3.4"

    def test_build_operation(self):
        """Test build_operation static method."""
        operation = Worker.build_operation("hunt", target="1.2.3.4", priority="high")

        assert isinstance(operation, Operation)
        assert operation.operation_type == "hunt"
        assert operation.parameters == {"target": "1.2.3.4", "priority": "high"}

    def test_operations_default(self):
        """Test default operations method returns empty list."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.operations({"test": "data"}) == []

    def test_get_env_existing(self):
        """Test get_env with existing environment variable."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = worker.get_env("TEST_VAR")
            assert result == "test_value"

    def test_get_env_missing_with_default(self):
        """Test get_env with missing environment variable and default value."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        with patch.dict(os.environ, {}, clear=True):
            result = worker.get_env("MISSING_VAR", default="default_value")
            assert result == "default_value"

    def test_get_env_missing_with_message(self):
        """Test get_env with missing environment variable and error message."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError) as exc_info:
                worker.get_env("MISSING_VAR", message="Required environment variable missing")
            assert "Required environment variable missing" in str(exc_info.value)

    def test_error_method(self):
        """Test error method outputs correct JSON and exits."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        with pytest.raises(RuntimeError) as exc_info:
            worker.error("Test error message")

        # Parse the JSON output from exception message
        output = json.loads(str(exc_info.value))
        assert output["success"] is False
        assert output["errorMessage"] == "Test error message"
        assert "input" in output

    def test_summary_default(self):
        """Test default summary method returns empty dict."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.summary({"test": "data"}) == {}

    def test_artifacts_default(self):
        """Test default artifacts method returns empty list."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        assert worker.artifacts({"test": "data"}) == []

    def test_report_default(self):
        """Test default report method returns the input."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        worker = ConcreteWorker(input_data)

        test_data = {"test": "data"}
        result = worker.report(test_data)
        assert result == test_data

    def test_run_abstract(self):
        """Test that run method is abstract."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        # Cannot instantiate Worker directly
        with pytest.raises(TypeError):
            Worker(input_data)

    def test_set_proxies_called_during_init(self):
        """Test that __set_proxies is called during initialization."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        with patch.object(ConcreteWorker, "_Worker__set_proxies") as mock_set_proxies:
            ConcreteWorker(input_data)
            mock_set_proxies.assert_called_once()

    def test_error_output_structure(self):
        """Test that error method produces correct output structure."""
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
            proxy=ProxyConfig(http="http://proxy:8080", https="https://proxy:8080"),
        )
        input_data = WorkerInput(
            data_type="file",
            data="malware.exe",
            filename="malware.exe",
            tlp=2,
            pap=2,
            config=config,
        )
        worker = ConcreteWorker(input_data)

        with pytest.raises(RuntimeError) as exc_info:
            worker.error("Test error")

        output = json.loads(str(exc_info.value))

        # Check the structure
        assert output["success"] is False
        assert output["errorMessage"] == "Test error"
        assert "input" in output

        input_data = output["input"]
        assert input_data["dataType"] == "file"
        assert input_data["data"] == "malware.exe"
        assert input_data["filename"] == "malware.exe"
        assert input_data["tlp"] == 2
        assert input_data["pap"] == 2

        config_data = input_data["config"]
        assert config_data["check_tlp"] is True
        assert config_data["max_tlp"] == 2
        assert config_data["check_pap"] is True
        assert config_data["max_pap"] == 2
        assert config_data["auto_extract"] is True
        assert config_data["proxy"]["http"] == "http://proxy:8080"
        assert config_data["proxy"]["https"] == "https://proxy:8080"
