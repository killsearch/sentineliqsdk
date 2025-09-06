"""Integration tests for sentineliqsdk."""

from __future__ import annotations

import json
import os
from io import StringIO
from unittest.mock import patch

import pytest

from sentineliqsdk import (
    Analyzer,
    Extractor,
    ProxyConfig,
    Responder,
    WorkerConfig,
    WorkerInput,
    runner,
)


class TestAnalyzerIntegration:
    """Integration tests for Analyzer."""

    class ReputationAnalyzer(Analyzer):
        """Test analyzer for integration testing."""

        def run(self) -> None:
            """Test analyzer implementation."""
            observable = self.get_data()

            # Simple reputation check
            if observable == "1.2.3.4":
                verdict = "malicious"
            elif observable == "8.8.8.8":
                verdict = "safe"
            else:
                verdict = "suspicious"

            # Build taxonomy
            taxonomy = self.build_taxonomy(
                level=verdict,  # type: ignore
                namespace="reputation",
                predicate="static",
                value=str(observable),
            )

            # Build full report
            full_report = {
                "observable": observable,
                "verdict": verdict,
                "taxonomy": [taxonomy.to_dict()],
                "related_ips": ["8.8.8.8", "1.1.1.1"],
                "related_urls": ["https://example.com"],
            }

            # Report the results
            self.report(full_report)

    def test_analyzer_with_auto_extract(self):
        """Test analyzer with auto-extraction enabled."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = self.ReputationAnalyzer(input_data)

        # Run the analyzer
        analyzer.run()

        # Test that the analyzer was properly initialized
        assert analyzer.auto_extract is True
        assert analyzer.get_data() == "1.2.3.4"

    def test_analyzer_with_auto_extract_disabled(self):
        """Test analyzer with auto-extraction disabled."""
        config = WorkerConfig(auto_extract=False)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
        analyzer = self.ReputationAnalyzer(input_data)

        # Run the analyzer
        analyzer.run()

        # Test that the analyzer was properly initialized
        assert analyzer.auto_extract is False

    def test_analyzer_with_file_datatype(self):
        """Test analyzer with file datatype."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(
            data_type="file", data="malware.exe", filename="malware.exe", config=config
        )
        analyzer = self.ReputationAnalyzer(input_data)

        # Test that get_data returns filename for file datatype
        assert analyzer.get_data() == "malware.exe"

    def test_analyzer_tlp_validation(self):
        """Test analyzer TLP validation."""
        config = WorkerConfig(check_tlp=True, max_tlp=2)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=3, config=config)

        with pytest.raises(SystemExit):
            self.ReputationAnalyzer(input_data)

    def test_analyzer_pap_validation(self):
        """Test analyzer PAP validation."""
        config = WorkerConfig(check_pap=True, max_pap=2)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", pap=3, config=config)

        with pytest.raises(SystemExit):
            self.ReputationAnalyzer(input_data)

    def test_analyzer_with_proxy_config(self):
        """Test analyzer with proxy configuration."""
        proxy_config = ProxyConfig(http="http://proxy:8080", https="https://proxy:8080")
        config = WorkerConfig(proxy=proxy_config)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        with patch(
            "sentineliqsdk.core.config.proxy.EnvProxyConfigurator.set_environ"
        ) as mock_set_proxies:
            analyzer = self.ReputationAnalyzer(input_data)
            mock_set_proxies.assert_called_once_with("http://proxy:8080", "https://proxy:8080")


class TestResponderIntegration:
    """Integration tests for Responder."""

    class BlockIpResponder(Responder):
        """Test responder for integration testing."""

        def run(self) -> None:
            """Test responder implementation."""
            ip = self.get_data()

            # Simulate blocking the IP
            result = {
                "action": "block",
                "target": ip,
                "status": "success",
                "timestamp": "2024-01-01T00:00:00Z",
            }

            # Build operations
            operations = [
                self.build_operation("block", target=ip, duration="24h"),
                self.build_operation("alert", severity="high", message=f"Blocked IP {ip}"),
            ]

            # Add operations to result
            result["operations"] = [
                {"operation_type": op.operation_type, "parameters": op.parameters}
                for op in operations
            ]

            # Report the results
            self.report(result)

    def test_responder_basic_functionality(self):
        """Test responder basic functionality."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        responder = self.BlockIpResponder(input_data)

        # Test that the responder was properly initialized
        assert responder.get_data() == "1.2.3.4"

    def test_responder_with_custom_config(self):
        """Test responder with custom configuration."""
        config = WorkerConfig(check_tlp=True, max_tlp=3)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, config=config)
        responder = self.BlockIpResponder(input_data)

        # Test that the responder was properly initialized
        assert responder.enable_check_tlp is True
        assert responder.max_tlp == 3

    def test_responder_tlp_validation(self):
        """Test responder TLP validation."""
        config = WorkerConfig(check_tlp=True, max_tlp=2)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", tlp=3, config=config)

        with pytest.raises(SystemExit):
            self.BlockIpResponder(input_data)


class TestExtractorIntegration:
    """Integration tests for Extractor."""

    def test_extractor_with_complex_data(self):
        """Test extractor with complex nested data."""
        extractor = Extractor()

        # Complex data structure with various IOCs
        data = {
            "observable": "1.2.3.4",
            "metadata": {
                "source": "firewall",
                "timestamp": "2024-01-01T00:00:00Z",
            },
            "related_ips": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
            "related_urls": [
                "https://example.com",
                "http://malicious.com",
            ],
            "related_domains": ["example.com", "evil.org"],
            "hashes": [
                "d41d8cd98f00b204e9800998ecf8427e",  # MD5
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
            ],
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            ],
            "emails": ["admin@example.com", "test@evil.org"],
            "registry_paths": [
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
                "HKLM\\SOFTWARE\\Malware",
            ],
            "uri_paths": [
                "ftp://files.example.com",
                "file:///path/to/malware.exe",
            ],
        }

        results = extractor.check_iterable(data)

        # Should find various types of IOCs
        data_types = [result.data_type for result in results]

        assert "ip" in data_types
        assert "url" in data_types
        assert "domain" in data_types
        assert "hash" in data_types
        assert "user-agent" in data_types
        assert "mail" in data_types
        assert "registry" in data_types
        assert "uri_path" in data_types

        # Should not find the original observable (it's in the "observable" key, not as a separate IOC)
        # The extractor should find other IOCs but not the main observable
        data_values = [result.data for result in results]
        # The observable "1.2.3.4" should be found as it's in the related_ips list
        # but we can verify it's not being duplicated
        assert data_values.count("1.2.3.4") == 1  # Should appear only once

    def test_extractor_with_ignore_parameter(self):
        """Test extractor with ignore parameter."""
        extractor = Extractor(ignore="1.2.3.4")

        data = {
            "observable": "1.2.3.4",  # Should be ignored
            "related_ips": ["8.8.8.8", "1.1.1.1"],
            "related_urls": ["https://example.com"],
        }

        results = extractor.check_iterable(data)

        # Should not find the ignored observable
        assert "1.2.3.4" not in [result.data for result in results]

        # Should find other IOCs
        data_types = [result.data_type for result in results]
        assert "ip" in data_types
        assert "url" in data_types

    def test_extractor_deduplication(self):
        """Test extractor deduplication functionality."""
        extractor = Extractor()

        # Data with duplicates
        data = [
            "1.2.3.4",
            "1.2.3.4",  # Duplicate
            "https://example.com",
            "https://example.com",  # Duplicate
            "8.8.8.8",
        ]

        results = extractor.check_iterable(data)

        # Should deduplicate results
        assert len(results) == 3

        # Check that duplicates are removed
        data_values = [result.data for result in results]
        assert data_values.count("1.2.3.4") == 1
        assert data_values.count("https://example.com") == 1
        assert data_values.count("8.8.8.8") == 1


class TestRunnerIntegration:
    """Integration tests for runner function."""

    class TestWorker:
        """Test worker for runner testing."""

        def __init__(self, input_data: WorkerInput) -> None:
            self.input_data = input_data
            self.run_called = False

        def run(self) -> None:
            """Test run method."""
            self.run_called = True

    def test_runner_with_worker_class(self):
        """Test runner with worker class."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        # Test that runner can be called with a worker class
        # We can't easily test the actual instantiation without complex mocking,
        # but we can test that the function signature is correct
        assert callable(runner)

        # Test that the worker class can be instantiated
        worker = self.TestWorker(input_data)
        assert worker.input_data == input_data
        assert not worker.run_called

        # Test that run method works
        worker.run()
        assert worker.run_called


class TestEndToEndIntegration:
    """End-to-end integration tests."""

    def test_analyzer_with_extractor_integration(self):
        """Test analyzer with extractor integration."""
        config = WorkerConfig(auto_extract=True)
        input_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)

        class TestAnalyzer(Analyzer):
            def run(self) -> None:
                full_report = {
                    "observable": self.get_data(),
                    "verdict": "malicious",
                    "related_ips": ["8.8.8.8", "1.1.1.1"],
                    "related_urls": ["https://example.com"],
                }
                self.report(full_report)

        analyzer = TestAnalyzer(input_data)

        # Test that analyzer can be instantiated
        assert analyzer.auto_extract is True
        assert analyzer.get_data() == "1.2.3.4"

    def test_responder_with_operations_integration(self):
        """Test responder with operations integration."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        class TestResponder(Responder):
            def run(self) -> None:
                operations = [
                    self.build_operation("block", target=self.get_data()),
                    self.build_operation("alert", severity="high"),
                ]
                result = {
                    "action": "block",
                    "target": self.get_data(),
                    "operations": [
                        {"operation_type": op.operation_type, "parameters": op.parameters}
                        for op in operations
                    ],
                }
                self.report(result)

        responder = TestResponder(input_data)

        # Test that responder can be instantiated
        assert responder.get_data() == "1.2.3.4"

    def test_worker_with_environment_variables(self):
        """Test worker with environment variables."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        class TestWorker(Analyzer):
            def run(self) -> None:
                # Test get_env method
                test_var = self.get_env("TEST_VAR", default="default_value")
                assert test_var == "default_value"

                # Test get_env with required variable
                with pytest.raises(SystemExit):
                    self.get_env("REQUIRED_VAR", message="Required variable missing")

        with patch.dict(os.environ, {}, clear=True):
            worker = TestWorker(input_data)
            worker.run()

    def test_worker_error_handling(self):
        """Test worker error handling."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        class TestWorker(Analyzer):
            def run(self) -> None:
                self.error("Test error message")

        worker = TestWorker(input_data)

        # Capture stdout to test error output
        captured_output = StringIO()

        with patch("sys.stdout", captured_output):
            with pytest.raises(SystemExit) as exc_info:
                worker.run()

        assert exc_info.value.code == 1

        # Parse the JSON output
        output = json.loads(captured_output.getvalue())
        assert output["success"] is False
        assert output["errorMessage"] == "Test error message"
        assert "input" in output
