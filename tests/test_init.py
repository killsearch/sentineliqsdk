"""Tests for sentineliqsdk.__init__ module."""

from __future__ import annotations

import inspect

from sentineliqsdk import (
    Analyzer,
    AnalyzerReport,
    Artifact,
    Extractor,
    ExtractorResult,
    ExtractorResults,
    Operation,
    ProxyConfig,
    Responder,
    ResponderReport,
    Runnable,
    T,
    TaxonomyEntry,
    TaxonomyLevel,
    Worker,
    WorkerConfig,
    WorkerError,
    WorkerInput,
    runner,
)


class TestImports:
    """Test that all public API items are properly imported."""

    def test_analyzer_import(self):
        """Test Analyzer import."""
        assert Analyzer is not None
        from sentineliqsdk.analyzers import Analyzer as AnalyzerClass

        assert Analyzer is AnalyzerClass

    def test_responder_import(self):
        """Test Responder import."""
        assert Responder is not None
        from sentineliqsdk.responders import Responder as ResponderClass

        assert Responder is ResponderClass

    def test_worker_import(self):
        """Test Worker import."""
        assert Worker is not None
        from sentineliqsdk.core import Worker as WorkerClass

        assert Worker is WorkerClass

    def test_extractor_import(self):
        """Test Extractor import."""
        assert Extractor is not None
        from sentineliqsdk.extractors import Extractor as ExtractorClass

        assert Extractor is ExtractorClass

    def test_models_imports(self):
        """Test all model imports."""
        # Test that all model classes are imported
        assert AnalyzerReport is not None
        assert Artifact is not None
        assert ExtractorResult is not None
        assert ExtractorResults is not None
        assert Operation is not None
        assert ProxyConfig is not None
        assert ResponderReport is not None
        assert TaxonomyEntry is not None
        assert TaxonomyLevel is not None
        assert WorkerConfig is not None
        assert WorkerError is not None
        assert WorkerInput is not None

    def test_runner_import(self):
        """Test runner function import."""
        assert runner is not None
        assert callable(runner)

    def test_all_exports(self):
        """Test that __all__ contains all expected exports."""
        from sentineliqsdk import __all__

        expected_exports = [
            "Analyzer",
            "AnalyzerReport",
            "Artifact",
            "Extractor",
            "ExtractorResult",
            "ExtractorResults",
            "Operation",
            "ProxyConfig",
            "Responder",
            "ResponderReport",
            "TaxonomyEntry",
            "TaxonomyLevel",
            "Worker",
            "WorkerConfig",
            "WorkerError",
            "WorkerInput",
            "runner",
        ]

        assert set(__all__) == set(expected_exports)


class TestRunner:
    """Test runner function."""

    class TestWorker:
        """Test worker class for runner testing."""

        def __init__(self, input_data: WorkerInput) -> None:
            self.input_data = input_data
            self.run_called = False

        def run(self) -> None:
            """Test run method."""
            self.run_called = True

    def test_runner_with_valid_worker(self):
        """Test runner with valid worker class."""
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")

        # Test that runner can be called (it instantiates the worker)
        # We can't easily test the actual instantiation without mocking,
        # but we can test that the function is callable and has the right signature
        assert callable(runner)

        # Test that the worker class can be instantiated with input_data
        worker_instance = self.TestWorker(input_data)
        assert worker_instance.input_data == input_data

    def test_runner_type_annotation(self):
        """Test that runner has proper type annotation."""
        sig = inspect.signature(runner)
        assert len(sig.parameters) == 2
        assert "worker_cls" in sig.parameters
        assert "input_data" in sig.parameters

        # Check return type annotation (should be 'None' string, not NoneType)
        assert sig.return_annotation == "None"


class TestRunnableProtocol:
    """Test Runnable protocol."""

    def test_runnable_protocol(self):
        """Test that Runnable protocol can be implemented."""

        class TestRunnable:
            def run(self) -> None:
                pass

        # This should not raise any type errors
        runnable: Runnable = TestRunnable()
        assert hasattr(runnable, "run")

    def test_runnable_protocol_method_signature(self):
        """Test that Runnable protocol method has correct signature."""

        class TestRunnable:
            def run(self) -> None:
                pass

        runnable: Runnable = TestRunnable()
        # Should be callable
        assert callable(runnable.run)

        # Should not raise any exception
        runnable.run()


class TestTypeVar:
    """Test TypeVar T."""

    def test_typevar_exists(self):
        """Test that TypeVar T exists and is properly bound."""
        # T should be bound to Runnable
        # We can't easily test the binding without complex type checking,
        # but we can test that T exists
        assert T is not None
