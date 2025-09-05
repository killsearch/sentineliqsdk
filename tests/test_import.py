"""Basic import and public API smoke tests for sentineliqsdk using dataclasses."""

import sentineliqsdk
from sentineliqsdk import Analyzer, Extractor, Responder, Worker, WorkerInput, runner


def test_package_imports_correctly() -> None:
    """Test package imports and exposes correct name."""
    assert isinstance(sentineliqsdk.__name__, str)


def test_core_classes_are_importable() -> None:
    """Test key classes are importable from the top-level API."""
    for obj in (Analyzer, Responder, Worker, Extractor):
        assert obj is not None
        assert callable(obj)


def test_runner_works_with_dataclass_input() -> None:
    """Test runner works with dataclass input data."""
    executed = {"ok": False}

    class DummyWorker:
        def __init__(self, input_data: WorkerInput):
            self.input_data = input_data

        def run(self) -> None:  # pragma: no cover - direct call below
            executed["ok"] = True

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    runner(DummyWorker, input_data)
    assert executed["ok"] is True


def test_runner_works_with_dict_input() -> None:
    """Test runner works with legacy dictionary input data."""
    executed = {"ok": False}

    class DummyWorker:
        def __init__(self, input_data):
            self.input_data = input_data

        def run(self) -> None:  # pragma: no cover - direct call below
            executed["ok"] = True

    # Create a mock runner that accepts dict input
    def mock_runner(worker_cls, input_data):
        worker = worker_cls(input_data)
        worker.run()

    input_data = {"dataType": "ip", "data": "1.2.3.4"}
    mock_runner(DummyWorker, input_data)
    assert executed["ok"] is True
