"""Basic import and public API smoke tests for sentineliqsdk."""

import sentineliqsdk
from sentineliqsdk import Analyzer, Extractor, Responder, Worker, runner


def test_package_imports() -> None:
    """Package imports and exposes a name."""
    assert isinstance(sentineliqsdk.__name__, str)


def test_public_api_importable() -> None:
    """Key classes are importable from the top-level API."""
    for obj in (Analyzer, Responder, Worker, Extractor):
        assert obj is not None
        assert callable(obj)


def test_runner_invokes_run() -> None:
    """`runner` should instantiate the class and call `run()` with no args."""
    executed = {"ok": False}

    class Dummy:
        def run(self) -> None:  # pragma: no cover - direct call below
            executed["ok"] = True

    runner(Dummy)
    assert executed["ok"] is True
