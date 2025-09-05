"""Public package entry points for SentinelIQ SDK.

Exports the modern API and a convenience runner for workers.
"""

from __future__ import annotations

from typing import Any, Protocol, TypeVar

from sentineliqsdk.analyzers import Analyzer
from sentineliqsdk.core import Worker
from sentineliqsdk.extractors import Extractor
from sentineliqsdk.responders import Responder

__all__ = ["Analyzer", "Extractor", "Responder", "Worker", "runner"]


class Runnable(Protocol):
    """Protocol for runnable workers exposing a ``run()`` method."""

    def run(self) -> None:  # pragma: no cover - typing-only contract
        ...


T = TypeVar("T", bound=Runnable)


def runner(worker_cls: type[T], input_data: dict[str, Any]) -> None:
    """Instantiate and run a worker class with a ``run()`` method."""
    worker: Runnable = worker_cls(input_data)  # type: ignore[call-arg]
    worker.run()
