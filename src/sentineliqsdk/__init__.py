"""Public package entry points for SentinelIQ SDK.

Exports the modern API and a convenience runner for workers.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from sentineliqsdk.analyzers import Analyzer
from sentineliqsdk.core import Worker
from sentineliqsdk.extractors import Extractor
from sentineliqsdk.models import (
    AnalyzerReport,
    Artifact,
    ExtractorResult,
    ExtractorResults,
    Operation,
    ProxyConfig,
    ResponderReport,
    TaxonomyEntry,
    TaxonomyLevel,
    WorkerConfig,
    WorkerError,
    WorkerInput,
)
from sentineliqsdk.responders import Responder

__all__ = [
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


class Runnable(Protocol):
    """Protocol for runnable workers exposing a ``run()`` method."""

    def run(self) -> None:  # pragma: no cover - typing-only contract
        ...


T = TypeVar("T", bound=Runnable)


def runner[T: Runnable](worker_cls: type[T], input_data: WorkerInput) -> None:
    """Instantiate and run a worker class with a ``run()`` method."""
    worker: Runnable = worker_cls(input_data)  # type: ignore[call-arg]
    worker.run()
