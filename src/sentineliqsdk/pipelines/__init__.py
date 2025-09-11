"""Pipeline infrastructure for SentinelIQ SDK."""

from __future__ import annotations

from sentineliqsdk.pipelines.base import Pipeline
from sentineliqsdk.pipelines.orchestrator import PipelineOrchestrator
from sentineliqsdk.pipelines.router import MessageRouter

__all__ = [
    "MessageRouter",
    "Pipeline",
    "PipelineOrchestrator",
]

# Optional pipeline exports
from contextlib import suppress

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.pipelines.security import SecurityPipeline  # noqa: F401

    __all__.append("SecurityPipeline")
