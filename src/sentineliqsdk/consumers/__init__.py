"""Message consumers for SentinelIQ SDK."""

from __future__ import annotations

from sentineliqsdk.consumers.base import Consumer

__all__ = ["Consumer"]

# Optional consumer exports
from contextlib import suppress

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.consumers.kafka import KafkaConsumer  # noqa: F401

    __all__.append("KafkaConsumer")

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.consumers.pipeline_consumer import PipelineConsumer  # noqa: F401

    __all__.append("PipelineConsumer")
