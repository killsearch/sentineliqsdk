"""Message producers for SentinelIQ SDK."""

from __future__ import annotations

from sentineliqsdk.producers.base import Producer

__all__ = ["Producer"]

# Optional producer exports
from contextlib import suppress

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.producers.kafka import KafkaProducer  # noqa: F401

    __all__.append("KafkaProducer")
