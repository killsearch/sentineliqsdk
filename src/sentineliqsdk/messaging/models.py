"""Message models for Producer/Consumer infrastructure."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from sentineliqsdk.models import DataType

# Message types for different communication patterns
MessageType = Literal["event", "command", "query", "response", "notification"]
MessagePriority = Literal["low", "normal", "high", "critical"]
MessageStatus = Literal["pending", "processing", "completed", "failed", "retry"]


@dataclass(frozen=True)
class MessageMetadata:
    """Metadata for message tracking and routing."""

    message_id: str
    correlation_id: str | None = None
    reply_to: str | None = None
    timestamp: float | None = None
    ttl: float | None = None
    priority: MessagePriority = "normal"
    status: MessageStatus = "pending"
    retry_count: int = 0
    max_retries: int = 3
    # Additional metadata for routing and processing
    tags: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure immutability of tags."""
        if isinstance(self.tags, dict):
            object.__setattr__(self, "tags", MappingProxyType(dict(self.tags)))


@dataclass(frozen=True)
class Message:
    """Generic message structure for Producer/Consumer communication."""

    message_type: MessageType
    data_type: DataType
    data: str
    metadata: MessageMetadata
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure immutability of payload."""
        if isinstance(self.payload, dict):
            object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


@dataclass(frozen=True)
class QueueConfig:
    """Configuration for message queues."""

    queue_name: str
    exchange: str | None = None
    routing_key: str | None = None
    durable: bool = True
    auto_delete: bool = False
    exclusive: bool = False
    # Queue-specific settings
    max_length: int | None = None
    message_ttl: float | None = None
    dead_letter_exchange: str | None = None
    dead_letter_routing_key: str | None = None


@dataclass(frozen=True)
class MessageConfig:
    """Configuration for message processing."""

    # Delivery settings
    delivery_mode: Literal["transient", "persistent"] = "persistent"
    mandatory: bool = False
    immediate: bool = False

    # Processing settings
    auto_ack: bool = False
    prefetch_count: int = 1
    prefetch_size: int = 0

    # Retry settings
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    max_retry_delay: float = 300.0

    # Timeout settings
    consumer_timeout: float | None = None
    connection_timeout: float = 30.0

    # Security settings
    ssl_enabled: bool = False
    ssl_verify: bool = True
    ssl_cert_path: str | None = None
    ssl_key_path: str | None = None
    ssl_ca_path: str | None = None


@dataclass(frozen=True)
class ProducerReport:
    """Report from message producer."""

    success: bool = True
    message_id: str | None = None
    queue_name: str | None = None
    delivery_confirmed: bool = False
    error_message: str | None = None
    full_report: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConsumerReport:
    """Report from message consumer."""

    success: bool = True
    messages_processed: int = 0
    messages_failed: int = 0
    processing_time: float = 0.0
    error_message: str | None = None
    full_report: dict[str, Any] = field(default_factory=dict)
