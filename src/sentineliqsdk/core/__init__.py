"""Core building blocks for SentinelIQ SDK.

This subpackage contains the low-level primitives used by analyzers and responders,
such as the base ``Worker`` class.
"""

from __future__ import annotations

from sentineliqsdk.core.worker import Worker

__all__ = ["Worker"]
