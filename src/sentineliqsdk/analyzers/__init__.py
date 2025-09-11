"""Analyzer abstractions for SentinelIQ SDK."""

from __future__ import annotations

from sentineliqsdk.analyzers.base import Analyzer
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer

__all__ = ["Analyzer", "DnsLookingglassAnalyzer"]
