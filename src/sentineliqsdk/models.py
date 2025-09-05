"""Data models for SentinelIQ SDK using dataclasses instead of JSON.

This module provides strongly-typed data structures to replace JSON dictionaries
throughout the SDK, improving type safety and developer experience.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sentineliqsdk.constants import DEFAULT_PAP, DEFAULT_TLP

# Type aliases for better readability
TaxonomyLevel = Literal["info", "safe", "suspicious", "malicious"]
DataType = Literal[
    "ip",
    "url",
    "domain",
    "fqdn",
    "hash",
    "mail",
    "user-agent",
    "uri_path",
    "registry",
    "file",
    "other",
]


@dataclass(frozen=True)
class ProxyConfig:
    """HTTP/HTTPS proxy configuration."""

    http: str | None = None
    https: str | None = None


@dataclass(frozen=True)
class WorkerConfig:
    """Configuration for workers including TLP/PAP validation and proxy settings."""

    check_tlp: bool = False
    max_tlp: int = DEFAULT_TLP
    check_pap: bool = False
    max_pap: int = DEFAULT_PAP
    auto_extract: bool = True
    proxy: ProxyConfig = field(default_factory=ProxyConfig)


@dataclass(frozen=True)
class WorkerInput:
    """Input data structure for workers."""

    data_type: str
    data: str
    filename: str | None = None
    tlp: int = DEFAULT_TLP
    pap: int = DEFAULT_PAP
    config: WorkerConfig = field(default_factory=WorkerConfig)


@dataclass(frozen=True)
class TaxonomyEntry:
    """Taxonomy entry for analyzer reports."""

    level: TaxonomyLevel
    namespace: str
    predicate: str
    value: str


@dataclass(frozen=True)
class Artifact:
    """Artifact extracted from analysis."""

    data_type: str
    data: str
    filename: str | None = None
    tlp: int | None = None
    pap: int | None = None
    # Additional fields can be added as needed
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Operation:
    """Follow-up operation for workers."""

    operation_type: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkerError:
    """Error response from workers."""

    success: bool = False
    error_message: str = ""
    input_data: WorkerInput | None = None


@dataclass(frozen=True)
class AnalyzerReport:
    """Complete analyzer report with envelope."""

    success: bool = True
    summary: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    full_report: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResponderReport:
    """Complete responder report with envelope."""

    success: bool = True
    full_report: dict[str, Any] = field(default_factory=dict)
    operations: list[Operation] = field(default_factory=list)


@dataclass(frozen=True)
class ExtractorResult:
    """Result from IOC extraction."""

    data_type: str
    data: str


@dataclass(frozen=True)
class ExtractorResults:
    """Collection of IOC extraction results."""

    results: list[ExtractorResult] = field(default_factory=list)

    def add_result(self, data_type: str, data: str) -> None:
        """Add a new extraction result."""
        self.results.append(ExtractorResult(data_type=data_type, data=data))

    def deduplicate(self) -> ExtractorResults:
        """Remove duplicate results based on data_type and data."""
        seen = set()
        unique_results = []
        for result in self.results:
            key = (result.data_type, result.data)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        return ExtractorResults(results=unique_results)
