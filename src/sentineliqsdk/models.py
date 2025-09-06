"""Data models for SentinelIQ SDK using dataclasses instead of JSON.

This module provides strongly-typed data structures to replace JSON dictionaries
throughout the SDK, improving type safety and developer experience.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from sentineliqsdk.constants import DEFAULT_PAP, DEFAULT_TLP, SENTINELIQ_LICENSE

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
    # Extended types supported by detectors
    "asn",
    "cve",
    "ip_port",
    "mac",
    "cidr",
]


@dataclass(frozen=True)
class ProxyConfig:
    """HTTP/HTTPS proxy configuration."""

    http: str | None = None
    https: str | None = None
    # Optional NO_PROXY support (comma-separated hosts/domains)
    no_proxy: str | None = None


@dataclass(frozen=True)
class WorkerConfig:
    """Configuration for workers including TLP/PAP validation and proxy settings."""

    check_tlp: bool = False
    max_tlp: int = DEFAULT_TLP
    check_pap: bool = False
    max_pap: int = DEFAULT_PAP
    auto_extract: bool = True
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    # Generic runtime parameters and secrets for programmatic configuration.
    # Use dotted paths (e.g., "shodan.api_key", "webhook.method") when convenient.
    params: Mapping[str, Any] = field(default_factory=dict)
    secrets: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:  # type: ignore[override]
        # Ensure mapping immutability for params and secrets
        if isinstance(self.params, dict):
            object.__setattr__(self, "params", MappingProxyType(dict(self.params)))
        if isinstance(self.secrets, dict):
            object.__setattr__(self, "secrets", MappingProxyType(dict(self.secrets)))


@dataclass(frozen=True)
class WorkerInput:
    """Input data structure for workers."""

    data_type: DataType
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "level": self.level,
            "namespace": self.namespace,
            "predicate": self.predicate,
            "value": self.value,
        }


@dataclass(frozen=True)
class Artifact:
    """Artifact extracted from analysis."""

    data_type: DataType
    data: str
    filename: str | None = None
    tlp: int | None = None
    pap: int | None = None
    # Additional fields can be added as needed
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:  # type: ignore[override]
        # Wrap mutable mappings in an immutable proxy to ensure deep immutability
        if isinstance(self.extra, dict):
            object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))


@dataclass(frozen=True)
class Operation:
    """Follow-up operation for workers."""

    operation_type: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:  # type: ignore[override]
        if isinstance(self.parameters, dict):
            object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


@dataclass(frozen=True)
class WorkerError:
    """Error response from workers."""

    success: bool = False
    error_message: str = ""
    input_data: WorkerInput | None = None


# Version stage for module metadata
ModuleVersionStage = Literal["DEVELOPER", "TESTING", "STABLE"]


@dataclass(frozen=True)
class ModuleMetadata:
    """Descriptive metadata for modules (analyzers/responders).

    Use this to declare authoring and documentation details that can be surfaced
    programmatically or included in reports for traceability.
    """

    name: str
    description: str
    author: tuple[str, ...] = ()
    license: str = SENTINELIQ_LICENSE
    pattern: str = ""
    doc_pattern: str = ""
    doc: str = ""
    version_stage: ModuleVersionStage = "DEVELOPER"

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary using required external key names."""
        return {
            "Name": self.name,
            "Description": self.description,
            "Author": list(self.author),
            "License": self.license,
            "pattern": self.pattern,
            "doc_pattern": self.doc_pattern,
            "doc": self.doc,
            "VERSION": self.version_stage,
        }


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

    data_type: DataType
    data: str


@dataclass(frozen=True)
class ExtractorResults:
    """Collection of IOC extraction results."""

    results: list[ExtractorResult] = field(default_factory=list)

    def add_result(self, data_type: DataType, data: str) -> None:
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
