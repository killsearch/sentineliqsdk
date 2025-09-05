"""Analyzer base class for SentinelIQ SDK (analyzers.base)."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from sentineliqsdk.core import Worker
from sentineliqsdk.extractors import Extractor
from sentineliqsdk.models import AnalyzerReport, Artifact, TaxonomyEntry, TaxonomyLevel, WorkerInput


class Analyzer(Worker):
    """Base class for analyzers with auto-extraction and helpers."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.auto_extract: bool = self._input.config.auto_extract

    def get_data(self) -> Any:
        """Return the observable value or filename for `file` datatypes."""
        if self.data_type == "file":
            if self._input.filename is None:
                self.error("Missing filename for file datatype.")
            return self._input.filename
        return self._input.data

    def build_taxonomy(
        self, level: TaxonomyLevel, namespace: str, predicate: str, value: str
    ) -> TaxonomyEntry:
        """Create a normalized taxonomy entry for report metadata."""
        if level not in ("info", "safe", "suspicious", "malicious"):
            level = "info"
        return TaxonomyEntry(
            level=level,
            namespace=namespace,
            predicate=predicate,
            value=value,
        )

    def summary(self, raw: Any) -> dict:
        """Return analyzer-specific short summary (optional)."""
        return {}

    def artifacts(self, raw: Any) -> list[Artifact]:
        """Auto-extract IOCs from the full report when enabled."""
        if self.auto_extract:
            extractor = Extractor(ignore=self.get_data())
            results = extractor.check_iterable(raw)
            return [Artifact(data_type=r.data_type, data=r.data) for r in results]
        return []

    def build_artifact(self, data_type: str, data: Any, **kwargs: Any) -> Artifact:
        """Build an artifact dataclass.

        For file types, returns metadata without copying files.
        """
        if data_type == "file":
            return Artifact(data_type=data_type, data=str(data), filename=str(data), extra=kwargs)
        return Artifact(data_type=data_type, data=str(data), extra=kwargs)

    def _build_envelope(self, full_report: dict) -> AnalyzerReport:
        """Build the SDK envelope with summary, artifacts, and operations."""
        summary: dict = {}
        with suppress(Exception):
            summary = self.summary(full_report)
        operation_list: list = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        return AnalyzerReport(
            success=True,
            summary=summary,
            artifacts=self.artifacts(full_report),
            operations=operation_list,
            full_report=full_report,
        )

    def report(self, full_report: dict) -> AnalyzerReport:
        """Wrap full report with SDK envelope and return AnalyzerReport."""
        return self._build_envelope(full_report)

    def run(self) -> None:  # pragma: no cover - to be overridden
        """Override in subclasses."""
