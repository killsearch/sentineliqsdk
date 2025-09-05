"""Analyzer base class for SentinelIQ SDK (analyzers.base)."""

from __future__ import annotations

from contextlib import suppress
from typing import Any, Literal

from sentineliqsdk.core import Worker
from sentineliqsdk.extractors import Extractor

TaxonomyLevel = Literal["info", "safe", "suspicious", "malicious"]


class Analyzer(Worker):
    """Base class for analyzers with auto-extraction and helpers."""

    def __init__(
        self,
        input_data: dict[str, Any],
        secret_phrases=None,
    ) -> None:
        super().__init__(input_data, secret_phrases)
        self.auto_extract: bool = self.get_param("config.auto_extract", True)

    def get_data(self) -> Any:
        """Return the observable value or filename for `file` datatypes."""
        if self.data_type == "file":
            return self.get_param("filename", None, "Missing filename.")
        return self.get_param("data", None, "Missing data field")

    def get_param(self, name: str, default: Any | None = None, message: str | None = None) -> Any:
        """Resolve dotted name; special-case `file`/`filename` for file datatypes.

        - When `dataType == "file"`, `get_param("file")` maps to the underlying `filename` value.
        - `get_param("filename")` behaves the same in this context.
        """
        # Determine the base key to fetch if the accessor is the logical "file" alias.
        base_key = "filename" if (name == "file") else name
        return super().get_param(base_key, default, message)

    def build_taxonomy(
        self, level: TaxonomyLevel, namespace: str, predicate: str, value: str
    ) -> dict:
        """Create a normalized taxonomy entry for report metadata."""
        if level not in ("info", "safe", "suspicious", "malicious"):
            level = "info"
        return {
            "level": level,
            "namespace": namespace,
            "predicate": predicate,
            "value": value,
        }

    def summary(self, raw: Any) -> dict:
        """Return analyzer-specific short summary (optional)."""
        return {}

    def artifacts(self, raw: Any) -> list[dict]:
        """Auto-extract IOCs from the full report when enabled."""
        if self.auto_extract:
            extractor = Extractor(ignore=self.get_data())
            return extractor.check_iterable(raw)
        return []

    def build_artifact(self, data_type: str, data: Any, **kwargs: Any) -> dict:
        """Build an artifact dict.

        For file types, returns metadata without copying files.
        """
        if data_type == "file":
            return {"dataType": data_type, "filename": str(data), **kwargs}
        return {"dataType": data_type, "data": data, **kwargs}

    def _build_envelope(self, full_report: dict) -> dict[str, Any]:
        """Build the SDK envelope with summary, artifacts, and operations."""
        summary: dict = {}
        with suppress(Exception):
            summary = self.summary(full_report)
        operation_list: list[dict] = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        return {
            "success": True,
            "summary": summary,
            "artifacts": self.artifacts(full_report),
            "operations": operation_list,
            "full": full_report,
        }

    def report(self, full_report: dict) -> dict[str, Any]:
        """Wrap full report with SDK envelope and return JSON dict in memory."""
        return super().report(self._build_envelope(full_report))

    def run(self) -> None:  # pragma: no cover - to be overridden
        """Override in subclasses."""
