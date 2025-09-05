"""Analyzer base class for SentinelIQ SDK (analyzers.base)."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from shutil import copyfileobj
from typing import Any, Literal

from sentineliqsdk.core import Worker
from sentineliqsdk.extractors import Extractor

TaxonomyLevel = Literal["info", "safe", "suspicious", "malicious"]


class Analyzer(Worker):
    """Base class for analyzers with auto-extraction and helpers."""

    def __init__(self, job_directory: str | None = None, secret_phrases=None) -> None:
        super().__init__(job_directory, secret_phrases)
        self.auto_extract: bool = self.get_param("config.auto_extract", True)

    def get_data(self) -> Any:
        """Return the observable value or filename for `file` datatypes."""
        if self.data_type == "file":
            return self.get_param("filename", None, "Missing filename.")
        return self.get_param("data", None, "Missing data field")

    def get_param(self, name: str, default: Any | None = None, message: str | None = None) -> Any:
        """Resolve dotted name; special-case `file`/`filename` for job-dir absolute path.

        - When `dataType == "file"` and running in job-directory mode, `get_param("file")`
          maps to the underlying `filename` value and, if the file exists under
          `<job_dir>/input/`, returns its absolute path. If not found, returns the raw value.
        - `get_param("filename")` behaves the same in this context.
        """
        # Determine the base key to fetch if the accessor is the logical "file" alias.
        base_key = "filename" if (name == "file") else name
        data = super().get_param(base_key, default, message)
        if (
            base_key in {"file", "filename"}
            and self.data_type == "file"
            and self.job_directory is not None
            and isinstance(data, str)
        ):
            path = f"{self.job_directory}/input/{data}"
            if os.path.isfile(path):
                return path
        return data

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

    def _copy_file_to_output(self, src_path: str) -> dict | None:
        """Copy a source file into `<job_dir>/output/` and return file metadata.

        When running in STDIN mode (`job_directory is None`), this returns None to
        avoid creating an `output/` directory in the current working directory.
        """
        if self.job_directory is None:
            return None
        if not os.path.isfile(src_path):
            return None
        output_dir = os.path.join(self.job_directory or "", "output")
        os.makedirs(output_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output_dir, delete=False) as dst:
            with open(src_path, "rb") as src:
                copyfileobj(src, dst)
            dstfname = dst.name
        os.chmod(dstfname, 0o444)
        return {"file": os.path.basename(dstfname), "filename": os.path.basename(src_path)}

    def build_artifact(self, data_type: str, data: Any, **kwargs: Any) -> dict | None:
        """Build an artifact dict; copy files to output for `file` type.

        In STDIN mode (`job_directory is None`), `file` artifacts are skipped
        and this returns None.
        """
        if data_type == "file":
            file_fields = self._copy_file_to_output(str(data))
            if file_fields is None:
                return None
            out = {"dataType": data_type, **file_fields, **kwargs}
            return out
        return {"dataType": data_type, "data": data, **kwargs}

    def report(self, full_report: dict, ensure_ascii: bool = False) -> None:
        """Wrap full report with SDK envelope and write JSON output."""
        summary: dict = {}
        with suppress(Exception):
            summary = self.summary(full_report)
        operation_list: list[dict] = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        super().report(
            {
                "success": True,
                "summary": summary,
                "artifacts": self.artifacts(full_report),
                "operations": operation_list,
                "full": full_report,
            },
            ensure_ascii,
        )

    def run(self) -> None:  # pragma: no cover - to be overridden
        """Override in subclasses."""
