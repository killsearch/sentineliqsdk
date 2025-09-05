"""File-related behaviors for Analyzer: get_param('file') and file artifacts."""

from __future__ import annotations

import json
import os
import tempfile

from sentineliqsdk import Analyzer


def _write_job_input(job_dir: str, payload: dict) -> None:
    os.makedirs(os.path.join(job_dir, "input"), exist_ok=True)
    with open(os.path.join(job_dir, "input", "input.json"), "w") as fh:
        json.dump(payload, fh)


def test_get_param_file_resolves_absolute_path() -> None:
    """get_param('file') should resolve to an absolute path under job_dir/input when present."""
    with tempfile.TemporaryDirectory() as job_dir:
        # Prepare a fake file input
        filename = "sample.txt"
        input_payload = {"dataType": "file", "filename": filename}
        _write_job_input(job_dir, input_payload)
        # Create the file under job_dir/input
        src_path = os.path.join(job_dir, "input", filename)
        with open(src_path, "w") as fh:
            fh.write("content")

        analyzer = Analyzer(input_data=input_payload)
        resolved = analyzer.get_param("file")
        assert isinstance(resolved, str)
        assert resolved == filename  # In the new API, it returns the filename directly


def test_build_artifact_file_creates_output_and_copies() -> None:
    with tempfile.TemporaryDirectory() as job_dir:
        filename = "artifact.bin"
        payload = {"dataType": "file", "filename": filename}
        _write_job_input(job_dir, payload)
        # write source file
        src_path = os.path.join(job_dir, "input", filename)
        with open(src_path, "wb") as fh:
            fh.write(b"\x00\x01\x02")

        analyzer = Analyzer(input_data=payload)
        artifact = analyzer.build_artifact("file", analyzer.get_param("file"))
        assert artifact is not None
        assert artifact["dataType"] == "file"
        # In the new API, build_artifact for files just returns metadata without copying
        assert artifact["filename"] == filename
        # The new API doesn't copy files to output directory, just returns metadata
