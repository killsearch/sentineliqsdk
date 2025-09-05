"""File-related behaviors for Analyzer using dataclasses."""

from __future__ import annotations

import json
import os
import tempfile

from sentineliqsdk import Analyzer, WorkerInput


def _write_job_input(job_dir: str, payload: dict) -> None:
    """Write job input JSON file to the specified directory."""
    os.makedirs(os.path.join(job_dir, "input"), exist_ok=True)
    with open(os.path.join(job_dir, "input", "input.json"), "w") as fh:
        json.dump(payload, fh)


def test_analyzer_handles_file_input_with_dataclass() -> None:
    """Test analyzer handles file input using dataclass."""
    filename = "sample.txt"
    input_data = WorkerInput(data_type="file", data=filename, filename=filename)
    analyzer = Analyzer(input_data)

    # Test that get_data returns the filename for file type
    assert analyzer.get_data() == filename
    assert analyzer.data_type == "file"


def test_analyzer_file_parameter_resolution() -> None:
    """Test analyzer file parameter resolution in job directory mode."""
    with tempfile.TemporaryDirectory() as job_dir:
        # Prepare a fake file input using dataclass
        filename = "sample.txt"
        input_data = WorkerInput(data_type="file", data=filename, filename=filename)
        _write_job_input(job_dir, {"dataType": "file", "data": filename, "filename": filename})
        # Create the file under job_dir/input
        src_path = os.path.join(job_dir, "input", filename)
        with open(src_path, "w") as fh:
            fh.write("content")

        analyzer = Analyzer(input_data=input_data)
        # Test that get_data returns filename for file type
        resolved = analyzer.get_data()
        assert isinstance(resolved, str)
        assert resolved == filename


def test_analyzer_builds_file_artifact() -> None:
    """Test analyzer builds file artifacts using dataclass."""
    with tempfile.TemporaryDirectory() as job_dir:
        filename = "artifact.bin"
        input_data = WorkerInput(data_type="file", data=filename, filename=filename)
        _write_job_input(job_dir, {"dataType": "file", "data": filename, "filename": filename})
        # write source file
        src_path = os.path.join(job_dir, "input", filename)
        with open(src_path, "wb") as fh:
            fh.write(b"\x00\x01\x02")

        analyzer = Analyzer(input_data=input_data)
        artifact = analyzer.build_artifact("file", analyzer.get_data())
        assert artifact is not None
        assert artifact.data_type == "file"
        # In the new API, build_artifact for files just returns metadata without copying
        assert artifact.filename == filename
        # The new API doesn't copy files to output directory, just returns metadata
