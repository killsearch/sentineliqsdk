"""File-related behaviors for Analyzer: get_param('file') and file artifacts."""

from __future__ import annotations

import json
import os
import stat
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

        analyzer = Analyzer(job_directory=job_dir)
        resolved = analyzer.get_param("file")
        assert isinstance(resolved, str)
        assert resolved == src_path
        assert os.path.isfile(resolved)


def test_build_artifact_file_creates_output_and_copies() -> None:
    with tempfile.TemporaryDirectory() as job_dir:
        filename = "artifact.bin"
        payload = {"dataType": "file", "filename": filename}
        _write_job_input(job_dir, payload)
        # write source file
        src_path = os.path.join(job_dir, "input", filename)
        with open(src_path, "wb") as fh:
            fh.write(b"\x00\x01\x02")

        analyzer = Analyzer(job_directory=job_dir)
        artifact = analyzer.build_artifact("file", analyzer.get_param("file"))
        assert artifact is not None
        assert artifact["dataType"] == "file"
        # returned fields must include file (random name) and original filename
        assert artifact["filename"] == filename
        out_dir = os.path.join(job_dir, "output")
        assert os.path.isdir(out_dir)
        out_file = os.path.join(out_dir, artifact["file"])  # type: ignore[index]
        assert os.path.isfile(out_file)
        # ensure read-only bit at least for owner (platform dependent, so weak assert)
        mode = os.stat(out_file).st_mode
        assert not (mode & stat.S_IWUSR)
