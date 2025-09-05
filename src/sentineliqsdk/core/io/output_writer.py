"""Output writer implementations.

Encapsulates writing to STDOUT or a job directory path.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import suppress
from typing import Any


class JsonOutputWriter:
    """Write JSON output to STDOUT or `<job_dir>/output/output.json`."""

    def write(self, data: dict[str, Any], job_directory: str | None, *, ensure_ascii: bool) -> None:
        """Write JSON `data` to STDOUT or to the job directory output file.

        - When `job_directory` is `None`, writes to the current process' `sys.stdout`.
        - Otherwise, ensures `<job_dir>/output` exists and writes `output.json` there.
        """
        if job_directory is None:
            json.dump(data, sys.stdout, ensure_ascii=ensure_ascii)
            return

        with suppress(Exception):
            os.makedirs(f"{job_directory}/output")
        with open(f"{job_directory}/output/output.json", mode="w") as f_output:
            json.dump(data, f_output, ensure_ascii=ensure_ascii)
