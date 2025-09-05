"""Responder base class for SentinelIQ SDK (responders.base)."""

from __future__ import annotations

from contextlib import suppress

from sentineliqsdk.core import Worker


class Responder(Worker):
    """Base class for responders."""

    def __init__(self, job_directory: str | None = None, secret_phrases=None):
        super().__init__(job_directory, secret_phrases)

    def get_data(self):
        """Return data from input dict.

        :return: Data (observable value) given through Cortex
        """
        return self.get_param("data", None, "Missing data field")

    def report(self, full_report, ensure_ascii: bool = False):
        """Return a JSON dict via stdout.

        :param full_report: Responsder results as dict.
        :param ensure_ascii: Force ascii output. Default: False
        """
        operation_list = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        super().report(
            {"success": True, "full": full_report, "operations": operation_list},
            ensure_ascii,
        )

    def run(self):
        """Overwritten by responders."""
