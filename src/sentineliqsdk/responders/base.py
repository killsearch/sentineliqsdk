"""Responder base class for SentinelIQ SDK (responders.base)."""

from __future__ import annotations

from contextlib import suppress

from sentineliqsdk.core import Worker
from sentineliqsdk.models import ResponderReport, WorkerInput


class Responder(Worker):
    """Base class for responders."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases=None,
    ):
        super().__init__(input_data, secret_phrases)

    def _build_envelope(self, full_report) -> ResponderReport:
        """Build the responder envelope with operations."""
        operation_list = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        return ResponderReport(success=True, full_report=full_report, operations=operation_list)

    def report(self, full_report) -> ResponderReport:
        """Return a ResponderReport.

        :param full_report: Responder results as dict.
        :return: The ResponderReport
        """
        return self._build_envelope(full_report)

    def run(self):
        """Overwritten by responders."""
