"""Responder base class for SentinelIQ SDK (responders.base)."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from sentineliqsdk.core import Worker


class Responder(Worker):
    """Base class for responders."""

    def __init__(
        self,
        input_data: dict[str, Any],
        secret_phrases=None,
    ):
        super().__init__(input_data, secret_phrases)

    def _build_envelope(self, full_report) -> dict[str, Any]:
        """Build the responder envelope with operations."""
        operation_list = []
        with suppress(Exception):
            operation_list = self.operations(full_report)
        return {"success": True, "full": full_report, "operations": operation_list}

    def report(self, full_report) -> dict[str, Any]:
        """Return a JSON dict in memory.

        :param full_report: Responder results as dict.
        :return: The output dict
        """
        return super().report(self._build_envelope(full_report))

    def run(self):
        """Overwritten by responders."""
