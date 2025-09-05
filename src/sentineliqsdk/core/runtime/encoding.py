"""Encoding helpers."""

from __future__ import annotations

import codecs
import sys


def ensure_utf8_streams() -> None:
    """Ensure stdout/stderr use UTF-8 writers when not already UTF-8.

    Any exception is ignored to preserve behavior in constrained runtimes.
    """
    try:
        if sys.stdout.encoding != "UTF-8":
            sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
        if sys.stderr.encoding != "UTF-8":
            sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")
    except Exception:
        pass  # nosec B110
