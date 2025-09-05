"""Contracts and protocols used across the SDK core.

These help organize responsibilities following SOLID, enabling composition and testing.
"""

from __future__ import annotations

from typing import Any, Protocol


class OutputWriter(Protocol):
    """Contract for writing worker outputs to some destination."""

    def write(self, data: dict[str, Any], job_directory: str | None, *, ensure_ascii: bool) -> None:
        """Persist `data` to STDOUT or a job directory depending on context."""
        ...


class ProxyConfigurator(Protocol):
    """Contract to configure HTTP(S) proxy environment for a worker."""

    def set_environ(self, http_proxy: str | None, https_proxy: str | None) -> None:
        """Set `http_proxy` and `https_proxy` to OS environment as needed."""
        ...


class SecretSanitizer(Protocol):
    """Contract to sanitize configuration entries in error payloads."""

    def sanitize(self, config: dict[str, Any], secret_phrases: tuple[str, ...]) -> dict[str, Any]:
        """Return a sanitized copy of `config` replacing sensitive values."""
        ...
