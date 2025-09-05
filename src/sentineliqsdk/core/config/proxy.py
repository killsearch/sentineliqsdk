"""Proxy configuration helpers."""

from __future__ import annotations

import os


class EnvProxyConfigurator:
    """Set `http_proxy`/`https_proxy` environment variables when provided."""

    def set_environ(self, http_proxy: str | None, https_proxy: str | None) -> None:
        """Apply proxies to process environment if provided."""
        if http_proxy is not None:
            os.environ["http_proxy"] = http_proxy
        if https_proxy is not None:
            os.environ["https_proxy"] = https_proxy
