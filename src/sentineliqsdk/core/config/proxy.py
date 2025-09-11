"""Proxy configuration helpers."""

from __future__ import annotations

import os


class EnvProxyConfigurator:
    """Set proxy environment variables, overriding prior values for provided keys.

    - Sets both lowercase and uppercase variants: http_proxy/HTTP_PROXY and https_proxy/HTTPS_PROXY.
    - Leaves unrelated environment variables untouched.
    - Ignores any value that is ``None``.
    """

    def _set(self, key_lower: str, key_upper: str, value: str | None) -> None:
        if value is None:
            return
        os.environ[key_lower] = value
        os.environ[key_upper] = value

    def set_environ(self, http_proxy: str | None, https_proxy: str | None) -> None:
        """Apply proxies to process environment if provided.

        Provided values override any existing environment variables for these keys.
        """
        self._set("http_proxy", "HTTP_PROXY", http_proxy)
        self._set("https_proxy", "HTTPS_PROXY", https_proxy)
