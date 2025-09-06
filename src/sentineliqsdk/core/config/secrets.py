"""Secret sanitization utilities for error payloads."""

from __future__ import annotations

from typing import Any


def sanitize_config(config: dict[str, Any], secret_phrases: tuple[str, ...]) -> dict[str, Any]:
    """Return a deep copy of the config with sensitive keys replaced by 'REMOVED'.

    - Matches keys case-insensitively when a secret phrase appears as a substring
      in the key name (e.g., "apikey", "api_key", "password").
    - Walks nested dictionaries and lists to ensure deep sanitization.
    - Preserves non-dict values as-is.
    """

    def _sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return sanitize_config(value, secret_phrases)
        if isinstance(value, list):
            return [_sanitize(v) for v in value]
        return value

    result: dict[str, Any] = {}
    for key, value in config.items():
        if any(secret in key.lower() for secret in secret_phrases):
            result[key] = "REMOVED"
        else:
            result[key] = _sanitize(value)
    return result
