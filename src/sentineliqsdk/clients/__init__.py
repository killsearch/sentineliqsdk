"""HTTP clients for external services (e.g., Shodan, Axur)."""

from __future__ import annotations

from contextlib import suppress

# Optional client exports. Keep package import resilient when optional
# integrations are not present in the environment or repo.
__all__: list[str] = ["AxurClient", "ShodanClient"]

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.clients.shodan import ShodanClient

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.clients.axur import AxurClient
