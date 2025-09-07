"""HTTP clients for external services (e.g., Shodan, Axur)."""

from __future__ import annotations

from contextlib import suppress

# Optional client exports. Keep package import resilient when optional
# integrations are not present in the environment or repo.
__all__: list[str] = ["AxurClient", "Cluster25Client", "ShodanClient"]

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.clients.shodan import ShodanClient

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.clients.axur import AxurClient

with suppress(Exception):  # pragma: no cover - import guard
    from sentineliqsdk.clients.cluster25 import Cluster25Client
