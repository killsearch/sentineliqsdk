"""HTTP clients for external services (e.g., Shodan, Axur)."""

from __future__ import annotations

# Optional client exports. Keep package import resilient when optional
# integrations are not present in the environment or repo.
__all__: list[str] = []
try:  # pragma: no cover - import guard
    from sentineliqsdk.clients.shodan import ShodanClient

    __all__.append("ShodanClient")
except Exception:  # pragma: no cover - import guard
    pass

try:  # pragma: no cover - import guard
    from sentineliqsdk.clients.axur import AxurClient

    __all__.append("AxurClient")
except Exception:  # pragma: no cover - import guard
    pass
