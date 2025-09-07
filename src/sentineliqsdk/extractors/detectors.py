"""Detectors for IOC classification.

Each detector encapsulates a single responsibility: deciding whether a given
string matches a specific data type (e.g., ip, url, domain). This separation
allows easier extensibility and testing while keeping the Extractor class
focused on orchestration.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Protocol
from urllib.parse import urlparse

from sentineliqsdk.constants import DOMAIN_PARTS, HASH_LENGTHS, MIN_FQDN_LABELS, USER_AGENT_PREFIXES

# Port number constants
MAX_PORT_NUMBER = 65535


class DetectionContext(Protocol):
    """Context contract implemented by the orchestrator (Extractor).

    Provides normalization helpers and policy flags to detectors without
    coupling them to the full Extractor implementation.
    """

    # Policies and feature flags
    support_mailto: bool

    # Helpers
    def label_allowed(self, label: str) -> bool:  # pragma: no cover - protocol
        """Return True if a DNS label is allowed for the current policy."""
        ...

    def normalize_domain(self, domain: str) -> str:  # pragma: no cover - protocol
        """Normalize a domain string (e.g., via IDNA) according to settings."""
        ...

    def normalize_url(self, url: str) -> str:  # pragma: no cover - protocol
        """Normalize a URL string (e.g., lowercase host, drop default ports)."""
        ...


class Detector(Protocol):
    """Detector protocol that classifies a string into a data type."""

    name: str

    def matches(self, value: str) -> bool:  # pragma: no cover - protocol
        """Return True if ``value`` matches the detector's type."""
        ...


@dataclass
class IpDetector:
    """Detect IPv4/IPv6 addresses using ``ipaddress`` from the stdlib."""

    name: str = "ip"

    def matches(self, value: str) -> bool:
        """Check whether ``value`` is a valid IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


@dataclass
class UrlDetector:
    """Detect HTTP/HTTPS URLs by scheme and netloc presence."""

    ctx: DetectionContext
    name: str = "url"

    def matches(self, value: str) -> bool:
        """Return True for valid ``http(s)://`` URLs with a netloc."""
        if not value.lower().startswith(("http://", "https://")):
            return False
        parsed = urlparse(value)
        return bool(parsed.scheme.lower() in {"http", "https"} and parsed.netloc)


@dataclass
class DomainDetector:
    """Detect simple ``domain.tld`` values (exactly two labels)."""

    ctx: DetectionContext
    name: str = "domain"

    def matches(self, value: str) -> bool:
        """Return True for domains with two labels and alpha TLD."""
        if value.startswith(("http://", "https://")):
            return False
        normalized = self.ctx.normalize_domain(value)
        parts = normalized.split(".")
        if len(parts) != DOMAIN_PARTS:
            return False
        left, tld = parts
        return self.ctx.label_allowed(left) and tld.isalpha()


@dataclass
class HashDetector:
    """Detect hex digests for MD5/SHA1/SHA256 by length and charset."""

    name: str = "hash"

    def matches(self, value: str) -> bool:
        """Return True if ``value`` is a valid hex digest of known size."""
        if len(value) not in HASH_LENGTHS:
            return False
        # Accept only hex digits for configured lengths
        return all(c in "0123456789abcdefABCDEF" for c in value)


@dataclass
class UserAgentDetector:
    """Detect legacy user-agent strings based on known prefixes."""

    name: str = "user-agent"

    def matches(self, value: str) -> bool:
        """Return True if ``value`` starts with a known UA prefix."""
        return value.startswith(USER_AGENT_PREFIXES)


@dataclass
class UriPathDetector:
    """Detect non-HTTP(S) URIs by presence of scheme and ``://``."""

    name: str = "uri_path"

    def matches(self, value: str) -> bool:
        """Return True for non-HTTP(S) URIs containing a scheme."""
        if value.startswith(("http://", "https://")):
            return False
        if "://" not in value:
            return False
        parsed = urlparse(value)
        return bool(parsed.scheme)


@dataclass
class RegistryDetector:
    """Detect Windows registry paths starting with known root hives."""

    name: str = "registry"

    def matches(self, value: str) -> bool:
        """Return True for registry strings containing backslashes and known hives."""
        prefixes = ("HKEY", "HKLM", "HKCU", "HKCR", "HKCC")
        if not value.startswith(prefixes):
            return False
        return "\\" in value


@dataclass
class MailDetector:
    """Detect simple email addresses, optionally handling ``mailto:`` prefix."""

    ctx: DetectionContext
    name: str = "mail"

    def matches(self, value: str) -> bool:
        """Return True for ``local@domain`` addresses validated by ``parseaddr``."""
        if self.ctx.support_mailto and value.startswith("mailto:"):
            value = value[7:]
        name, addr = parseaddr(value)
        if addr != value:
            return False
        if "@" not in addr:
            return False
        local, _, domain = addr.partition("@")
        return bool(local and domain and "." in domain)


@dataclass
class FqdnDetector:
    """Detect FQDNs with at least three labels and alpha TLD."""

    ctx: DetectionContext
    name: str = "fqdn"

    def matches(self, value: str) -> bool:
        """Return True for FQDNs where all labels are allowed and TLD is alpha."""
        if value.startswith(("http://", "https://")):
            return False
        normalized = self.ctx.normalize_domain(value)
        parts = normalized.split(".")
        if len(parts) < MIN_FQDN_LABELS:
            return False
        *labels, tld = parts
        return all(self.ctx.label_allowed(lbl) for lbl in labels) and tld.isalpha()


# --- Additional detectors (opt-in via extractor registration order) ---


@dataclass
class CidrDetector:
    """Detect IPv4/IPv6 CIDR notations like ``1.2.3.4/24`` or ``2001:db8::/48``."""

    name: str = "cidr"

    def matches(self, value: str) -> bool:
        """Return True when value is a valid network with an explicit prefix length."""
        if "/" not in value:
            return False
        try:
            # strict=False accepts host bits set but requires a prefix length
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False


@dataclass
class MacDetector:
    """Detect MAC addresses in common notations.

    Supported forms:
      - ``aa:bb:cc:dd:ee:ff``
      - ``aa-bb-cc-dd-ee-ff``
      - ``aabb.ccdd.eeff``
    """

    name: str = "mac"

    # Precompiled regexes to avoid false positives and keep performance reasonable
    _colon = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
    _dash = re.compile(r"^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}$")
    _dot = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")

    def matches(self, value: str) -> bool:
        """Check if value matches MAC address pattern."""
        v = value.strip()
        return bool(self._colon.match(v) or self._dash.match(v) or self._dot.match(v))


@dataclass
class AsnDetector:
    """Detect Autonomous System Numbers like ``AS13335``."""

    name: str = "asn"

    _asn = re.compile(r"^(?i:AS)[0-9]{1,10}$")

    def matches(self, value: str) -> bool:
        """Check if value matches ASN pattern."""
        return bool(self._asn.match(value))


@dataclass
class CveDetector:
    """Detect CVE identifiers like ``CVE-2023-12345``."""

    name: str = "cve"

    _cve = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    def matches(self, value: str) -> bool:
        """Check if value matches CVE pattern."""
        return bool(self._cve.match(value))


@dataclass
class IpPortDetector:
    """Detect IPv4 with TCP/UDP port like ``1.2.3.4:443``."""

    name: str = "ip_port"

    _ip_port = re.compile(r"^(\d{1,3}\.){3}\d{1,3}:(\d{1,5})$")

    def matches(self, value: str) -> bool:
        """Check if value matches IP:port pattern."""
        m = self._ip_port.match(value)
        if not m:
            return False
        # Validate IP and port ranges using stdlib
        host, _, port_str = value.rpartition(":")
        try:
            ipaddress.IPv4Address(host)
            port = int(port_str)
            return 0 < port <= MAX_PORT_NUMBER
        except (ValueError, ipaddress.AddressValueError):
            return False
