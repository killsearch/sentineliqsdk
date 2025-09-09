"""IOC extractor utilities used by analyzers to auto-extract artifacts.

This extractor prioritizes Python stdlib helpers over complex regexes (e.g.,
``ipaddress``, ``urllib.parse``, ``email.utils``) while keeping behavior aligned with tests.

Detector order (first match wins):
  1. ip
  2. cidr
  3. url
  4. domain
  5. hash
  6. user-agent
  7. uri_path
  8. registry
  9. mail
 10. mac
 11. asn
 12. cve
 13. ip_port
 14. fqdn

You can customize detection precedence via ``register_detector(detector, before=..., after=...)``.
Only one of ``before`` or ``after`` is allowed. If neither is provided, the detector is appended.
"""

from __future__ import annotations

import encodings.idna
import ipaddress
import string
from typing import Any, cast
from urllib.parse import urlparse, urlunparse

from sentineliqsdk.constants import (
    DEFAULT_HTTP_PORT,
    DEFAULT_HTTPS_PORT,
    HASH_LENGTHS,
    USER_AGENT_PREFIXES,
)
from sentineliqsdk.extractors.detectors import (
    AsnDetector,
    CidrDetector,
    CveDetector,
    DetectionContext,
    Detector,
    DomainDetector,
    FqdnDetector,
    HashDetector,
    IpDetector,
    IpPortDetector,
    MacDetector,
    MailDetector,
    RegistryDetector,
    UriPathDetector,
    UrlDetector,
    UserAgentDetector,
)
from sentineliqsdk.models import DataType, ExtractorResult, ExtractorResults

# Precomputed character sets to avoid rebuilding per call
ALLOWED_LABEL_CHARS = frozenset(string.ascii_letters + string.digits + "_-")
ALLOWED_LABEL_CHARS_STRICT = frozenset(string.ascii_letters + string.digits + "-")
HEX_DIGITS = frozenset(string.hexdigits)

# Size limits for DoS protection
MAX_STRING_LENGTH = 10000  # Maximum string length to process
MAX_ITERABLE_DEPTH = 100  # Maximum nesting depth for iterables




class ExtractionError(Exception):
    """Extraction error raised for invalid inputs."""


class Extractor(DetectionContext):
    """Detect IOC attribute types using stdlib-backed heuristics.

    Two functions are provided:
      - ``check_string(str)`` which checks a string and returns the type.
      - ``check_iterable(itr)`` that iterates over a list or a dictionary and returns a
        list of {type, value} dicts.

    Note: not a full-text search; IOC values must appear as isolated strings.

    :param ignore: String to ignore when matching artifacts to type
    :param strict_dns: If True, enforce RFC-compliant DNS validation (no underscores)
    :param normalize_domains: If True, normalize domains using IDNA/punycode
    :param normalize_urls: If True, normalize URLs (lowercase host, remove default ports)
    :param support_mailto: If True, accept mailto: prefix in email detection
    :param max_string_length: Maximum string length to process (DoS protection)
    :param max_iterable_depth: Maximum nesting depth for iterables (DoS protection)
    """

    def __init__(
        self,
        ignore: str | None = None,
        strict_dns: bool = False,
        normalize_domains: bool = False,
        normalize_urls: bool = False,
        support_mailto: bool = False,
        max_string_length: int = MAX_STRING_LENGTH,
        max_iterable_depth: int = MAX_ITERABLE_DEPTH,
    ):
        self.ignore = ignore
        self.strict_dns = strict_dns
        self.normalize_domains = normalize_domains
        self.normalize_urls = normalize_urls
        self.support_mailto = support_mailto
        self.max_string_length = max_string_length
        self.max_iterable_depth = max_iterable_depth

        # Small per-instance cache to avoid repeated classification work.
        self._cache: dict[tuple[str | None, str], str] = {}

        # Detectors compose classification in precedence order.
        self._detectors: list[Detector] = [
            IpDetector(),
            CidrDetector(),
            UrlDetector(self),
            DomainDetector(self),
            HashDetector(),
            UserAgentDetector(),
            UriPathDetector(),
            RegistryDetector(),
            MailDetector(self),
            MacDetector(),
            AsnDetector(),
            CveDetector(),
            IpPortDetector(),
            FqdnDetector(self),
        ]

    # --- Extensibility helpers ---
    def register_detector(
        self, detector: Detector, *, before: str | None = None, after: str | None = None
    ) -> None:
        """Register a custom detector.

        - If neither ``before`` nor ``after`` is provided, appends to the end.
        - If ``before`` is provided, inserts before the first detector with that name.
        - If ``after`` is provided, inserts after the first detector with that name.
        """
        if before and after:
            raise ValueError("Use only one of 'before' or 'after'.")

        if before:
            for i, det in enumerate(self._detectors):
                if det.name == before:
                    self._detectors.insert(i, detector)
                    return
        elif after:  # pragma: no branch
            for i, det in enumerate(self._detectors):
                if det.name == after:
                    self._detectors.insert(i + 1, detector)
                    return

        self._detectors.append(detector)

    # --- Type checks ---
    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_url(self, value: str) -> bool:
        return UrlDetector(self).matches(value)

    def _label_allowed(self, label: str) -> bool:
        """Check if a DNS label is allowed based on current strict mode."""
        if not label:
            return False
        allowed_chars = ALLOWED_LABEL_CHARS_STRICT if self.strict_dns else ALLOWED_LABEL_CHARS
        return all(c in allowed_chars for c in label)

    # DetectionContext adapters used by detectors
    def label_allowed(self, label: str) -> bool:
        """Public adapter for detectors to validate a single DNS label."""
        return self._label_allowed(label)

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain using IDNA/punycode if enabled."""
        if not self.normalize_domains:
            return domain
        try:
            # Convert to IDNA encoding (punycode)
            return encodings.idna.ToASCII(domain).decode("ascii")
        except (UnicodeError, ValueError):
            # If normalization fails, return original
            return domain

    def normalize_domain(self, domain: str) -> str:
        """Public adapter for detectors to normalize domains according to settings."""
        return self._normalize_domain(domain)

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by lowercasing host and removing default ports."""
        if not self.normalize_urls:
            return url
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return url

            # Lowercase the hostname
            hostname = parsed.hostname.lower() if parsed.hostname else parsed.netloc.lower()

            # Remove default ports
            port = parsed.port
            if port and (
                (parsed.scheme == "http" and port == DEFAULT_HTTP_PORT)
                or (parsed.scheme == "https" and port == DEFAULT_HTTPS_PORT)
            ):
                port = None

            # Reconstruct netloc
            netloc = f"{hostname}:{port}" if port else hostname

            # Reconstruct URL
            return urlunparse(
                (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
            )
        except (ValueError, AttributeError):
            # If normalization fails, return original
            return url

    def normalize_url(self, url: str) -> str:
        """Public adapter for detectors to normalize URLs according to settings."""
        return self._normalize_url(url)

    def _is_domain(self, value: str) -> bool:
        return DomainDetector(self).matches(value)

    @staticmethod
    def _is_hash(value: str) -> bool:
        if len(value) not in HASH_LENGTHS:
            return False
        return all(c in HEX_DIGITS for c in value)

    @staticmethod
    def _is_user_agent(value: str) -> bool:
        return value.startswith(USER_AGENT_PREFIXES)

    @staticmethod
    def _is_uri_path(value: str) -> bool:
        return UriPathDetector().matches(value)

    @staticmethod
    def _is_registry(value: str) -> bool:
        return RegistryDetector().matches(value)

    def _is_mail(self, value: str) -> bool:
        return MailDetector(self).matches(value)

    def _is_fqdn(self, value: str) -> bool:
        return FqdnDetector(self).matches(value)

    def __checktype(self, value: Any) -> str:
        """Check if the given value is a known datatype.

        :param value: The value to check
        :type value: str or number
        :return: Data type of value, if known, else empty string
        :rtype: str
        """
        if self.ignore and isinstance(value, str) and self.ignore == value:
            # Ignore only exact matches to avoid hiding valid IOCs that merely
            # contain the observable as a substring.
            return ""

        if isinstance(value, str):
            # Check string length limit for DoS protection
            if len(value) > self.max_string_length:
                return ""

            key = (self.ignore, value)
            if key in self._cache:
                return self._cache[key]

            dtype = ""
            for detector in self._detectors:
                if detector.matches(value):
                    dtype = detector.name
                    break

            self._cache[key] = dtype
            return dtype
        return ""

    def check_string(self, value: str) -> str:
        """Check if a string matches a datatype.

        :param value: String to test
        :type value: str
        :return: Data type or empty string
        :rtype: str
        """
        return self.__checktype(value)

    def check_iterable(self, iterable: Any) -> list[ExtractorResult]:
        """Check values of a list or a dict for IOCs.

        Returns a list of ExtractorResult objects. Raises TypeError if iterable is not an
        expected type.

        :param iterable: List or dict of values
        :type iterable: list | dict | str
        :return: List of IOC results
        :rtype: list[ExtractorResult]
        """
        results = ExtractorResults()

        if not isinstance(iterable, str | list | dict | tuple | set):
            raise TypeError("Not supported type.")

        # Use depth tracking for DoS protection
        stack: list[tuple[Any, int]] = [(iterable, 0)]
        while stack:
            item, depth = stack.pop()

            # Check depth limit
            if depth > self.max_iterable_depth:
                continue

            if isinstance(item, dict):
                stack.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list | tuple | set):
                stack.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):  # pragma: no branch
                dt = self.__checktype(item)
                if dt:
                    # Narrow dtype to the declared DataType Literal for type checkers
                    results.add_result(cast(DataType, dt), item)

        # Deduplicate and return as list of ExtractorResult objects
        deduped = results.deduplicate()
        return deduped.results

    @staticmethod
    def deduplicate(list_of_objects: list[dict[str, str]]) -> list[dict[str, str]]:
        """Deduplicate list of IOC objects by type + data in O(n)."""
        seen: set[tuple[str, str]] = set()
        dedup_list: list[dict[str, str]] = []
        for obj in list_of_objects:
            key = (obj["dataType"], obj["data"])
            if key in seen:
                continue
            seen.add(key)
            dedup_list.append(obj)
        return dedup_list

    @staticmethod
    def deduplicate_results(results: list[ExtractorResult]) -> list[ExtractorResult]:
        """Deduplicate ``ExtractorResult`` items by ``data_type`` and ``data``.

        This mirrors ``deduplicate`` but works with the modern dataclass API.
        """
        seen: set[tuple[str, str]] = set()
        unique: list[ExtractorResult] = []
        for r in results:
            key = (r.data_type, r.data)
            if key in seen:
                continue
            seen.add(key)
            unique.append(r)
        return unique
