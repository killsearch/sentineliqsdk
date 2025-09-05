"""IOC extractor utilities used by analyzers to auto-extract artifacts.

This version prefers Python's standard library helpers over complex regular
expressions where feasible (e.g., ipaddress, urllib.parse, email.utils),
keeping behavior aligned with the test suite.
"""

from __future__ import annotations

import ipaddress
import string
from collections.abc import Callable
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from sentineliqsdk.constants import (
    DOMAIN_PARTS,
    HASH_LENGTHS,
    MIN_FQDN_LABELS,
    USER_AGENT_PREFIXES,
)
from sentineliqsdk.models import ExtractorResult, ExtractorResults

# Precomputed character sets to avoid rebuilding per call
ALLOWED_LABEL_CHARS = frozenset(string.ascii_letters + string.digits + "_-")
HEX_DIGITS = frozenset(string.hexdigits)


class ExtractionError(Exception):
    """Extraction error raised for invalid inputs."""


class Extractor:
    """Detect IOC attribute types using stdlib-backed heuristics.

    Two functions are provided:
      - ``check_string(str)`` which checks a string and returns the type.
      - ``check_iterable(itr)`` that iterates over a list or a dictionary and returns a
        list of {type, value} dicts.

    Note: not a full-text search; IOC values must appear as isolated strings.

    :param ignore: String to ignore when matching artifacts to type
    """

    def __init__(self, ignore: str | None = None):
        self.ignore = ignore
        # Small per-instance cache to avoid repeated classification work.
        self._cache: dict[tuple[str | None, str], str] = {}
        # Pre-bind predicate checks to avoid rebuilding on every call
        self._checks: list[tuple[Callable[[str], bool], str]] = [
            (self._is_ip, "ip"),
            (self._is_url, "url"),
            (self._is_domain, "domain"),
            (self._is_hash, "hash"),
            (self._is_user_agent, "user-agent"),
            (self._is_uri_path, "uri_path"),
            (self._is_registry, "registry"),
            (self._is_mail, "mail"),
            (self._is_fqdn, "fqdn"),
        ]

    # --- Type checks ---
    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_url(value: str) -> bool:
        if not value.startswith(("http://", "https://")):
            return False
        parsed = urlparse(value)
        return bool(parsed.scheme in {"http", "https"} and parsed.netloc)

    @staticmethod
    def _label_allowed(label: str) -> bool:
        return bool(label) and all(c in ALLOWED_LABEL_CHARS for c in label)

    @classmethod
    def _is_domain(cls, value: str) -> bool:
        if value.startswith(("http://", "https://")):
            return False
        parts = value.split(".")
        if len(parts) != DOMAIN_PARTS:
            return False
        left, tld = parts
        return cls._label_allowed(left) and tld.isalpha()

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
        # Consider non-HTTP(S) URI schemes like ftp://, file://, etc.
        if value.startswith(("http://", "https://")):
            return False
        if "://" not in value:
            return False
        parsed = urlparse(value)
        return bool(parsed.scheme)

    @staticmethod
    def _is_registry(value: str) -> bool:
        prefixes = ("HKEY", "HKLM", "HKCU", "HKCR", "HKCC")
        if not value.startswith(prefixes):
            return False
        return "\\" in value

    @staticmethod
    def _is_mail(value: str) -> bool:
        name, addr = parseaddr(value)
        if addr != value:
            return False
        if "@" not in addr:
            return False
        local, _, domain = addr.partition("@")
        return bool(local and domain and "." in domain)

    @classmethod
    def _is_fqdn(cls, value: str) -> bool:
        if value.startswith(("http://", "https://")):
            return False
        parts = value.split(".")
        if len(parts) < MIN_FQDN_LABELS:
            return False
        *labels, tld = parts
        return all(cls._label_allowed(lbl) for lbl in labels) and tld.isalpha()

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
            key = (self.ignore, value)
            if key in self._cache:
                return self._cache[key]

            dtype = ""
            for predicate, dtype_name in self._checks:
                if predicate(value):
                    dtype = dtype_name
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

        stack: list[Any] = [iterable]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list | tuple | set):
                stack.extend(item)
            elif isinstance(item, str):
                dt = self.__checktype(item)
                if dt:
                    results.add_result(dt, item)

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
