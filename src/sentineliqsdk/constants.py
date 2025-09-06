"""Constants and configuration values for SentinelIQ SDK.

This module centralizes all constants used throughout the SDK to improve
maintainability and avoid magic numbers scattered across the codebase.
"""

from __future__ import annotations

# Security and sanitization
DEFAULT_SECRET_PHRASES = ("key", "password", "secret", "token")

# TLP/PAP configuration defaults
DEFAULT_TLP = 2
DEFAULT_PAP = 2

# Hash validation constants
# Supported lengths: MD5 (32), SHA1 (40), SHA256 (64)
# Note: SHA512 (128) is intentionally excluded to match current extractor behavior/tests.
HASH_LENGTHS = {32, 40, 64}
MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64
SHA512_LENGTH = 128

# Domain validation constants
DOMAIN_PARTS = 2
MIN_FQDN_LABELS = 3

# User agent detection
USER_AGENT_PREFIXES = ("Mozilla/4.0 ", "Mozilla/5.0 ")

# System exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1

# JSON serialization
# When True, json.dumps escapes non-ASCII characters; when False, preserves Unicode.
JSON_ENSURE_ASCII = False
