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
HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256
MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64

# Domain validation constants
DOMAIN_PARTS = 2
MIN_FQDN_LABELS = 3

# User agent detection
USER_AGENT_PREFIXES = ("Mozilla/4.0 ", "Mozilla/5.0 ")

# System exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1

# JSON serialization
JSON_ENSURE_ASCII = False
