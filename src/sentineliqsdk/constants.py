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

# Project license identifier for module metadata
SENTINELIQ_LICENSE = "SentinelIQ License"

# HTTP Status Codes
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_OK_MIN = 200
HTTP_OK_MAX = 300
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_RATE_LIMIT = 429
HTTP_CLIENT_ERROR_MIN = 400
HTTP_SERVER_ERROR_MIN = 500
HTTP_SUCCESS_STATUS = 200

# CIRCL Analyzers Thresholds
# EPSS (Exploit Prediction Scoring System) risk levels
EPSS_VERY_HIGH_THRESHOLD = 0.90
EPSS_HIGH_THRESHOLD = 0.70
EPSS_MODERATE_THRESHOLD = 0.40
EPSS_LOW_THRESHOLD = 0.10

# CVSS (Common Vulnerability Scoring System) severity levels
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

# CIRCL Passive SSL/DNS thresholds
SAFE_CERTIFICATE_THRESHOLD = 3
SAFE_RECORD_THRESHOLD = 5

# Threat Intelligence Analyzers Thresholds
SUSPICIOUS_RESULTS_THRESHOLD = 100  # Censys
MALICIOUS_REPORT_THRESHOLD = 5  # ChainAbuse
SAFE_SCORE_THRESHOLD = 50  # Cluster25
SUSPICIOUS_SCORE_THRESHOLD = 80  # Cluster25 and AnyRun
MALICIOUS_SCORE_THRESHOLD = 100  # AnyRun
MALICIOUS_THRESHOLD = 80  # AbuseIPDB

# Messaging and Queue Configuration
# Retry settings
RETRY_DELAY = 1.0
RETRY_BACKOFF = 2.0
MAX_RETRY_DELAY = 300.0
MAX_RETRIES = 3

# Timeout settings
CONNECTION_TIMEOUT = 30.0
REQUEST_TIMEOUT_MS = 30000

# Queue settings
PREFETCH_COUNT = 1
PREFETCH_SIZE = 0
AUTO_COMMIT_INTERVAL_MS = 1000

# Content Types
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_TEXT = "text/plain"

# Cuckoo Analyzer Thresholds
MALSCORE_SUSPICIOUS = 2.0
MALSCORE_MALICIOUS = 6.5

# Network and Security Constants
MAX_PORT_NUMBER = 65535
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
SHA1_HASH_LENGTH = 40
SHA256_HASH_LENGTH = 64

# SMTP Configuration
SMTP_GMAIL_SERVER = "smtp.gmail.com"
SMTP_OUTLOOK_SERVER = "smtp.office365.com"
SMTP_PORT = 587
