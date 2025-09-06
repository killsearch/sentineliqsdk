"""Tests for sentineliqsdk.constants module."""

from __future__ import annotations

from sentineliqsdk.constants import (
    DEFAULT_PAP,
    DEFAULT_SECRET_PHRASES,
    DEFAULT_TLP,
    DOMAIN_PARTS,
    EXIT_ERROR,
    EXIT_SUCCESS,
    HASH_LENGTHS,
    JSON_ENSURE_ASCII,
    MD5_LENGTH,
    MIN_FQDN_LABELS,
    SHA1_LENGTH,
    SHA256_LENGTH,
    USER_AGENT_PREFIXES,
)


class TestConstants:
    """Test constants module values."""

    def test_default_tlp_pap(self):
        """Test default TLP and PAP values."""
        assert DEFAULT_TLP == 2
        assert DEFAULT_PAP == 2

    def test_secret_phrases(self):
        """Test default secret phrases."""
        assert DEFAULT_SECRET_PHRASES == ("key", "password", "secret", "token")

    def test_hash_lengths(self):
        """Test hash length constants."""
        assert {32, 40, 64} == HASH_LENGTHS
        assert MD5_LENGTH == 32
        assert SHA1_LENGTH == 40
        assert SHA256_LENGTH == 64

    def test_domain_constants(self):
        """Test domain validation constants."""
        assert DOMAIN_PARTS == 2
        assert MIN_FQDN_LABELS == 3

    def test_user_agent_prefixes(self):
        """Test user agent prefixes."""
        assert USER_AGENT_PREFIXES == ("Mozilla/4.0 ", "Mozilla/5.0 ")

    def test_exit_codes(self):
        """Test system exit codes."""
        assert EXIT_SUCCESS == 0
        assert EXIT_ERROR == 1

    def test_json_serialization(self):
        """Test JSON serialization constant."""
        assert JSON_ENSURE_ASCII is False
