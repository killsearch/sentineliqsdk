"""Tests for sentineliqsdk.extractors module."""

from __future__ import annotations

import pytest

from sentineliqsdk.extractors import Extractor
from sentineliqsdk.models import ExtractorResult


class TestExtractor:
    """Test Extractor class."""

    def test_init_without_ignore(self):
        """Test Extractor initialization without ignore parameter."""
        extractor = Extractor()
        assert extractor.ignore is None

    def test_init_with_ignore(self):
        """Test Extractor initialization with ignore parameter."""
        extractor = Extractor(ignore="1.2.3.4")
        assert extractor.ignore == "1.2.3.4"

    def test_is_ip_valid_ipv4(self):
        """Test _is_ip method with valid IPv4 addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ]

        for ip in valid_ips:
            assert Extractor._is_ip(ip) is True

    def test_is_ip_valid_ipv6(self):
        """Test _is_ip method with valid IPv6 addresses."""
        valid_ips = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "::",
            "2001:db8::",
        ]

        for ip in valid_ips:
            assert Extractor._is_ip(ip) is True

    def test_is_ip_invalid(self):
        """Test _is_ip method with invalid IP addresses."""
        invalid_ips = [
            "256.1.1.1",
            "1.1.1.256",
            "192.168.1",
            "192.168.1.1.1",
            "not-an-ip",
            "192.168.1.1:8080",
            "http://192.168.1.1",
        ]

        for ip in invalid_ips:
            assert Extractor._is_ip(ip) is False

    def test_is_url_valid(self):
        """Test _is_url method with valid URLs."""
        valid_urls = [
            "http://example.com",
            "https://example.com",
            "http://example.com/path",
            "https://example.com/path?query=value",
            "http://subdomain.example.com",
            "https://example.com:8080",
        ]

        for url in valid_urls:
            assert Extractor._is_url(url) is True

    def test_is_url_invalid(self):
        """Test _is_url method with invalid URLs."""
        invalid_urls = [
            "ftp://example.com",
            "example.com",
            "http://",
            "https://",
            "not-a-url",
            "file:///path/to/file",
            "http://",
            "https://",
        ]

        for url in invalid_urls:
            assert Extractor._is_url(url) is False

    def test_label_allowed_valid(self):
        """Test _label_allowed method with valid labels."""
        valid_labels = [
            "example",
            "test123",
            "my-label",
            "label_with_underscore",
            "a",
            "123",
            "test-label_123",
        ]

        for label in valid_labels:
            assert Extractor._label_allowed(label) is True

    def test_label_allowed_invalid(self):
        """Test _label_allowed method with invalid labels."""
        invalid_labels = [
            "",
            "label with space",
            "label.with.dot",
            "label@with@at",
            "label+with+plus",
            "label=with=equals",
            "label/with/slash",
        ]

        for label in invalid_labels:
            assert Extractor._label_allowed(label) is False

    def test_is_domain_valid(self):
        """Test _is_domain method with valid domains."""
        valid_domains = [
            "example.com",
            "test.org",
            "a.b",
            "test-domain.com",
            "example123.com",
        ]

        for domain in valid_domains:
            assert Extractor._is_domain(domain) is True

    def test_is_domain_invalid(self):
        """Test _is_domain method with invalid domains."""
        invalid_domains = [
            "example",
            "com",
            "subdomain.example.com",  # Too many parts for domain
            "example.com.",
            ".example.com",
            "example..com",
            "http://example.com",
            "https://example.com",
            "example.com/path",
            "example@com",
            "example com",
        ]

        for domain in invalid_domains:
            assert Extractor._is_domain(domain) is False

    def test_is_hash_valid(self):
        """Test _is_hash method with valid hashes."""
        valid_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        ]

        for hash_value in valid_hashes:
            assert Extractor._is_hash(hash_value) is True

    def test_is_hash_invalid(self):
        """Test _is_hash method with invalid hashes."""
        invalid_hashes = [
            "d41d8cd98f00b204e9800998ecf8427",  # Too short
            "d41d8cd98f00b204e9800998ecf8427e1",  # Too long
            "d41d8cd98f00b204e9800998ecf8427g",  # Invalid character
            "not-a-hash",
            "1234567890abcdef",
        ]

        for hash_value in invalid_hashes:
            assert Extractor._is_hash(hash_value) is False

    def test_is_user_agent_valid(self):
        """Test _is_user_agent method with valid user agents."""
        valid_user_agents = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]

        for ua in valid_user_agents:
            assert Extractor._is_user_agent(ua) is True

    def test_is_user_agent_invalid(self):
        """Test _is_user_agent method with invalid user agents."""
        invalid_user_agents = [
            "curl/7.68.0",
            "wget/1.20.3",
            "python-requests/2.25.1",
            "not-a-user-agent",
            "Mozilla/3.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        ]

        for ua in invalid_user_agents:
            assert Extractor._is_user_agent(ua) is False

    def test_is_uri_path_valid(self):
        """Test _is_uri_path method with valid URI paths."""
        valid_uris = [
            "ftp://example.com",
            "file:///path/to/file",
            "ssh://user@host",
            "telnet://example.com",
            "ldap://ldap.example.com",
        ]

        for uri in valid_uris:
            assert Extractor._is_uri_path(uri) is True

    def test_is_uri_path_invalid(self):
        """Test _is_uri_path method with invalid URI paths."""
        invalid_uris = [
            "http://example.com",
            "https://example.com",
            "example.com",
            "not-a-uri",
            "://example.com",
            "http://",
        ]

        for uri in invalid_uris:
            assert Extractor._is_uri_path(uri) is False

    def test_is_registry_valid(self):
        """Test _is_registry method with valid registry paths."""
        valid_registries = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft",
            "HKLM\\SOFTWARE\\Microsoft\\Windows",
            "HKCU\\SOFTWARE\\MyApp",
            "HKCR\\CLSID\\{12345678-1234-1234-1234-123456789012}",
            "HKCC\\SYSTEM\\CurrentControlSet",
        ]

        for registry in valid_registries:
            assert Extractor._is_registry(registry) is True

    def test_is_registry_invalid(self):
        """Test _is_registry method with invalid registry paths."""
        invalid_registries = [
            "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft",
            "not-a-registry",
            "HKEY_LOCAL_MACHINE",
            "HKLM",
        ]

        for registry in invalid_registries:
            assert Extractor._is_registry(registry) is False

    def test_is_mail_valid(self):
        """Test _is_mail method with valid email addresses."""
        valid_emails = [
            "user@example.com",
            "test.email@domain.org",
            "user+tag@example.co.uk",
            "user123@test-domain.com",
            "a@b.co",
        ]

        for email in valid_emails:
            assert Extractor._is_mail(email) is True

    def test_is_mail_invalid(self):
        """Test _is_mail method with invalid email addresses."""
        invalid_emails = [
            "user@",
            "@example.com",
            "user@example",
            "user.example.com",
            "user@example@com",
            "user @example.com",
            "user@example .com",
        ]

        for email in invalid_emails:
            assert Extractor._is_mail(email) is False

    def test_is_fqdn_valid(self):
        """Test _is_fqdn method with valid FQDNs."""
        valid_fqdns = [
            "www.example.com",
            "subdomain.example.org",
            "a.b.c.d.e.f",
            "test.example.co.uk",
            "very.long.subdomain.example.com",
        ]

        for fqdn in valid_fqdns:
            assert Extractor._is_fqdn(fqdn) is True

    def test_is_fqdn_invalid(self):
        """Test _is_fqdn method with invalid FQDNs."""
        invalid_fqdns = [
            "example.com",
            "com",
            "www.example",
            "http://www.example.com",
            "https://www.example.com",
            "www.example.com/path",
            "www.example..com",
            "www.example com",
        ]

        for fqdn in invalid_fqdns:
            assert Extractor._is_fqdn(fqdn) is False

    def test_checktype_with_ignore(self):
        """Test __checktype method with ignore parameter."""
        extractor = Extractor(ignore="1.2.3.4")

        # Should ignore exact match
        assert extractor._Extractor__checktype("1.2.3.4") == ""

        # Should not ignore similar values
        assert extractor._Extractor__checktype("1.2.3.5") == "ip"

    def test_checktype_without_ignore(self):
        """Test __checktype method without ignore parameter."""
        extractor = Extractor()

        assert extractor._Extractor__checktype("1.2.3.4") == "ip"
        assert extractor._Extractor__checktype("https://example.com") == "url"
        assert extractor._Extractor__checktype("not-a-valid-type") == ""

    def test_checktype_with_non_string(self):
        """Test __checktype method with non-string input."""
        extractor = Extractor()

        assert extractor._Extractor__checktype(123) == ""
        assert extractor._Extractor__checktype(None) == ""
        assert extractor._Extractor__checktype([]) == ""

    def test_checktype_caching(self):
        """Test that __checktype method caches results."""
        extractor = Extractor()

        # First call should cache the result
        result1 = extractor._Extractor__checktype("1.2.3.4")
        assert result1 == "ip"

        # Second call should use cached result
        result2 = extractor._Extractor__checktype("1.2.3.4")
        assert result2 == "ip"

        # Cache should contain the result
        assert (None, "1.2.3.4") in extractor._cache

    def test_check_string(self):
        """Test check_string method."""
        extractor = Extractor()

        assert extractor.check_string("1.2.3.4") == "ip"
        assert extractor.check_string("https://example.com") == "url"
        assert extractor.check_string("example.com") == "domain"
        assert extractor.check_string("not-a-valid-type") == ""

    def test_check_iterable_with_list(self):
        """Test check_iterable method with list input."""
        extractor = Extractor()

        data = ["1.2.3.4", "https://example.com", "example.com", "not-valid"]
        results = extractor.check_iterable(data)

        assert len(results) == 3
        assert all(isinstance(result, ExtractorResult) for result in results)

        # Check specific results
        data_types = [result.data_type for result in results]
        assert "ip" in data_types
        assert "url" in data_types
        assert "domain" in data_types

    def test_check_iterable_with_dict(self):
        """Test check_iterable method with dict input."""
        extractor = Extractor()

        data = {
            "ip": "1.2.3.4",
            "url": "https://example.com",
            "domain": "example.com",
            "invalid": "not-valid",
        }
        results = extractor.check_iterable(data)

        assert len(results) == 3
        assert all(isinstance(result, ExtractorResult) for result in results)

    def test_check_iterable_with_nested_structure(self):
        """Test check_iterable method with nested structure."""
        extractor = Extractor()

        data = {
            "observable": "1.2.3.4",
            "related": {
                "ips": ["8.8.8.8", "1.1.1.1"],
                "urls": ["https://example.com"],
            },
            "metadata": {
                "tags": ["malware", "c2"],
                "domains": ["evil.com"],
            },
        }
        results = extractor.check_iterable(data)

        # Should find all IOCs in nested structure
        data_types = [result.data_type for result in results]
        assert data_types.count("ip") >= 3  # 1.2.3.4, 8.8.8.8, 1.1.1.1
        assert "url" in data_types
        assert "domain" in data_types

    def test_check_iterable_with_tuple(self):
        """Test check_iterable method with tuple input."""
        extractor = Extractor()

        data = ("1.2.3.4", "https://example.com", "example.com")
        results = extractor.check_iterable(data)

        assert len(results) == 3
        assert all(isinstance(result, ExtractorResult) for result in results)

    def test_check_iterable_with_set(self):
        """Test check_iterable method with set input."""
        extractor = Extractor()

        data = {"1.2.3.4", "https://example.com", "example.com"}
        results = extractor.check_iterable(data)

        assert len(results) == 3
        assert all(isinstance(result, ExtractorResult) for result in results)

    def test_check_iterable_with_string(self):
        """Test check_iterable method with string input."""
        extractor = Extractor()

        data = "1.2.3.4"
        results = extractor.check_iterable(data)

        assert len(results) == 1
        assert isinstance(results[0], ExtractorResult)
        assert results[0].data_type == "ip"
        assert results[0].data == "1.2.3.4"

    def test_check_iterable_with_unsupported_type(self):
        """Test check_iterable method with unsupported type."""
        extractor = Extractor()

        with pytest.raises(TypeError):
            extractor.check_iterable(123)

    def test_check_iterable_deduplication(self):
        """Test that check_iterable deduplicates results."""
        extractor = Extractor()

        data = ["1.2.3.4", "1.2.3.4", "https://example.com", "https://example.com"]
        results = extractor.check_iterable(data)

        # Should deduplicate based on data_type and data
        assert len(results) == 2
        data_types = [result.data_type for result in results]
        assert data_types.count("ip") == 1
        assert data_types.count("url") == 1

    def test_deduplicate_static_method(self):
        """Test deduplicate static method."""
        data = [
            {"dataType": "ip", "data": "1.2.3.4"},
            {"dataType": "ip", "data": "1.2.3.4"},  # Duplicate
            {"dataType": "url", "data": "https://example.com"},
            {"dataType": "ip", "data": "8.8.8.8"},
        ]

        result = Extractor.deduplicate(data)

        assert len(result) == 3
        assert result[0]["dataType"] == "ip"
        assert result[0]["data"] == "1.2.3.4"
        assert result[1]["dataType"] == "url"
        assert result[1]["data"] == "https://example.com"
        assert result[2]["dataType"] == "ip"
        assert result[2]["data"] == "8.8.8.8"

    def test_deduplicate_empty_list(self):
        """Test deduplicate static method with empty list."""
        result = Extractor.deduplicate([])
        assert result == []

    def test_deduplicate_no_duplicates(self):
        """Test deduplicate static method with no duplicates."""
        data = [
            {"dataType": "ip", "data": "1.2.3.4"},
            {"dataType": "url", "data": "https://example.com"},
        ]

        result = Extractor.deduplicate(data)
        assert len(result) == 2
        assert result == data
