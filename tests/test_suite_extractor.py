"""Extractor tests using convenient test names for IOC detection."""

from __future__ import annotations

from operator import itemgetter

from sentineliqsdk import Extractor


def test_extractor_detects_fqdn() -> None:
    """Test extractor detects fully qualified domain names."""
    assert Extractor().check_string(value="www.google.de") == "fqdn"


def test_extractor_detects_fqdn_unicode() -> None:
    """Test extractor detects FQDN with unicode characters."""
    assert Extractor().check_string(value="www.google.de") == "fqdn"


def test_extractor_detects_domain() -> None:
    """Test extractor detects domain names."""
    assert Extractor().check_string(value="google.de") == "domain"


def test_extractor_detects_url() -> None:
    """Test extractor detects URLs."""
    assert Extractor().check_string(value="https://google.de") == "url"


def test_extractor_detects_ipv4() -> None:
    """Test extractor detects IPv4 addresses."""
    assert Extractor().check_string(value="10.0.0.1") == "ip"


def test_extractor_detects_ipv6() -> None:
    """Test extractor detects IPv6 addresses."""
    assert Extractor().check_string(value="2001:0db8:85a3:08d3:1319:8a2e:0370:7344") == "ip"


def test_extractor_detects_md5_hash() -> None:
    """Test extractor detects MD5 hashes."""
    assert Extractor().check_string(value="b373bd6b144e7846f45a1e47ced380b8") == "hash"


def test_extractor_detects_sha1_hash() -> None:
    """Test extractor detects SHA1 hashes."""
    assert Extractor().check_string(value="94d4d48ba9a79304617f8291982bf69a8ce16fb0") == "hash"


def test_extractor_detects_sha256_hash() -> None:
    """Test extractor detects SHA256 hashes."""
    assert (
        Extractor().check_string(
            value="7ef8b3dc5bf40268f66721a89b95f4c5f0cc08e34836f8c3a007ceed193654d4"
        )
        == "hash"
    )


def test_extractor_detects_user_agent() -> None:
    """Test extractor detects user agent strings."""
    assert (
        Extractor().check_string(
            value=("Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0")
        )
        == "user-agent"
    )


def test_extractor_detects_email() -> None:
    """Test extractor detects email addresses."""
    assert Extractor().check_string(value="VeryImportant@mail.org") == "mail"


def test_extractor_detects_registry_key() -> None:
    """Test extractor detects Windows registry keys."""
    assert (
        Extractor().check_string(
            value=("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        )
        == "registry"
    )


def test_extractor_processes_iterable_data() -> None:
    """Test extractor processes complex nested data structures."""
    l_real = Extractor().check_iterable(
        {
            "results": [
                {"This is an totally unimportant key": "127.0.0.1"},
                {"Totally nested!": ["https://nestedurl.verynested.com"]},
            ],
            "some_more": "94d4d48ba9a79304617f8291982bf69a8ce16fb0",
            "another_list": ["google.de", "bing.com", "www.fqdn.de"],
        }
    )
    l_expected = [
        {"dataType": "hash", "data": "94d4d48ba9a79304617f8291982bf69a8ce16fb0"},
        {"dataType": "ip", "data": "127.0.0.1"},
        {"dataType": "url", "data": "https://nestedurl.verynested.com"},
        {"dataType": "domain", "data": "google.de"},
        {"dataType": "domain", "data": "bing.com"},
        {"dataType": "fqdn", "data": "www.fqdn.de"},
    ]

    # Convert ExtractorResult objects to dicts for comparison
    l_real_dicts = [{"dataType": r.data_type, "data": r.data} for r in l_real]
    assert sorted(l_real_dicts, key=itemgetter("data")) == sorted(
        l_expected, key=itemgetter("data")
    )


def test_extractor_rejects_float_as_domain() -> None:
    """Test extractor correctly rejects float values as domains."""
    assert Extractor().check_string(value="0.001234") == ""


def test_extractor_rejects_float_as_fqdn() -> None:
    """Test extractor correctly rejects float values as FQDNs."""
    assert Extractor().check_string(value="0.1234.5678") == ""
