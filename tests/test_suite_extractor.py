"""Extractor tests using pytest functions for concurrency-friendly runs."""

from __future__ import annotations

from operator import itemgetter

from sentineliqsdk import Extractor


def test_single_fqdn() -> None:
    assert Extractor().check_string(value="www.google.de") == "fqdn"


def test_single_fqdn_as_unicode() -> None:
    assert Extractor().check_string(value="www.google.de") == "fqdn"


def test_single_domain() -> None:
    assert Extractor().check_string(value="google.de") == "domain"


def test_single_url() -> None:
    assert Extractor().check_string(value="https://google.de") == "url"


def test_single_ipv4() -> None:
    assert Extractor().check_string(value="10.0.0.1") == "ip"


def test_single_ipv6() -> None:
    assert Extractor().check_string(value="2001:0db8:85a3:08d3:1319:8a2e:0370:7344") == "ip"


def test_single_md5() -> None:
    assert Extractor().check_string(value="b373bd6b144e7846f45a1e47ced380b8") == "hash"


def test_single_sha1() -> None:
    assert Extractor().check_string(value="94d4d48ba9a79304617f8291982bf69a8ce16fb0") == "hash"


def test_single_sha256() -> None:
    assert (
        Extractor().check_string(
            value="7ef8b3dc5bf40268f66721a89b95f4c5f0cc08e34836f8c3a007ceed193654d4"
        )
        == "hash"
    )


def test_single_useragent() -> None:
    assert (
        Extractor().check_string(
            value=("Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0")
        )
        == "user-agent"
    )


def test_single_mail() -> None:
    assert Extractor().check_string(value="VeryImportant@mail.org") == "mail"


def test_single_regkey() -> None:
    assert (
        Extractor().check_string(
            value=("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        )
        == "registry"
    )


def test_iterable() -> None:
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

    assert sorted(l_real, key=itemgetter("data")) == sorted(l_expected, key=itemgetter("data"))


def test_float_domain() -> None:
    assert Extractor().check_string(value="0.001234") == ""


def test_float_fqdn() -> None:
    assert Extractor().check_string(value="0.1234.5678") == ""
