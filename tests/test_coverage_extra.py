from __future__ import annotations

from typing import Any

import pytest

from sentineliqsdk import WorkerInput, runner
from sentineliqsdk.extractors.regex import Extractor


class DummyDetector:
    """Simple detector used to validate detector registration ordering."""

    def __init__(self, name: str, match_value: str):
        self.name = name
        self._match_value = match_value

    def matches(self, value: str) -> bool:  # pragma: no cover - trivial
        return value == self._match_value


def test_register_detector_before_influences_order():
    extractor = Extractor()
    custom = DummyDetector(name="custom", match_value="http://example.com")
    extractor.register_detector(custom, before="url")

    # Because the custom detector sits before 'url', it should win.
    assert extractor.check_string("http://example.com") == "custom"


def test_register_detector_after_and_default_append():
    extractor = Extractor()
    after_det = DummyDetector(name="afterurl", match_value="special-value")
    extractor.register_detector(after_det, after="url")

    # Ensure the detector was placed after the first 'url' detector
    names = [d.name for d in extractor._detectors]  # type: ignore[attr-defined]
    assert "url" in names
    url_index = names.index("url")
    assert names[url_index + 1] == "afterurl"

    # If target not found, detector should be appended at the end
    tail = DummyDetector(name="tail", match_value="irrelevant")
    extractor.register_detector(tail, before="does-not-exist")
    new_names = [d.name for d in extractor._detectors]  # type: ignore[attr-defined]
    assert new_names[-1] == "tail"


def test_register_detector_after_not_found_appends():
    extractor = Extractor()
    tail = DummyDetector(name="tail2", match_value="irrelevant")
    extractor.register_detector(tail, after="does-not-exist")
    names = [d.name for d in extractor._detectors]  # type: ignore[attr-defined]
    assert names[-1] == "tail2"


def test_register_detector_after_with_empty_list_hits_direct_append():
    extractor = Extractor()
    # Force empty detectors to traverse 124 -> 130 directly
    extractor._detectors = []  # type: ignore[attr-defined]
    tail = DummyDetector(name="tail3", match_value="irrelevant")
    extractor.register_detector(tail, after="url")
    names = [d.name for d in extractor._detectors]  # type: ignore[attr-defined]
    assert names == ["tail3"]


def test_register_detector_conflict_raises():
    extractor = Extractor()
    with pytest.raises(ValueError, match=r"Use only one of 'before' or 'after'."):
        extractor.register_detector(DummyDetector("x", "y"), before="url", after="ip")


def test_normalize_domain_exception_path():
    # Use a string with an invalid surrogate to trigger UnicodeError in IDNA
    bad = "bad\udcff.com"
    extractor = Extractor(normalize_domains=True)
    assert extractor._normalize_domain(bad) == bad


def test_normalize_url_branches(monkeypatch: pytest.MonkeyPatch):
    # Early return when normalization is disabled
    extractor = Extractor(normalize_urls=False)
    original = "http://EXAMPLE.com:80"
    assert extractor._normalize_url(original) == original

    # No netloc branch
    extractor2 = Extractor(normalize_urls=True)
    no_netloc = "http:/path"
    assert extractor2._normalize_url(no_netloc) == no_netloc

    # Exception path via monkeypatching urlparse to raise
    import sentineliqsdk.extractors.regex as regex_mod

    def boom(_url: str) -> Any:
        raise ValueError("parse error")

    monkeypatch.setattr(regex_mod, "urlparse", boom)
    assert extractor2._normalize_url("http://example.com") == "http://example.com"

    # Adapter coverage
    extractor3 = Extractor(normalize_urls=True)
    assert extractor3.normalize_url("http://example.com:80").startswith("http://")


def test_check_iterable_string_nonmatch_path():
    extractor = Extractor()
    # Multiple non-matching strings ensure 304 -> 293 is exercised
    results = extractor.check_iterable(["foo", "bar", "baz"])
    assert results == []


def test_runner_covers_package_init():
    ran = {"ok": False}

    class SimpleWorker:
        def __init__(self, input_data: WorkerInput):
            self.input_data = input_data

        def run(self) -> None:
            ran["ok"] = True

    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    runner(SimpleWorker, input_data)
    assert ran["ok"] is True
