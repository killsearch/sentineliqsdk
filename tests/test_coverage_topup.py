"""Top-up tests to drive coverage to 100%.

These tests focus on branches and detectors that were previously uncovered.
"""

from __future__ import annotations

from sentineliqsdk.extractors.regex import Extractor
from sentineliqsdk.models import ExtractorResult


def test_cidr_detection_success() -> None:
    extractor = Extractor()
    assert extractor.check_string("10.0.0.0/8") == "cidr"


def test_ip_port_detector_valid_and_invalid() -> None:
    extractor = Extractor()

    # Valid ip:port should match
    assert extractor.check_string("1.2.3.4:443") == "ip_port"

    # Regex matches but IPv4 validation fails -> covers exception branch
    assert extractor.check_string("999.999.999.999:443") == ""


def test_deduplicate_results_function() -> None:
    # Cover Extractor.deduplicate_results with duplicates
    items = [
        ExtractorResult(data_type="ip", data="1.2.3.4"),
        ExtractorResult(data_type="ip", data="1.2.3.4"),
        ExtractorResult(data_type="url", data="https://example.com"),
    ]
    unique = Extractor.deduplicate_results(items)
    assert len(unique) == 2
    kinds = {(r.data_type, r.data) for r in unique}
    assert ("ip", "1.2.3.4") in kinds
    assert ("url", "https://example.com") in kinds
