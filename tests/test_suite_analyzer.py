"""Analyzer tests using pytest with parallel-safe patterns."""

from __future__ import annotations

import json
import os

import pytest

from sentineliqsdk import Analyzer


def _load_fixture(fixture_path: str) -> dict:
    """Load fixture JSON data."""
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, fixture_path)) as fh:
        return json.load(fh)


def test_default_config() -> None:
    input_data = _load_fixture("fixtures/test-minimal-config.json")
    analyzer = Analyzer(input_data)
    assert analyzer.data_type == "ip"
    assert analyzer.tlp == 2
    assert not analyzer.enable_check_tlp
    assert analyzer.max_tlp == 2
    assert analyzer.http_proxy is None
    assert analyzer.https_proxy is None


def test_artifact_data() -> None:
    input_data = _load_fixture("fixtures/test-minimal-config.json")
    analyzer = Analyzer(input_data)
    assert analyzer.get_data() == "1.1.1.1"


def test_params_data() -> None:
    input_data = _load_fixture("fixtures/test-minimal-config.json")
    analyzer = Analyzer(input_data)
    assert analyzer.get_param("data") == "1.1.1.1"


def test_proxy_config() -> None:
    input_data = _load_fixture("fixtures/test-proxy-config.json")
    analyzer = Analyzer(input_data)
    proxy_url = "http://local.proxy:8080"
    assert analyzer.http_proxy == proxy_url
    assert analyzer.https_proxy == proxy_url
    assert os.environ["http_proxy"] == proxy_url
    assert os.environ["https_proxy"] == proxy_url


def test_check_tlp_disabled() -> None:
    input_data = _load_fixture("fixtures/test-tlp-config.json")
    analyzer = Analyzer(input_data)
    analyzer.enable_check_tlp = False
    # TLP check is disabled, so it should pass
    assert not (analyzer.enable_check_tlp and analyzer.tlp > analyzer.max_tlp)


def test_check_tlp_ko() -> None:
    input_data = _load_fixture("fixtures/test-tlp-config.json")
    analyzer = Analyzer(input_data)
    analyzer.enable_check_tlp = True
    analyzer.max_tlp = 1
    analyzer.tlp = 3
    # TLP is higher than max, should fail
    assert analyzer.enable_check_tlp and analyzer.tlp > analyzer.max_tlp


def test_check_tlp_ok() -> None:
    input_data = _load_fixture("fixtures/test-tlp-config.json")
    analyzer = Analyzer(input_data)
    analyzer.enable_check_tlp = True
    analyzer.max_tlp = 3
    analyzer.tlp = 3
    # TLP is within limits, should pass
    assert not (analyzer.enable_check_tlp and analyzer.tlp > analyzer.max_tlp)


def test_error_response(capsys: pytest.CaptureFixture[str]) -> None:
    input_data = _load_fixture("fixtures/test-error-response.json")
    analyzer = Analyzer(input_data)
    assert analyzer.get_param("config.password") == "secret"
    assert analyzer.get_param("config.key") == "secret"
    assert analyzer.get_param("config.apikey") == "secret"
    assert analyzer.get_param("config.api_key") == "secret"
    assert analyzer.get_param("config.apiSecret") == "secret"
    assert analyzer.get_param("config.api_Pass") == "secret"
    assert analyzer.get_param("config.API") == "secret"

    with pytest.raises(SystemExit):
        analyzer.error("Error")

    out = capsys.readouterr().out.strip()
    json_output = json.loads(out)
    assert json_output["success"] is False
    assert json_output["errorMessage"] == "Error"
    assert json_output["input"]["dataType"] == "ip"
    assert json_output["input"]["data"] == "1.1.1.1"
    assert json_output["input"]["config"]["password"] == "REMOVED"
    assert json_output["input"]["config"]["key"] == "REMOVED"
    assert json_output["input"]["config"]["apikey"] == "REMOVED"
    assert json_output["input"]["config"]["api_key"] == "REMOVED"
    assert json_output["input"]["config"]["apiSecret"] == "REMOVED"
    assert json_output["input"]["config"]["api_Pass"] == "secret"
    assert json_output["input"]["config"]["API"] == "secret"


def test_report_response() -> None:
    input_data = _load_fixture("fixtures/test-report-response.json")
    analyzer = Analyzer(input_data)
    result = analyzer.report({"report_id": "12345"})
    assert result.get("success") is True
    assert result.get("errorMessage", None) is None
    assert result["full"]["report_id"] == "12345"
