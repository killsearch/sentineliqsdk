"""Analyzer tests using pytest with parallel-safe patterns."""

from __future__ import annotations

import json
import os
import sys
from io import StringIO

import pytest

from sentineliqsdk import Analyzer


def _set_stdin_from_fixture(monkeypatch: pytest.MonkeyPatch, fixture_path: str) -> None:
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, fixture_path)) as fh:
        content = fh.read()
    monkeypatch.setattr(sys, "stdin", StringIO(content))


def test_default_config(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-minimal-config.json")
    analyzer = Analyzer()
    assert analyzer.data_type == "ip"
    assert analyzer.tlp == 2
    assert not analyzer.enable_check_tlp
    assert analyzer.max_tlp == 2
    assert analyzer.http_proxy is None
    assert analyzer.https_proxy is None


def test_artifact_data(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-minimal-config.json")
    analyzer = Analyzer()
    assert analyzer.get_data() == "1.1.1.1"


def test_params_data(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-minimal-config.json")
    analyzer = Analyzer()
    assert analyzer.get_param("data") == "1.1.1.1"


def test_proxy_config(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-proxy-config.json")
    analyzer = Analyzer()
    proxy_url = "http://local.proxy:8080"
    assert analyzer.http_proxy == proxy_url
    assert analyzer.https_proxy == proxy_url
    assert os.environ["http_proxy"] == proxy_url
    assert os.environ["https_proxy"] == proxy_url


def test_check_tlp_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-tlp-config.json")
    analyzer = Analyzer()
    analyzer.enable_check_tlp = False
    assert analyzer._Worker__check_tlp() is True  # type: ignore[attr-defined]


def test_check_tlp_ko(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-tlp-config.json")
    analyzer = Analyzer()
    analyzer.enable_check_tlp = True
    analyzer.max_tlp = 1
    analyzer.tlp = 3
    assert analyzer._Worker__check_tlp() is False  # type: ignore[attr-defined]


def test_check_tlp_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-tlp-config.json")
    analyzer = Analyzer()
    analyzer.enable_check_tlp = True
    analyzer.max_tlp = 3
    analyzer.tlp = 3
    assert analyzer._Worker__check_tlp() is True  # type: ignore[attr-defined]


def test_error_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-error-response.json")
    analyzer = Analyzer()
    assert analyzer.get_param("config.password") == "secret"
    assert analyzer.get_param("config.key") == "secret"
    assert analyzer.get_param("config.apikey") == "secret"
    assert analyzer.get_param("config.api_key") == "secret"
    assert analyzer.get_param("config.apiSecret") == "secret"
    assert analyzer.get_param("config.api_Pass") == "secret"
    assert analyzer.get_param("config.API") == "secret"

    with pytest.raises(SystemExit):
        analyzer.error("Error", True)

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


def test_report_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_stdin_from_fixture(monkeypatch, "fixtures/test-report-response.json")
    analyzer = Analyzer()
    analyzer.report({"report_id": "12345"})
    out = capsys.readouterr().out.strip()
    json_output = json.loads(out)
    assert json_output.get("success") is True
    assert json_output.get("errorMessage", None) is None
    assert json_output["full"]["report_id"] == "12345"
