from __future__ import annotations

import pytest

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cuckoo import CuckooSandboxAnalyzer


def test_metadata_present() -> None:
    input_data = WorkerInput(data_type="url", data="http://example.com")
    analyzer = CuckooSandboxAnalyzer(input_data)
    assert analyzer.METADATA is not None


def test_execute_requires_url_config(monkeypatch: pytest.MonkeyPatch) -> None:
    input_data = WorkerInput(data_type="url", data="http://example.com", config=WorkerConfig())
    analyzer = CuckooSandboxAnalyzer(input_data)
    with pytest.raises(RuntimeError):
        analyzer.execute()
