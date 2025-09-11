"""Additional tests for sentineliqsdk.models to cover branch edges."""

from __future__ import annotations

from types import MappingProxyType

from sentineliqsdk.models import Artifact, Operation


def test_artifact_extra_non_dict_path() -> None:
    # Pass a MappingProxyType to exercise the 'not dict' branch in __post_init__
    proxy = MappingProxyType({"a": 1})
    art = Artifact(data_type="ip", data="1.2.3.4", extra=proxy)
    # Extra should be exactly the provided mapping (no conversion applied)
    assert art.extra is proxy


def test_operation_parameters_non_dict_path() -> None:
    # Pass a MappingProxyType to exercise the 'not dict' branch in __post_init__
    proxy = MappingProxyType({"x": 1})
    op = Operation(operation_type="hunt", parameters=proxy)
    # Parameters should be exactly the provided mapping (no conversion applied)
    assert op.parameters is proxy
