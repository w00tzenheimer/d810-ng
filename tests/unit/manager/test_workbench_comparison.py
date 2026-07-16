from __future__ import annotations

import dataclasses

import pytest

from d810.manager.workbench_comparison import (
    ComparisonIdentity,
    WorkbenchComparisonService,
    function_byte_fingerprint,
)
from d810.manager.workbench_models import ArtifactFreshness


def _identity(**changes: object) -> ComparisonIdentity:
    identity = ComparisonIdentity(
        function_ea=0x401000,
        function_fingerprint="fingerprint:one",
        decompilation_generation=7,
        idb_identity="idb:sample",
        type_generation="types:4",
        hexrays_version="9.2",
        runtime_path="/runtime/sample.json",
        runtime_pass_ids=("pass.one", "pass.two"),
        runtime_generation=3,
    )
    return dataclasses.replace(identity, **changes)


def _captured_service() -> WorkbenchComparisonService:
    timestamps = iter((100.25, 101.5))
    service = WorkbenchComparisonService(clock=lambda: next(timestamps))
    identity = _identity()
    service.capture_baseline(identity, "int f() {\r\n  return 1;\r\n}\r\n\r\n")
    service.capture_d810_output(identity, "int f() {\n  return 2;\n}\n")
    return service


def test_function_byte_fingerprint_uses_the_shared_sha256_identity_format() -> None:
    assert function_byte_fingerprint(b"\x01\x02\x03\x04") == (
        "sha256:9f64a747e1b97f131fabb6b447296c9b" "6f0201e79fb3c5356e6c77e89b6a806a"
    )


def test_capture_normalizes_text_and_records_deterministic_metadata() -> None:
    service = _captured_service()

    baseline, output = service.refs(0x401000)

    assert baseline.pseudocode == "int f() {\n  return 1;\n}\n"
    assert baseline.captured_at == 100.25
    assert baseline.line_count == 3
    assert baseline.character_count == 24
    assert baseline.content_sha256 == (
        "sha256:0b770cbd97f00faf47697bb179be619c1a15c509c4469789008f36506afcb283"
    )
    assert output.pseudocode == "int f() {\n  return 2;\n}\n"
    assert output.captured_at == 101.5
    assert output.runtime_path == "/runtime/sample.json"
    assert output.runtime_pass_ids == ("pass.one", "pass.two")
    assert output.runtime_generation == 3


def test_compare_returns_current_evidence_and_non_semantic_metrics() -> None:
    comparison = _captured_service().compare(_identity())

    assert comparison.baseline_freshness is ArtifactFreshness.CURRENT
    assert comparison.d810_freshness is ArtifactFreshness.CURRENT
    assert comparison.baseline_stale_reasons == ()
    assert comparison.d810_stale_reasons == ()
    assert comparison.text_changed is True
    assert [metric.name for metric in comparison.metrics] == ["Lines", "Characters"]
    assert comparison.metrics[0].delta == 0
    assert comparison.metrics[1].delta == 0


@pytest.mark.parametrize(
    ("change", "reason", "stale_side"),
    (
        (
            {"function_fingerprint": "fingerprint:two"},
            "Function fingerprint changed",
            "both",
        ),
        ({"decompilation_generation": 8}, "Decompilation generation changed", "both"),
        ({"idb_identity": "idb:other"}, "IDB identity changed", "both"),
        ({"type_generation": "types:5"}, "Type generation changed", "both"),
        ({"hexrays_version": "9.3"}, "Hex-Rays version changed", "both"),
        ({"runtime_path": "/runtime/other.json"}, "Runtime path changed", "d810"),
        ({"runtime_pass_ids": ("pass.two",)}, "Runtime pass IDs changed", "d810"),
        ({"runtime_generation": 4}, "Runtime generation changed", "d810"),
    ),
)
def test_compare_rejects_each_drift_dimension(
    change: dict[str, object], reason: str, stale_side: str
) -> None:
    comparison = _captured_service().compare(_identity(**change))

    if stale_side == "both":
        assert comparison.baseline_freshness is ArtifactFreshness.STALE
        assert reason in comparison.baseline_stale_reasons
    else:
        assert comparison.baseline_freshness is ArtifactFreshness.CURRENT
    assert comparison.d810_freshness is ArtifactFreshness.STALE
    assert reason in comparison.d810_stale_reasons
    assert comparison.text_changed is None
    assert comparison.metrics == ()


def test_compare_never_reuses_artifacts_from_another_function() -> None:
    comparison = _captured_service().compare(_identity(function_ea=0x402000))

    assert comparison.baseline_freshness is ArtifactFreshness.MISSING
    assert comparison.d810_freshness is ArtifactFreshness.MISSING


def test_compare_reports_missing_artifacts_without_inventing_metrics() -> None:
    comparison = WorkbenchComparisonService().compare(_identity())

    assert comparison.baseline_freshness is ArtifactFreshness.MISSING
    assert comparison.d810_freshness is ArtifactFreshness.MISSING
    assert comparison.baseline_stale_reasons == (
        "Native baseline has not been captured",
    )
    assert comparison.d810_stale_reasons == ("D810 output has not been captured",)
    assert comparison.text_changed is None
    assert comparison.metrics == ()
