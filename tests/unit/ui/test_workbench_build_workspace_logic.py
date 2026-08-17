from __future__ import annotations

from types import SimpleNamespace

from d810.ui.workbench_build_workspace_logic import (
    build_function_dossier,
    build_workspace_projection,
)


def test_generic_case_dossier_is_visible_without_claiming_a_protection() -> None:
    snapshot = SimpleNamespace(
        function=SimpleNamespace(name="test_nested_or", ea=0x18000340),
        attack=SimpleNamespace(
            selected_profile=None,
            observed_shape="unknown",
            mechanism="unknown",
        ),
        case=None,
        collection_errors=(),
    )

    dossier = build_function_dossier(snapshot)

    assert dossier.protection_label == "Generic cleanup"
    assert "no classified protection-specific case evidence" in dossier.summary
    assert dossier.shape_lines == ()


def test_footer_uses_global_capture_state_not_case_presence() -> None:
    snapshot = SimpleNamespace(
        function=SimpleNamespace(name="f", ea=0x1000),
        attack=SimpleNamespace(selected_profile=None),
        case=None,
        runtime=SimpleNamespace(runtime_name="project.json"),
        engine_started=False,
    )
    canvas = SimpleNamespace(maturities=())

    enabled = build_workspace_projection(
        snapshot,
        canvas,
        diagnostics_capture_enabled=True,
    )
    disabled = build_workspace_projection(
        snapshot,
        canvas,
        diagnostics_capture_enabled=False,
    )

    assert enabled.footer.diagnostics_capture == "Diagnostics capture ON"
    assert disabled.footer.diagnostics_capture == "Diagnostics capture OFF"
