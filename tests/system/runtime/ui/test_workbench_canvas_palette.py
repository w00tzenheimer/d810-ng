"""Opt-in native smoke for the real searchable maturity-canvas popup."""

from __future__ import annotations

import os
import time

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("D810_NATIVE_GUI_SMOKE") != "1",
    reason="requires an explicitly disposable native IDA GUI session",
)


def _process_until(predicate, *, timeout: float = 30.0) -> object:
    from d810.qt_shim import QtWidgets

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QtWidgets.QApplication.processEvents()
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("native GUI condition timed out")


def _live_workbench() -> object:
    from d810.ui.actions.deobfuscation_stats import DeobfuscationStats

    return _process_until(lambda: DeobfuscationStats._panel)


def _build_workspace(workbench: object) -> object:
    workbench.build_deobfuscator_button.click()
    return _process_until(lambda: workbench._build_workspace_panel)


def _stage_with_legal_palette_row(canvas: object) -> tuple[str, object]:
    from d810.ui.workbench_canvas_palette_logic import project_canvas_add_palette

    for stage in canvas._projection.maturities:
        rows = project_canvas_add_palette(
            canvas._catalog_entries,
            stage.stage_id,
            canvas._draft,
        )
        if rows:
            return stage.stage_id, rows[0]
    raise AssertionError("the native catalog exposes no legal canvas palette row")


def test_native_canvas_palette_uses_actual_popup_controls() -> None:
    import idaapi

    from d810.qt_shim import QT_BINDING, QT_GRAPHICS_AVAILABLE

    expected_binding = os.environ["D810_EXPECTED_QT_BINDING"]
    assert QT_GRAPHICS_AVAILABLE is True
    assert QT_BINDING == expected_binding
    assert idaapi.get_kernel_version().startswith(
        "9.1" if expected_binding == "PyQt5" else "9.3"
    )

    canvas = _build_workspace(_live_workbench())
    stage_id, expected = _stage_with_legal_palette_row(canvas)
    canvas._select_stage(stage_id)
    assert canvas._selected_stage_id() == stage_id

    before = len(canvas._draft.passes)
    canvas.add_registered_node_button.click()
    popup = _process_until(
        lambda: canvas._add_palette
        if canvas._add_palette is not None and canvas._add_palette.isVisible()
        else None
    )
    popup.search_edit.setText(expected.pass_id)
    _process_until(lambda: popup.results.rowCount() == 1)
    assert popup._visible_rows[0].pass_id == expected.pass_id
    popup.results.setCurrentCell(0, 0)
    popup.results.cellClicked.emit(0, 0)
    _process_until(lambda: len(canvas._draft.passes) == before + 1)

    assert canvas._draft.passes[-1].pass_id == expected.pass_id
    assert popup.isVisible() is False
