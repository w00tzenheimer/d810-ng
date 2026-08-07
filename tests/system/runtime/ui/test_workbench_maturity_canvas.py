"""Opt-in native GUI smoke for the maturity-canvas Build workflow.

Run this inside the XQuartz-backed IDA GUI process after opening the Workbench
on a disposable IDB.  The normal focused pytest command collects this module
but skips the destructive GUI/reload flow unless explicitly enabled.
"""

from __future__ import annotations

import json
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


def _left_button_release_event() -> object:
    """Create one binding-neutral left-button release for the dataflow view."""

    from d810.qt_shim import QtCore, QtGui

    mouse_button = getattr(QtCore.Qt, "MouseButton", QtCore.Qt)
    keyboard_modifier = getattr(QtCore.Qt, "KeyboardModifier", QtCore.Qt)
    event_type = getattr(QtCore.QEvent, "Type", QtCore.QEvent)
    left_button = getattr(mouse_button, "LeftButton")
    no_modifier = getattr(keyboard_modifier, "NoModifier")
    mouse_release = getattr(event_type, "MouseButtonRelease")
    return QtGui.QMouseEvent(
        mouse_release,
        QtCore.QPointF(4.0, 4.0),
        left_button,
        left_button,
        no_modifier,
    )


def _assert_space_pan_stops_on_left_release(canvas: object) -> None:
    """A Space + left drag must not turn later clicks into continued panning."""

    from d810.qt_shim import QtCore

    view = canvas.canvas_view
    mouse_button = getattr(QtCore.Qt, "MouseButton", QtCore.Qt)
    view._space_pan = True
    view._panning = True
    view._pan_button = getattr(mouse_button, "LeftButton")

    view.mouseReleaseEvent(_left_button_release_event())

    assert view._panning is False


def _legal_add(canvas: object) -> str:
    from d810.ui.workbench_recipe_logic import canvas_add_candidates

    for stage in canvas._projection.maturities:
        candidates = canvas_add_candidates(
            canvas._catalog_entries,
            stage.stage_id,
            canvas._draft,
        )
        if not candidates:
            continue
        pass_id = candidates[0].pass_id
        before = len(canvas._draft.passes)
        canvas.renderer.request_add_pass(stage.stage_id, pass_id)
        assert len(canvas._draft.passes) == before + 1
        return pass_id
    raise AssertionError("the native catalog exposes no legal add candidate")


def _edit_declared_option(canvas: object) -> tuple[str, dict[str, object]]:
    catalog = {entry.pass_id: entry for entry in canvas._catalog_entries}
    for item in canvas._draft.passes:
        entry = catalog[item.pass_id]
        declared = json.loads(entry.option_template_json)
        current = canvas._options(item)
        for name, value in declared.items():
            if not isinstance(value, bool):
                continue
            proposed = dict(current)
            proposed[name] = not value
            try:
                canvas._adapter.replace_options(canvas._draft, item.item_id, proposed)
            except Exception:
                continue
            before = canvas._draft.revision
            canvas.renderer.request_edit_options(item.item_id, proposed)
            assert canvas._draft.revision == before + 1
            return item.pass_id, proposed
    raise AssertionError("the native recipe exposes no editable declared option")


def _assert_saved_projection(
    canvas: object,
    added_pass_id: str,
    edited_pass_id: str,
    edited_options: dict[str, object],
) -> None:
    assert any(item.pass_id == added_pass_id for item in canvas._draft.passes)
    edited = next(
        item for item in canvas._draft.passes if item.pass_id == edited_pass_id
    )
    assert canvas._options(edited) == edited_options


def test_native_build_canvas_recipe_reload_and_linked_diagnostic() -> None:
    import __main__
    import ida_kernwin
    import idaapi

    from d810.qt_shim import QT_BINDING, QT_GRAPHICS_AVAILABLE, QtWidgets
    from d810.ui.workbench_canvas_logic import linked_case_findings

    expected_binding = os.environ["D810_EXPECTED_QT_BINDING"]
    assert QT_GRAPHICS_AVAILABLE is True
    assert QT_BINDING == expected_binding
    assert idaapi.get_kernel_version().startswith(
        "9.1" if expected_binding == "PyQt5" else "9.3"
    )

    workbench = _live_workbench()
    canvas = _build_workspace(workbench)

    before_visual_navigation = canvas._draft.revision
    canvas.canvas_view.reset_zoom()
    assert canvas.canvas_view.transform().m11() == pytest.approx(1.0)
    canvas.fit_workspace_button.click()
    assert canvas.canvas_scene.sceneRect().isValid()
    _assert_space_pan_stops_on_left_release(canvas)
    selected_item = next(
        item
        for item in canvas.canvas_scene.items()
        if isinstance(item.data(0), str) and item.data(0)
    )
    selected_item.setSelected(True)
    QtWidgets.QApplication.processEvents()
    assert canvas._selected_node_id == selected_item.data(0)
    assert canvas.node_inspector.currentWidget() is canvas.node_inspector._details_page
    assert canvas.node_inspector.contract_tree.topLevelItemCount() > 0
    assert canvas._draft.revision == before_visual_navigation

    left_width = canvas.left_rail.expanded_width
    canvas.left_rail.set_expanded(False)
    QtWidgets.QApplication.processEvents()
    assert canvas.left_rail.expanded is False
    canvas.left_rail.set_expanded(True)
    QtWidgets.QApplication.processEvents()
    assert canvas.left_rail.expanded is True
    assert canvas.left_rail.expanded_width == left_width

    stage_id = canvas._projection.maturities[0].stage_id
    canvas._select_stage(stage_id)
    assert canvas._selected_stage_id() == stage_id
    canvas.collapse_button.click()
    assert stage_id in canvas._collapsed_stages
    canvas.collapse_button.click()
    assert stage_id not in canvas._collapsed_stages

    added_pass_id = _legal_add(canvas)
    edited_pass_id, edited_options = _edit_declared_option(canvas)
    canvas.renderer.request_save_recipe()
    assert (
        canvas._adapter._state.get_workbench_function_recipe(canvas._draft.function_ea)
        is not None
    )

    previous_state = __main__.D810.plugin
    __main__.D810.reload()
    _process_until(
        lambda: __main__.D810.plugin is not previous_state
        and __main__.D810.plugin.is_loaded()
    )
    assert ida_kernwin.process_ui_action("d810ng:deobfuscation_stats", 0)
    reloaded_workbench = _live_workbench()
    reloaded_canvas = _build_workspace(reloaded_workbench)
    _assert_saved_projection(
        reloaded_canvas,
        added_pass_id,
        edited_pass_id,
        edited_options,
    )

    linked = next(
        (
            (node, findings[0])
            for node in reloaded_canvas._projection.nodes
            if (
                findings := linked_case_findings(
                    node,
                    getattr(reloaded_canvas._snapshot, "case", None),
                )
            )
        ),
        None,
    )
    assert linked is not None, "the disposable Build produced no linked case record"
    node, finding = linked
    reloaded_canvas._select_node(node.node_id)
    reloaded_canvas.open_diagnostic_button.click()
    explorer = _process_until(lambda: reloaded_workbench._diagnostics_panel)
    _process_until(lambda: explorer._pending_case_record is None)
    selected = explorer._current_record_row().record
    assert selected.anchor_ea == finding.native_ea
    assert any(
        field.name == "finding" and field.value == finding.finding_id
        for field in selected.fields
    )
