"""Opt-in native IDA coverage for the config-v2 pass catalog workflow.

The test drives the production Add Pass dialog through its public generic
catalog API.  It is intentionally skipped outside an explicitly disposable
IDA GUI session so ordinary system-test collection remains side-effect free.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
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


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _DisposableStateProxy:
    """Use a copied runtime project while retaining the live manager services."""

    def __init__(self, state: object, runtime_project: object) -> None:
        self._state = state
        self.current_runtime_project = runtime_project

    def create_config_v2_project_draft(
        self, destination: pathlib.Path
    ) -> object:
        manager = self._state.manager
        return manager.create_config_v2_project_draft(
            self.current_runtime_project,
            destination=destination,
        )

    def __getattr__(self, name: str) -> object:
        return getattr(self._state, name)


def _live_state() -> object:
    import __main__

    host = getattr(__main__, "D810", None)
    state = getattr(host, "plugin", None)
    if state is None or not state.is_loaded():
        pytest.skip("D810 state is not loaded in the native IDA session")
    return state


def _choice_control(panel: object, field_id: str) -> object:
    from d810.ui.checkable_choice_list import CheckableChoiceListWidget

    inspector = panel._current_inspector()
    assert inspector is not None
    section_id = next(
        section.section_id
        for section in inspector.field_sections
        if any(entry.field.field_id == field_id for entry in section.entries)
    )
    group = panel.field_section_widgets[section_id]
    controls = group.findChildren(CheckableChoiceListWidget)
    if controls:
        return controls[0]
    raise AssertionError(f"choice-backed control {field_id!r} was not rendered")


def _drive_add_pass_dialog(receipt: dict[str, object]) -> None:
    """Schedule interaction while the production dialog's exec loop runs."""

    from d810.qt_shim import QtCore, QtWidgets
    from d810.ui.filterable_catalog_widget import FilterableCatalogDialog

    def drive() -> None:
        dialog = next(
            (
                widget
                for widget in QtWidgets.QApplication.topLevelWidgets()
                if isinstance(widget, FilterableCatalogDialog)
            ),
            None,
        )
        if dialog is None:
            QtCore.QTimer.singleShot(10, drive)
            return
        try:
            catalog = dialog.catalog
            target_ids = ("constant-simplification", "mba-solve")
            available = {row.key for row in catalog.view().rows}
            assert set(target_ids) <= available
            catalog.set_checked(target_ids[0], True)
            catalog.set_checked(target_ids[1], True)
            receipt["checked_before_filter"] = catalog.selected_keys()

            catalog.set_query("mba")
            visible = tuple(row.key for row in catalog.view().rows)
            assert target_ids[0] not in visible
            assert set(catalog.selected_keys()) == set(target_ids)
            receipt["hidden_checked"] = catalog.selected_keys()

            catalog.set_sort(2)
            catalog.set_query("")
            receipt["selected_after_clear"] = catalog.selected_keys()
            assert set(catalog.selected_keys()) == set(target_ids)
            assert catalog.view().action_text == "Add 2 passes"
            assert catalog.view().action_enabled is True
            dialog.accept_button.click()
        except BaseException as error:  # Report through the test thread.
            receipt["error"] = error
            dialog.reject()

    QtCore.QTimer.singleShot(0, drive)


def test_config_v2_pass_catalog_picker_native_ida94(tmp_path: pathlib.Path) -> None:
    import ida_loader
    import idaapi

    from d810.core.config import ProjectConfiguration
    from d810.qt_shim import QT_BINDING, QT_GRAPHICS_AVAILABLE, QtCore
    from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter
    from d810.ui.config_v2_editing_logic import ConfigV2EditorScreen
    from d810.ui.config_v2_editing_panel import ConfigV2EditingPanel

    assert QT_GRAPHICS_AVAILABLE is True
    assert QT_BINDING in {"PySide6", "PyQt5"}
    assert idaapi.get_kernel_version().split(".", 1)[0] == "9"

    idb_path = pathlib.Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)).resolve()
    assert idb_path.suffix == ".i64"
    assert ".tmp/ida-gui" in idb_path.as_posix()
    idb_hash_before = _sha256(idb_path)

    state = _live_state()
    source_path = pathlib.Path(__file__).resolve().parents[4] / (
        "src/d810/conf/default_config_v2_canary.json"
    )
    if not source_path.is_file():
        pytest.skip("the disposable config fixture is not available")
    source_hash_before = _sha256(source_path)
    copied_config = tmp_path / source_path.name
    shutil.copy2(source_path, copied_config)
    copied_project = ProjectConfiguration.from_file(copied_config)
    adapter = ConfigV2EditingAdapter(
        _DisposableStateProxy(state, copied_project),
        destination=copied_config,
    )

    qt_messages: list[str] = []
    previous_handler = QtCore.qInstallMessageHandler(
        lambda _mode, _context, message: qt_messages.append(str(message))
    )
    panel = ConfigV2EditingPanel(
        adapter,
        screen=ConfigV2EditorScreen.BUILDER,
    )
    reopened = None
    receipt: dict[str, object] = {}
    try:
        assert panel.show() is True
        _process_until(lambda: panel.parent is not None)

        _drive_add_pass_dialog(receipt)
        panel._add_pass()
        assert "error" not in receipt, repr(receipt.get("error"))
        assert receipt["checked_before_filter"] == (
            "constant-simplification",
            "mba-solve",
        )
        assert set(receipt["hidden_checked"]) == {
            "constant-simplification",
            "mba-solve",
        }

        selected_order = tuple(receipt["selected_after_clear"])
        pipeline_ids = tuple(row.pass_id for row in panel._view.pipeline_rows)
        assert pipeline_ids[-2:] == selected_order
        assert selected_order == ("mba-solve", "constant-simplification")

        constant_entry = next(
            entry
            for entry in panel._catalog
            if entry.pass_id == "constant-simplification"
        )
        constant_row = next(
            row
            for row in panel._view.pipeline_rows
            if row.pass_id == "constant-simplification"
        )
        constant_document = json.loads(constant_row.config_json)
        assert constant_document["options"] == json.loads(
            constant_entry.option_template_json
        )
        assert set(constant_document["options"]) >= {
            "preparation",
            "stages",
        }
        assert len(constant_document["options"]["stages"]) == 3

        # Add a second identical pass through the manager-backed panel edit,
        # then activate that exact duplicate through the Builder item route.
        assert panel._apply_edit(
            lambda: adapter.add_pass(panel._draft, "mba-solve")
        )
        duplicate_indexes = [
            index
            for index, inspector in enumerate(panel._editor_view.inspectors)
            if inspector.pass_id == "mba-solve"
        ]
        assert len(duplicate_indexes) >= 2
        duplicate_index = duplicate_indexes[-1]
        panel._show_builder()
        panel._activate_pipeline_item(panel.pipeline_list.item(duplicate_index))
        assert panel._screen is ConfigV2EditorScreen.INSPECTOR
        assert panel._selected_pass_index == duplicate_index
        duplicate_inspector = panel._current_inspector()
        assert duplicate_inspector is not None
        assert duplicate_inspector.pass_id == "mba-solve"
        assert duplicate_inspector.pass_index == duplicate_index

        choice_control = _choice_control(panel, "maturities")
        declared = choice_control.choices()
        assert declared
        before = choice_control.selected_choices()
        first = choice_control.checkbox_for(declared[0])
        assert first is not None
        first.setChecked(not first.isChecked())
        _process_until(lambda: choice_control.selected_choices() != before)
        first = _choice_control(panel, "maturities").checkbox_for(declared[0])
        assert first is not None
        first.setChecked(declared[0] in before)
        _process_until(lambda: _choice_control(panel, "maturities").selected_choices() == before)

        panel._save()
        assert copied_config.is_file()
        assert tuple(row.pass_id for row in panel._view.pipeline_rows)[-3:] == (
            "mba-solve",
            "constant-simplification",
            "mba-solve",
        )

        panel.close()
        _process_until(lambda: panel._closed)
        reopened = ConfigV2EditingPanel(adapter, screen=ConfigV2EditorScreen.BUILDER)
        assert reopened.show() is True
        _process_until(lambda: reopened.parent is not None)
        reloaded_ids = tuple(row.pass_id for row in reopened._view.pipeline_rows)
        assert reloaded_ids[-3:] == (
            "mba-solve",
            "constant-simplification",
            "mba-solve",
        )
        reloaded_constant = next(
            row
            for row in reopened._view.pipeline_rows
            if row.pass_id == "constant-simplification"
        )
        assert json.loads(reloaded_constant.config_json)["options"] == json.loads(
            constant_entry.option_template_json
        )
    finally:
        if reopened is not None and not reopened._closed:
            reopened.close()
        if not panel._closed:
            panel.close()
        QtCore.qInstallMessageHandler(previous_handler)

    assert _sha256(source_path) == source_hash_before
    assert _sha256(idb_path) == idb_hash_before
    lowered_messages = [message.casefold() for message in qt_messages]
    assert not any("qstackedwidget::setcurrentwidget" in message for message in lowered_messages)
    assert not any("traceback" in message for message in lowered_messages)
    assert not any("qt" in message and "critical" in message for message in lowered_messages)
