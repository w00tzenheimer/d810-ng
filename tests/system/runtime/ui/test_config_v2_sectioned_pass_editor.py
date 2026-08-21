"""Opt-in IDA 9.4 GUI coverage for the sectioned config-v2 pass editor.

This test deliberately runs only in the native GUI process.  The system-test
Docker command still collects it (and skips it unless ``D810_NATIVE_GUI_SMOKE``
is set), while the XQuartz launcher supplies the real IDA/PySide runtime when
the disposable-IDB interaction is exercised.
"""

from __future__ import annotations

import copy
import hashlib
import os
import pathlib
import shutil
import sys
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
    """Use a copied project while retaining the live manager services."""

    def __init__(self, state: object, project: object) -> None:
        self._state = state
        self.current_project = project

    def create_config_v2_project_draft(self, destination: pathlib.Path) -> object:
        manager = self._state.manager
        return manager.create_config_v2_project_draft(
            self.current_project,
            destination=destination,
        )

    def __getattr__(self, name: str) -> object:
        return getattr(self._state, name)


def _live_state() -> object:
    import __main__

    host = getattr(__main__, "D810", None)
    state = getattr(host, "plugin", None)
    assert state is not None, "D810 plugin prerequisite is missing"
    assert state.is_loaded(), "D810 plugin prerequisite is not loaded"
    return state


def _qt_critical_message_type(QtCore: object) -> object:
    for owner in (QtCore, getattr(QtCore, "Qt", None)):
        message_type = getattr(owner, "QtMsgType", None)
        if message_type is not None and hasattr(message_type, "QtCriticalMsg"):
            return message_type.QtCriticalMsg
        if owner is not None and hasattr(owner, "QtCriticalMsg"):
            return owner.QtCriticalMsg
    raise AssertionError("Qt binding does not expose QtCriticalMsg")


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
    for control in group.findChildren(CheckableChoiceListWidget):
        if control.choices():
            return control
    raise AssertionError(f"choice-backed control {field_id!r} was not rendered")


def _field_entry(panel: object, field_id: str) -> object:
    inspector = panel._current_inspector()
    assert inspector is not None
    for section in inspector.field_sections:
        for entry in section.entries:
            if entry.field.field_id == field_id:
                return entry
    raise AssertionError(f"field {field_id!r} was not projected")


def test_config_v2_sectioned_pass_editor_native_ida94(tmp_path: pathlib.Path) -> None:
    import ida_loader
    import idaapi

    from d810.core.config import ProjectConfiguration
    from d810.qt_shim import QT_BINDING, QT_GRAPHICS_AVAILABLE, QtCore
    from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter
    from d810.ui.config_v2_editing_logic import ConfigV2EditorScreen
    from d810.ui.config_v2_editing_panel import ConfigV2EditingPanel

    assert QT_GRAPHICS_AVAILABLE is True
    assert QT_BINDING in {"PySide6", "PyQt5"}
    assert idaapi.get_kernel_version().startswith("9.4")

    idb_path = pathlib.Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)).resolve()
    assert idb_path.suffix == ".i64"
    assert ".tmp/ida-gui" in idb_path.as_posix()
    idb_hash_before = _sha256(idb_path)

    state = _live_state()
    source_path = pathlib.Path(__file__).resolve().parents[4] / (
        "src/d810/conf/default.json"
    )
    assert source_path.is_file(), "the disposable config fixture is not available"

    copied_config = tmp_path / source_path.name
    shutil.copy2(source_path, copied_config)
    source_hash_before = _sha256(source_path)
    copied_project = ProjectConfiguration.from_file(copied_config)
    adapter = ConfigV2EditingAdapter(
        _DisposableStateProxy(state, copied_project),
        destination=copied_config,
    )

    qt_messages: list[tuple[object, str]] = []
    python_exceptions: list[tuple[type[BaseException], BaseException, object]] = []
    previous_excepthook = sys.excepthook
    sys.excepthook = lambda exc_type, exc, traceback: python_exceptions.append(
        (exc_type, exc, traceback)
    )
    previous_handler = QtCore.qInstallMessageHandler(
        lambda mode, _context, message: qt_messages.append((mode, str(message)))
    )
    panel = ConfigV2EditingPanel(
        adapter,
        screen=ConfigV2EditorScreen.INSPECTOR,
    )
    reopened = None
    try:
        assert panel.show() is True
        _process_until(lambda: panel.parent is not None)

        # Add the fields-only solver twice so the builder/inspector transition
        # checks exact row identity as well as the editor's current draft.
        target_pass_id = "mba-solve"
        target_entry = next(
            entry for entry in panel._catalog if entry.pass_id == target_pass_id
        )
        assert target_entry.editor_spec.kind.value == "fields"
        for _ in range(2):
            assert panel._apply_edit(
                lambda: adapter.add_pass(panel._draft, target_pass_id)
            )

        duplicate_indexes = [
            index
            for index, inspector in enumerate(panel._editor_view.inspectors)
            if inspector.pass_id == target_pass_id
        ]
        assert len(duplicate_indexes) >= 2
        target_index = duplicate_indexes[-1]
        panel._show_inspector(target_index)
        inspector = panel._current_inspector()
        assert inspector is not None
        assert inspector.pass_index == target_index
        assert inspector.pass_id == target_pass_id

        section_titles = tuple(section.label for section in inspector.field_sections)
        assert section_titles
        assert (
            tuple(
                panel.field_section_widgets[section.section_id].title()
                for section in inspector.field_sections
            )
            == section_titles
        )

        primary_sections = tuple(
            section
            for section in inspector.field_sections
            if section.presentation.value == "primary"
        )
        assert len(primary_sections) == 1
        primary_group = panel.field_section_widgets[primary_sections[0].section_id]
        assert panel.options_scroll.widget() is primary_group
        assert panel.options_scroll.isVisible() is True
        primary_index = panel._inspector_layout.indexOf(panel.primary_workspace)
        options_index = panel._inspector_layout.indexOf(panel.options_group)
        sink_index = panel._inspector_layout.indexOf(panel.inspector_elastic_sink)
        assert panel.primary_workspace.isVisible() is False
        assert options_index >= 0
        assert primary_index >= 0
        assert sink_index >= 0
        assert panel._inspector_layout.stretch(primary_index) == 0
        assert panel._inspector_layout.stretch(options_index) == 0
        assert panel.inspector_elastic_sink.isVisible() is True
        assert panel._inspector_layout.stretch(sink_index) == 1

        controller = _field_entry(panel, "auto_install_solver")
        subordinate_before = {
            entry.field.field_id: copy.deepcopy(
                inspector.options.get(entry.field.field_id)
            )
            for section in inspector.field_sections
            for entry in section.entries
            if not entry.is_controller
        }
        panel._apply_typed_option(controller.field, True)
        panel._apply_typed_option(controller.field, False)
        panel._apply_typed_option(controller.field, True)
        inspector = panel._current_inspector()
        assert inspector is not None
        assert {
            entry.field.field_id: copy.deepcopy(
                inspector.options.get(entry.field.field_id)
            )
            for section in inspector.field_sections
            for entry in section.entries
            if not entry.is_controller
        } == subordinate_before

        choice_entry = _field_entry(panel, "maturities")
        assert choice_entry.field.choices
        choice_control = _choice_control(panel, "maturities")
        declared_order = choice_control.choices()
        assert declared_order == tuple(choice_entry.field.choices)
        first_checkbox = choice_control.checkbox_for(declared_order[0])
        assert first_checkbox is not None
        initial_checked = first_checkbox.isChecked()
        first_checkbox.setChecked(not initial_checked)
        _process_until(lambda: panel._current_inspector() is not None)
        changed_inspector = panel._current_inspector()
        assert changed_inspector is not None
        assert changed_inspector.options["maturities"] != list(choice_entry.value)
        choice_control = _choice_control(panel, "maturities")
        first_checkbox = choice_control.checkbox_for(declared_order[0])
        assert first_checkbox is not None
        first_checkbox.setChecked(initial_checked)
        _process_until(lambda: panel._current_inspector() is not None)
        choice_control = _choice_control(panel, "maturities")
        restored_inspector = panel._current_inspector()
        assert restored_inspector is not None
        assert restored_inspector.options["maturities"] == list(choice_entry.value)
        assert choice_control.choices() == declared_order
        assert choice_control.selected_choices() == tuple(choice_entry.value)

        draft_before_transition = panel._draft.document_json
        panel._show_builder()
        panel.pipeline_list.setCurrentRow(target_index)
        panel._open_selected_inspector()
        assert panel._screen is ConfigV2EditorScreen.INSPECTOR
        assert panel._selected_pass_index == target_index
        assert panel._current_inspector().pass_index == target_index
        assert panel._current_inspector().pass_id == target_pass_id
        assert panel._draft.document_json == draft_before_transition

        panel.close()
        _process_until(lambda: panel._closed)
        reopened = ConfigV2EditingPanel(
            adapter,
            screen=ConfigV2EditorScreen.INSPECTOR,
        )
        assert reopened.show() is True
        _process_until(lambda: reopened.parent is not None)
        reopened.close()
        _process_until(lambda: reopened._closed)
    finally:
        if reopened is not None and not reopened._closed:
            reopened.close()
        if not panel._closed:
            panel.close()
        QtCore.qInstallMessageHandler(previous_handler)
        sys.excepthook = previous_excepthook

    source_hash_after = _sha256(source_path)
    assert source_hash_after == source_hash_before
    assert _sha256(idb_path) == idb_hash_before
    critical = _qt_critical_message_type(QtCore)
    assert not any(mode == critical for mode, _message in qt_messages)
    assert not any(
        "QStackedWidget::setCurrentWidget" in message for _mode, message in qt_messages
    )
    assert not python_exceptions
