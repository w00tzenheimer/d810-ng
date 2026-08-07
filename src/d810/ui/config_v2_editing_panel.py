"""Thin dockable Qt adapter for lossless config-v2 project editing."""

from __future__ import annotations

import json
import pathlib

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.config_v2_editing_logic import (
    ConfigV2EditorScreen,
    config_v2_action_states,
    project_config_v2_document,
    project_config_v2_editor_view,
    project_serializer_rows,
)
from d810.ui.project_config_logic import ConfigV2FocusTarget
from d810.ui.workbench_structured_details_logic import DetailField, DetailSection

logger = getLogger("D810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtWidgets
    from d810.ui.workbench_structured_details import (
        JsonTreeEditor,
        RawJsonDialog,
        StructuredDetailsView,
    )

    WOPN_NOT_CLOSED_BY_ESC = getattr(
        ida_kernwin,
        "WOPN_NOT_CLOSED_BY_ESC",
        0x100,
    )

    def _user_role() -> typing.Any:
        try:
            return QtCore.Qt.ItemDataRole.UserRole
        except AttributeError:
            return QtCore.Qt.UserRole


    def _checkable_flag() -> typing.Any:
        try:
            return QtCore.Qt.ItemFlag.ItemIsUserCheckable
        except AttributeError:
            return QtCore.Qt.ItemIsUserCheckable


    def _checked_state() -> typing.Any:
        try:
            return QtCore.Qt.CheckState.Checked
        except AttributeError:
            return QtCore.Qt.Checked


    def _unchecked_state() -> typing.Any:
        try:
            return QtCore.Qt.CheckState.Unchecked
        except AttributeError:
            return QtCore.Qt.Unchecked

    class ConfigV2EditingPanel(ida_kernwin.PluginForm):
        """Render typed serializers while leaving policy in the state service."""

        TITLE = "d810-ng Config-v2 Project Editor"

        def __init__(
            self,
            adapter: typing.Any,
            *,
            on_saved: typing.Callable[[], None] | None = None,
            screen: ConfigV2EditorScreen = ConfigV2EditorScreen.BUILDER,
            focus_target: ConfigV2FocusTarget | None = None,
        ) -> None:
            ida_kernwin.PluginForm.__init__(self)
            screen = ConfigV2EditorScreen(screen)
            self._adapter = adapter
            self._on_saved = on_saved
            self._screen = screen
            self._focus_target = focus_target
            self._focus_applied = False
            self._selected_pass_index: int | None = None
            self._rendering_inspector = False
            self._manifest = tuple(adapter.manifest())
            self._catalog = tuple(adapter.catalog())
            self._catalog_by_pass_id = {
                entry.pass_id: entry for entry in self._catalog
            }
            self._draft, self._validation = adapter.reset()
            self._view = project_config_v2_document(self._draft)
            self._editor_view = project_config_v2_editor_view(
                self._draft,
                self._validation,
                self._catalog,
            )
            self._closed = False
            self.parent: typing.Any = None

            self.destination_label = QtWidgets.QLabel(str(adapter.destination))
            self.validation_label = QtWidgets.QLabel()
            self.status_detail = QtWidgets.QPlainTextEdit()
            self.status_detail.setReadOnly(True)
            self.status_detail.setMaximumHeight(90)
            self._set_status("")

            self.manifest_list = QtWidgets.QListWidget()
            self.manifest_list.setToolTip(
                "Only these fields have declared lossless structured serializers"
            )

            self.description_edit = QtWidgets.QPlainTextEdit()
            self.description_edit.setFixedHeight(64)
            try:
                wrap_mode = QtWidgets.QPlainTextEdit.LineWrapMode.WidgetWidth
                vertical_policy = QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded
                horizontal_policy = QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff
            except AttributeError:
                wrap_mode = QtWidgets.QPlainTextEdit.WidgetWidth
                vertical_policy = QtCore.Qt.ScrollBarAsNeeded
                horizontal_policy = QtCore.Qt.ScrollBarAlwaysOff
            self.description_edit.setLineWrapMode(wrap_mode)
            self.description_edit.setVerticalScrollBarPolicy(vertical_policy)
            self.description_edit.setHorizontalScrollBarPolicy(horizontal_policy)
            self.description_button = QtWidgets.QPushButton("Set description")

            self.catalog_combo = QtWidgets.QComboBox()
            for entry in sorted(self._catalog, key=lambda item: item.pass_id):
                self.catalog_combo.addItem(
                    f"{entry.display_name} ({entry.pass_id})",
                    entry.pass_id,
                )
            self.pipeline_list = QtWidgets.QListWidget()
            self.pipeline_list.setToolTip("Execution order is top to bottom")
            self.pass_buttons: dict[str, typing.Any] = {}
            for action_id, label in (
                ("add", "Add registered pass"),
                ("remove", "Remove"),
                ("up", "Move up"),
                ("down", "Move down"),
                ("options", "Edit pass options"),
            ):
                self.pass_buttons[action_id] = QtWidgets.QPushButton(label)

            self.routing_button = QtWidgets.QPushButton("Edit routing override")
            self.routing_view = QtWidgets.QPlainTextEdit()
            self.routing_view.setReadOnly(True)
            self.routing_view.setMaximumHeight(130)

            self.complete_document = QtWidgets.QPlainTextEdit()
            self.complete_document.setReadOnly(True)
            self.unsupported_document = QtWidgets.QPlainTextEdit()
            self.unsupported_document.setReadOnly(True)

            self.screen_stack = QtWidgets.QStackedWidget()
            self.builder_page = QtWidgets.QWidget()
            self.inspector_page = QtWidgets.QWidget()
            self.screen_stack.addWidget(self.builder_page)
            self.screen_stack.addWidget(self.inspector_page)

            self.inspector_details = StructuredDetailsView()
            self.contract_chip_labels = {
                name: QtWidgets.QLabel() for name in ("Scope", "Backend", "Safety")
            }
            self.transform_picker = QtWidgets.QListWidget()
            self.no_transforms_label = QtWidgets.QLabel(
                "No individually selectable transforms."
            )
            self.options_tree = JsonTreeEditor()
            self.options_tree.set_on_value_changed(self._apply_inspector_options)
            self.contract_tree = JsonTreeEditor()
            self.raw_options_button = QtWidgets.QToolButton()
            self.raw_options_button.setText("Edit raw options")
            self.raw_contract_button = QtWidgets.QToolButton()
            self.raw_contract_button.setText("View raw contract")
            self.edit_pipeline_button = QtWidgets.QPushButton("Edit pipeline...")

            self.validate_button = QtWidgets.QPushButton("Validate full pipeline")
            self.reset_button = QtWidgets.QPushButton("Reset draft")
            self.reset_button.setToolTip(
                "Restore the complete runtime source and any originating recipe seed"
            )
            self.save_as_button = QtWidgets.QPushButton("Save as another config...")
            self.save_button = QtWidgets.QPushButton("Save atomically and reload")

            self.description_button.clicked.connect(self._set_description)
            self.pass_buttons["add"].clicked.connect(self._add_pass)
            self.pass_buttons["remove"].clicked.connect(self._remove_pass)
            self.pass_buttons["up"].clicked.connect(
                lambda checked=False: self._move_pass(-1)
            )
            self.pass_buttons["down"].clicked.connect(
                lambda checked=False: self._move_pass(1)
            )
            self.pass_buttons["options"].clicked.connect(self._edit_pass_options)
            self.routing_button.clicked.connect(self._edit_routing)
            self.transform_picker.itemChanged.connect(
                self._apply_selected_transforms
            )
            self.raw_options_button.clicked.connect(self._show_raw_options)
            self.raw_contract_button.clicked.connect(self._show_raw_contract)
            self.edit_pipeline_button.clicked.connect(self._show_builder)
            self.validate_button.clicked.connect(self._validate)
            self.reset_button.clicked.connect(self._reset)
            self.save_as_button.clicked.connect(self._save_as)
            self.save_button.clicked.connect(self._save)
            self._render()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            project_identity_group = QtWidgets.QGroupBox("Project", self.parent)
            identity_layout = QtWidgets.QFormLayout(project_identity_group)
            identity_layout.setContentsMargins(4, 4, 4, 4)
            identity_layout.setSpacing(4)
            identity_layout.addRow("Destination:", self.destination_label)
            identity_layout.addRow("Validation:", self.validation_label)

            description_row = QtWidgets.QHBoxLayout()
            description_row.setSpacing(4)
            description_row.addWidget(QtWidgets.QLabel("Description:"))
            description_row.addWidget(self.description_edit)
            description_row.addWidget(self.description_button)

            pass_row = QtWidgets.QHBoxLayout()
            pass_row.setSpacing(4)
            pass_row.addWidget(self.catalog_combo, stretch=1)
            for action_id in ("add", "remove", "up", "down", "options"):
                pass_row.addWidget(self.pass_buttons[action_id])

            typed_splitter = QtWidgets.QSplitter()
            try:
                typed_splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                typed_splitter.setOrientation(QtCore.Qt.Horizontal)
            typed_splitter.addWidget(self.manifest_list)
            typed_splitter.addWidget(self.pipeline_list)
            typed_splitter.addWidget(self.routing_view)
            self.manifest_list.setMinimumWidth(180)
            self.pipeline_list.setMinimumWidth(280)
            self.routing_view.setMinimumWidth(280)
            typed_splitter.setStretchFactor(0, 1)
            typed_splitter.setStretchFactor(1, 2)
            typed_splitter.setStretchFactor(2, 2)
            typed_splitter.setSizes([200, 400, 400])

            raw_tabs = QtWidgets.QTabWidget()
            raw_tabs.addTab(self.unsupported_document, "Unsupported fields (read-only)")
            raw_tabs.addTab(self.complete_document, "Complete document (read-only)")

            editing_group = QtWidgets.QGroupBox("Structured fields", self.parent)
            editing_layout = QtWidgets.QVBoxLayout(editing_group)
            editing_layout.setContentsMargins(4, 4, 4, 4)
            editing_layout.setSpacing(4)
            editing_layout.addLayout(description_row)
            editing_layout.addLayout(pass_row)
            editing_layout.addWidget(typed_splitter, stretch=1)

            raw_group = QtWidgets.QGroupBox("Preserved document", self.parent)
            raw_layout = QtWidgets.QVBoxLayout(raw_group)
            raw_layout.setContentsMargins(4, 4, 4, 4)
            raw_layout.setSpacing(4)
            raw_layout.addWidget(raw_tabs)

            outer_splitter = QtWidgets.QSplitter()
            try:
                outer_splitter.setOrientation(QtCore.Qt.Orientation.Vertical)
            except AttributeError:
                outer_splitter.setOrientation(QtCore.Qt.Vertical)
            outer_splitter.addWidget(editing_group)
            outer_splitter.addWidget(raw_group)
            outer_splitter.setStretchFactor(0, 1)
            outer_splitter.setStretchFactor(1, 1)
            outer_splitter.setSizes([450, 550])

            builder_layout = QtWidgets.QVBoxLayout(self.builder_page)
            builder_layout.setContentsMargins(0, 0, 0, 0)
            builder_layout.setSpacing(4)
            builder_layout.addWidget(outer_splitter, stretch=1)

            inspector_layout = QtWidgets.QVBoxLayout(self.inspector_page)
            inspector_layout.setContentsMargins(4, 4, 4, 4)
            inspector_layout.setSpacing(6)

            inspector_identity_group = QtWidgets.QGroupBox("Pass inspector")
            inspector_identity_layout = QtWidgets.QFormLayout(
                inspector_identity_group
            )
            inspector_identity_layout.setContentsMargins(4, 4, 4, 4)
            inspector_identity_layout.setSpacing(4)
            inspector_identity_layout.addRow(self.inspector_details)
            inspector_layout.addWidget(inspector_identity_group)

            chip_row = QtWidgets.QHBoxLayout()
            chip_row.setSpacing(4)
            for name in ("Scope", "Backend", "Safety"):
                chip_row.addWidget(self.contract_chip_labels[name])
            chip_row.addStretch(1)
            inspector_layout.addLayout(chip_row)

            transforms_group = QtWidgets.QGroupBox("Transforms")
            transforms_layout = QtWidgets.QVBoxLayout(transforms_group)
            transforms_layout.setContentsMargins(4, 4, 4, 4)
            transforms_layout.setSpacing(4)
            transforms_layout.addWidget(self.transform_picker)
            transforms_layout.addWidget(self.no_transforms_label)
            inspector_layout.addWidget(transforms_group, stretch=1)

            options_group = QtWidgets.QGroupBox("Options")
            options_layout = QtWidgets.QVBoxLayout(options_group)
            options_layout.setContentsMargins(4, 4, 4, 4)
            options_layout.setSpacing(4)
            options_layout.addWidget(self.options_tree)
            options_controls = QtWidgets.QHBoxLayout()
            options_controls.addStretch(1)
            options_controls.addWidget(self.raw_options_button)
            options_layout.addLayout(options_controls)
            inspector_layout.addWidget(options_group, stretch=1)

            contract_group = QtWidgets.QGroupBox("Pass contract (read-only)")
            contract_layout = QtWidgets.QVBoxLayout(contract_group)
            contract_layout.setContentsMargins(4, 4, 4, 4)
            contract_layout.setSpacing(4)
            contract_layout.addWidget(self.contract_tree)
            contract_controls = QtWidgets.QHBoxLayout()
            contract_controls.addStretch(1)
            contract_controls.addWidget(self.raw_contract_button)
            contract_layout.addLayout(contract_controls)
            inspector_layout.addWidget(contract_group, stretch=1)
            inspector_layout.addWidget(self.edit_pipeline_button)

            action_row = QtWidgets.QHBoxLayout()
            action_row.addWidget(self.routing_button)
            action_row.addWidget(self.reset_button)
            action_row.addStretch(1)
            action_row.addWidget(self.validate_button)
            action_row.addWidget(self.save_as_button)
            action_row.addWidget(self.save_button)

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(6)
            layout.addWidget(project_identity_group)
            layout.addWidget(self.screen_stack, stretch=1)
            layout.addWidget(self.status_detail)
            layout.addLayout(action_row)
            self._render()

        def OnClose(self, form: typing.Any) -> None:
            del form
            self._closed = True
            self.parent = None

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            if self.GetWidget() is not None:
                self.Close(ida_kernwin.PluginForm.WCLS_SAVE)

        def show(self) -> bool:
            shown = ida_kernwin.PluginForm.Show(
                self,
                self.TITLE,
                options=ida_kernwin.PluginForm.WOPN_PERSIST,
            )
            if shown:
                ida_kernwin.display_widget(
                    self.GetWidget(),
                    WOPN_NOT_CLOSED_BY_ESC,
                    None,
                )
                ida_kernwin.set_dock_pos(
                    self.TITLE,
                    "D-810 Configuration",
                    ida_kernwin.DP_RIGHT,
                )
                self._render()
            return shown

        def _render(self) -> None:
            self._view = project_config_v2_document(self._draft)
            self._editor_view = project_config_v2_editor_view(
                self._draft,
                self._validation,
                self._catalog,
            )
            self.destination_label.setText(str(self._adapter.destination))
            serializer_rows = project_serializer_rows(self._manifest)
            actions = {
                item.action_id: item
                for item in config_v2_action_states(self._draft, self._validation)
            }

            self.manifest_list.clear()
            for row in serializer_rows:
                item = QtWidgets.QListWidgetItem(
                    f"{row.label}\n{row.value_kind}: {row.path}"
                )
                item.setToolTip(
                    "Declared structured serializer; all other fields are read-only"
                )
                self.manifest_list.addItem(item)

            selected = self._selected_pass_index
            if selected is None and self._screen is ConfigV2EditorScreen.BUILDER:
                selected = self.pipeline_list.currentRow()
            self.pipeline_list.clear()
            for row in self._view.pipeline_rows:
                item = QtWidgets.QListWidgetItem(f"{row.index + 1}. {row.pass_id}")
                item.setToolTip(row.config_json)
                self.pipeline_list.addItem(item)
            self._apply_focus_target()

            if self._editor_view.inspectors:
                if self._selected_pass_index is None and self._screen is ConfigV2EditorScreen.BUILDER:
                    self._selected_pass_index = min(
                        max(selected if selected is not None else 0, 0),
                        len(self._editor_view.inspectors) - 1,
                    )
                elif (
                    self._selected_pass_index is not None
                    and self._selected_pass_index >= len(self._editor_view.inspectors)
                ):
                    self._selected_pass_index = len(self._editor_view.inspectors) - 1
            else:
                self._selected_pass_index = None
            if self._selected_pass_index is not None:
                self.pipeline_list.setCurrentRow(self._selected_pass_index)

            if not self.description_edit.hasFocus():
                self.description_edit.setPlainText(self._view.description)
            self.routing_view.setPlainText(self._view.routing_json)
            self.unsupported_document.setPlainText(self._view.unsupported_document_json)
            self.complete_document.setPlainText(self._view.complete_document_json)

            if self._validation.valid:
                self.validation_label.setText(
                    f"Full config-v2 validation: ready; {len(self._validation.pass_ids)} pass(es)"
                )
            else:
                self.validation_label.setText(
                    f"Full config-v2 validation: blocked; {len(self._validation.diagnostics)} diagnostic(s)"
                )
            save = actions["save_project"]
            self.save_button.setEnabled(save.enabled)
            self.save_button.setToolTip(save.reason)
            self._render_inspector()
            self.screen_stack.setCurrentWidget(
                self.inspector_page
                if self._screen is ConfigV2EditorScreen.INSPECTOR
                else self.builder_page
            )

        def _apply_focus_target(self) -> None:
            """Select one requested pass, or report why focus was not possible."""

            if self._focus_applied or self._focus_target is None:
                return
            target = self._focus_target
            if (
                not target.unambiguous
                or target.pass_id is None
                or target.pass_index is None
            ):
                self._set_status(target.message)
                self._focus_applied = True
                return
            if 0 <= target.pass_index < len(self._editor_view.inspectors):
                inspector = self._editor_view.inspectors[target.pass_index]
            else:
                inspector = None
            if (
                inspector is not None
                and inspector.pass_index == target.pass_index
                and inspector.pass_id == target.pass_id
            ):
                self._selected_pass_index = target.pass_index
                self._set_status(target.message)
            else:
                self._set_status(
                    f"{target.message} The exact pass row does not match this draft."
                )
            self._focus_applied = True

        def _builder_selected_pass_index(self) -> int | None:
            index = self.pipeline_list.currentRow()
            if not 0 <= index < len(self._view.pipeline_rows):
                return None
            self._selected_pass_index = index
            return index

        def _current_inspector(self) -> typing.Any | None:
            index = self._selected_pass_index
            if index is None or not 0 <= index < len(self._editor_view.inspectors):
                return None
            inspector = self._editor_view.inspectors[index]
            if inspector.pass_index != index:
                return None
            return inspector

        def _render_inspector(self) -> None:
            inspector = self._current_inspector()
            self._rendering_inspector = True
            try:
                self.transform_picker.clear()
                if inspector is None:
                    self.inspector_details.set_sections(
                        (
                            DetailSection(
                                "selection",
                                "Pass",
                                (DetailField("Pass", "No pass selected"),),
                            ),
                        )
                    )
                    for label in self.contract_chip_labels.values():
                        label.setText("")
                    self.transform_picker.setVisible(False)
                    self.no_transforms_label.setVisible(True)
                    self.options_tree.set_json({}, editable=False)
                    self.contract_tree.set_json({}, editable=False)
                    self.raw_options_button.setEnabled(False)
                    self.raw_contract_button.setEnabled(False)
                    return

                self.inspector_details.set_sections(
                    (
                        DetailSection(
                            "identity",
                            "Pass",
                            (
                                DetailField(
                                    "Pass",
                                    f"{inspector.display_name} ({inspector.pass_id})",
                                ),
                                DetailField("Purpose", inspector.purpose),
                                DetailField("Runs during", inspector.runs_during),
                            ),
                        ),
                    )
                )
                for name, value in inspector.contract_chips:
                    self.contract_chip_labels[name].setText(f"{name}: {value}")

                self.transform_picker.setVisible(inspector.transforms_editable)
                self.no_transforms_label.setVisible(not inspector.transforms_editable)
                if inspector.transforms_editable:
                    for row in inspector.selected_transforms:
                        item = QtWidgets.QListWidgetItem(row.transform_id)
                        item.setFlags(item.flags() | _checkable_flag())
                        item.setData(_user_role(), row.transform_id)
                        item.setCheckState(
                            _checked_state() if row.selected else _unchecked_state()
                        )
                        self.transform_picker.addItem(item)
                else:
                    self.no_transforms_label.setText(
                        "No individually selectable transforms."
                    )

                self.options_tree.set_json(inspector.options, editable=True)
                self.contract_tree.set_json(inspector.contract, editable=False)
                self.raw_options_button.setEnabled(True)
                self.raw_contract_button.setEnabled(True)
            finally:
                self._rendering_inspector = False

        def _show_inspector(self, pass_index: int) -> None:
            index = int(pass_index)
            if not 0 <= index < len(self._editor_view.inspectors):
                self._set_status(f"Pass row {index} is not present in this draft.")
                return
            inspector = self._editor_view.inspectors[index]
            if inspector.pass_index != index:
                self._set_status(f"Pass row {index} does not match this draft.")
                return
            self._selected_pass_index = index
            self._screen = ConfigV2EditorScreen.INSPECTOR
            self._render()

        def _show_builder(self, checked: bool = False) -> None:
            del checked
            self._screen = ConfigV2EditorScreen.BUILDER
            self._render()

        def _set_status(self, message: str) -> None:
            self.status_detail.setPlainText(message)
            self.status_detail.setVisible(bool(message))

        def _apply_edit(
            self,
            operation: typing.Callable[[], tuple[typing.Any, typing.Any]],
        ) -> bool:
            try:
                self._draft, self._validation = operation()
            except Exception as exc:
                logger.warning("Config-v2 edit failed: %s", exc)
                self._render()
                self._set_status(f"Edit failed: {exc}")
                return False
            self._set_status("")
            self._render()
            return True

        def _apply_selected_transforms(
            self,
            changed_item: typing.Any = None,
        ) -> None:
            del changed_item
            if self._rendering_inspector:
                return
            inspector = self._current_inspector()
            if inspector is None or not inspector.transforms_editable:
                self._render()
                return
            checked_ids = {
                str(self.transform_picker.item(index).data(_user_role()))
                for index in range(self.transform_picker.count())
                if self.transform_picker.item(index).checkState() == _checked_state()
            }
            transform_ids = tuple(
                row.transform_id
                for row in inspector.selected_transforms
                if row.transform_id in checked_ids
            )
            self._apply_edit(
                lambda: self._adapter.set_pass_transforms(
                    self._draft,
                    pass_index=inspector.pass_index,
                    transform_ids=transform_ids,
                )
            )

        def _apply_inspector_options(self, value: object) -> None:
            inspector = self._current_inspector()
            if inspector is None or not isinstance(value, dict):
                self._render()
                self._set_status("Pass options must be a JSON object.")
                return
            self._apply_edit(
                lambda: self._adapter.set_pass_options(
                    self._draft,
                    pass_index=inspector.pass_index,
                    options=value,
                )
            )

        def _show_raw_options(self, checked: bool = False) -> None:
            del checked
            inspector = self._current_inspector()
            if inspector is None:
                return
            dialog = RawJsonDialog(
                f"Edit raw options for {inspector.pass_id}",
                inspector.options,
                editable=True,
                on_apply=self._apply_inspector_options,
                parent=self.parent,
            )
            dialog.exec_()

        def _show_raw_contract(self, checked: bool = False) -> None:
            del checked
            inspector = self._current_inspector()
            if inspector is None:
                return
            dialog = RawJsonDialog(
                f"View raw contract for {inspector.pass_id}",
                inspector.contract,
                editable=False,
                parent=self.parent,
            )
            dialog.exec_()

        def _set_description(self, checked: bool = False) -> None:
            del checked
            value = self.description_edit.toPlainText()
            self._apply_edit(lambda: self._adapter.set_description(self._draft, value))

        def _add_pass(self, checked: bool = False) -> None:
            del checked
            pass_id = self.catalog_combo.currentData()
            if not pass_id:
                return
            selected = self._builder_selected_pass_index()
            insertion = None if selected is None else selected + 1
            self._apply_edit(
                lambda: self._adapter.add_pass(
                    self._draft,
                    str(pass_id),
                    index=insertion,
                )
            )

        def _remove_pass(self, checked: bool = False) -> None:
            del checked
            index = self._builder_selected_pass_index()
            if index is not None:
                self._apply_edit(lambda: self._adapter.remove_pass(self._draft, index))

        def _move_pass(self, delta: int) -> None:
            index = self._builder_selected_pass_index()
            if index is None:
                return
            target = index + int(delta)
            if 0 <= target < len(self._view.pipeline_rows):
                self._apply_edit(
                    lambda: self._adapter.reorder_pass(
                        self._draft,
                        index,
                        target,
                    )
                )
                self.pipeline_list.setCurrentRow(target)

        def _edit_pass_options(self, checked: bool = False) -> None:
            del checked
            index = self._builder_selected_pass_index()
            if index is None:
                return
            row = self._view.pipeline_rows[index]
            payload = json.loads(row.options_json)
            text, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                f"Options for {row.pass_id}",
                "Typed pass options JSON object:",
                json.dumps(payload, indent=2, sort_keys=True),
            )
            if not accepted:
                return
            try:
                value = json.loads(str(text))
                if not isinstance(value, dict):
                    raise ValueError("pass options must be an object")
            except (json.JSONDecodeError, ValueError) as exc:
                self._set_status(f"Invalid pass options: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.set_pass_options(
                    self._draft,
                    pass_index=index,
                    options=value,
                )
            )

        def _edit_routing(self, checked: bool = False) -> None:
            del checked
            current = json.loads(self._view.routing_json)
            if not current:
                current = {"prefer": {}, "require": None, "deny": []}
            text, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                "Profile routing override",
                "Typed JSON object with prefer, require, and deny:",
                json.dumps(current, indent=2, sort_keys=True),
            )
            if not accepted:
                return
            try:
                value = json.loads(str(text))
                if not isinstance(value, dict) or set(value) != {
                    "prefer",
                    "require",
                    "deny",
                }:
                    raise ValueError(
                        "routing must contain exactly prefer, require, and deny"
                    )
                prefer = value["prefer"]
                require = value["require"]
                deny = value["deny"]
                if (
                    not isinstance(prefer, dict)
                    or (require is not None and not isinstance(require, str))
                    or not isinstance(deny, list)
                    or not all(isinstance(item, str) for item in deny)
                ):
                    raise ValueError(
                        "prefer must be an object, require a string/null, and deny a string list"
                    )
            except (json.JSONDecodeError, ValueError) as exc:
                self._set_status(f"Invalid routing override: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.set_routing_override(
                    self._draft,
                    prefer=prefer,
                    require=require,
                    deny=deny,
                )
            )

        def _reset(self, checked: bool = False) -> None:
            del checked
            if self._apply_edit(lambda: self._adapter.reset()):
                self._set_status(
                    "Draft reset to its complete runtime source and recipe seed."
                )

        def _validate(self, checked: bool = False) -> None:
            del checked
            try:
                self._validation = self._adapter.validate(self._draft)
            except Exception as exc:
                self._set_status(f"Validation failed: {exc}")
                return
            if self._validation.valid:
                self._set_status("Full pipeline validation passed.")
            else:
                self._set_status(
                    "\n".join(item.message for item in self._validation.diagnostics)
                )
            self._render()

        def _save_as(self, checked: bool = False) -> None:
            del checked
            destination, _ = QtWidgets.QFileDialog.getSaveFileName(
                self.parent,
                "Save config-v2 project as",
                str(self._adapter.destination),
                "D810 project configurations (*.json)",
            )
            if not destination:
                return
            try:
                self._draft, self._validation = self._adapter.retarget(
                    self._draft,
                    pathlib.Path(destination),
                )
            except Exception as exc:
                logger.warning("Config-v2 Save As failed: %s", exc)
                self._set_status(f"Save As failed: {exc}")
                return
            self._set_status(
                f"Draft destination changed to {self._adapter.destination}."
            )
            self._render()

        def _save(self, checked: bool = False) -> None:
            del checked
            try:
                saved = self._adapter.save(self._draft, self._validation)
            except Exception as exc:
                logger.warning("Config-v2 save failed: %s", exc)
                self._set_status(f"Save failed: {exc}")
                return
            if self._on_saved is not None:
                try:
                    self._on_saved()
                except Exception as exc:
                    logger.warning("Config-v2 saved-view refresh failed: %s", exc)
            path = getattr(saved, "path", self._adapter.destination)
            try:
                self._draft, self._validation = self._adapter.reset()
            except Exception as exc:
                logger.warning("Config-v2 post-save editor refresh failed: %s", exc)
                self._set_status(
                    f"Saved atomically and reloaded: {path}. "
                    f"Reopen the editor to refresh this draft: {exc}"
                )
                return
            self._set_status(f"Saved atomically, validated, and reloaded: {path}")
            self._render()

else:

    class ConfigV2EditingPanel:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ConfigV2EditingPanel requires IDA Pro")


__all__ = ["ConfigV2EditingPanel", "IDA_AVAILABLE"]
