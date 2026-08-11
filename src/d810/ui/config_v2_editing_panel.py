"""Thin dockable Qt adapter for lossless config-v2 project editing."""

from __future__ import annotations

import copy
import pathlib

from d810.core import typing
from d810.core.pass_editor_spec import FieldControlKind, FieldEditorSpec
from d810.core.logging import getLogger
from d810.families.registry import registered_families
from d810.ui.config_v2_editing_logic import (
    ConfigV2EditorScreen,
    ConfigV2InspectorPrimarySection,
    apply_rule_catalog_selection,
    apply_rule_catalog_selection_to_options,
    apply_typed_field_option,
    apply_transform_catalog_selection,
    project_rule_catalog,
    project_transform_catalog,
    project_config_v2_document,
    project_config_v2_editor_view,
    project_serializer_rows,
    typed_field_option_value,
    transform_option_fields,
)
from d810.ui.project_config_logic import ConfigV2FocusTarget

logger = getLogger("d810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtWidgets, qt_flag_or
    from d810.ui.qt_layout_policy import (
        configure_left_aligned_form,
        configure_overflow_menu_button,
    )
    from d810.ui.workbench_structured_details import JsonTreeEditor, RawJsonDialog
    from d810.ui.config_v2_transform_catalog import ConfigV2TransformCatalogWidget
    from d810.ui.config_v2_rule_catalog import ConfigV2RuleCatalogWidget

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
            self._rendering_routing = False
            self._manifest = tuple(adapter.manifest())
            self._catalog = tuple(adapter.catalog())
            self._catalog_by_pass_id = {entry.pass_id: entry for entry in self._catalog}
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
            self.destination_label.setToolTip(str(adapter.destination))
            self.validation_label = QtWidgets.QLabel()
            self.error_label = QtWidgets.QLabel()
            self.error_label.setWordWrap(True)
            self.error_label.setMaximumHeight(44)
            self._set_status("")

            self.description_label = QtWidgets.QLabel()
            self.description_label.setWordWrap(True)
            self.edit_description_button = QtWidgets.QPushButton("Edit description...")
            self.pipeline_list = QtWidgets.QListWidget()
            self.pipeline_list.setToolTip("Execution order is top to bottom")
            self.pass_buttons: dict[str, typing.Any] = {}
            for action_id, label in (
                ("add", "Add pass..."),
                ("remove", "Remove"),
                ("up", "Move up"),
                ("down", "Move down"),
                ("inspector", "Open in editor..."),
            ):
                self.pass_buttons[action_id] = QtWidgets.QPushButton(label)

            self.screen_stack = QtWidgets.QStackedWidget()
            self.builder_page = QtWidgets.QWidget()
            self.inspector_page = QtWidgets.QWidget()
            self.screen_stack.addWidget(self.builder_page)
            self.screen_stack.addWidget(self.inspector_page)

            self.pass_title_label = QtWidgets.QLabel()
            self.pass_title_label.setWordWrap(False)
            self.pass_purpose_label = QtWidgets.QLabel()
            self.pass_purpose_label.setWordWrap(True)
            self.inspector_actions = QtWidgets.QWidget()
            self.details_body = QtWidgets.QWidget()
            self.summary_message_label = QtWidgets.QLabel()
            self.summary_message_label.setWordWrap(True)
            self.primary_workspace = QtWidgets.QStackedWidget()
            self.transforms_group = QtWidgets.QGroupBox("Transforms")
            self.rules_group = QtWidgets.QGroupBox("Rules")
            self.options_group = QtWidgets.QGroupBox("Options")
            self.inspector_elastic_sink = QtWidgets.QWidget()
            self._inspector_layout: typing.Any | None = None
            self._contract_metadata_tooltip = (
                "Read-only registered pass contract metadata; it cannot be changed "
                "in a project."
            )
            self.contract_chip_labels = {}
            for name in ("Scope", "Backend", "Safety"):
                label = QtWidgets.QLabel()
                label.setToolTip(self._contract_metadata_tooltip)
                self.contract_chip_labels[name] = label
            self._transform_catalog_query = ""
            self.transform_catalog_widget = ConfigV2TransformCatalogWidget(
                on_query_changed=self._transform_catalog_query_changed,
                on_selection_changed=self._apply_transform_catalog_selection,
            )
            self._rule_catalog_query = ""
            self.rule_catalog_widget = ConfigV2RuleCatalogWidget(
                on_query_changed=self._rule_catalog_query_changed,
                on_selection_changed=self._apply_rule_catalog_selection,
            )
            self.typed_options_body = QtWidgets.QWidget()
            self.typed_options_layout = QtWidgets.QFormLayout(self.typed_options_body)
            self.typed_options_layout.setContentsMargins(0, 0, 0, 0)
            self.typed_options_layout.setSpacing(4)
            configure_left_aligned_form(self.typed_options_layout)
            self.raw_contract_button = QtWidgets.QToolButton()
            self.raw_contract_button.setText("View contract...")
            self.pipeline_button = QtWidgets.QToolButton()
            self.pipeline_button.setText("Pipeline")
            self.details_toggle = QtWidgets.QToolButton()
            self.details_toggle.setText("Details")
            self.details_toggle.setCheckable(True)
            self.details_toggle.setChecked(False)

            self.edit_description_button.clicked.connect(self._edit_description)
            self.pass_buttons["add"].clicked.connect(self._add_pass)
            self.pass_buttons["remove"].clicked.connect(self._remove_pass)
            self.pass_buttons["up"].clicked.connect(
                lambda checked=False: self._move_pass(-1)
            )
            self.pass_buttons["down"].clicked.connect(
                lambda checked=False: self._move_pass(1)
            )
            self.pass_buttons["inspector"].clicked.connect(
                self._open_selected_inspector
            )
            self.raw_contract_button.clicked.connect(self._show_raw_contract)
            self.pipeline_button.clicked.connect(self._show_builder)
            self.details_toggle.toggled.connect(self._set_details_expanded)
            self._render()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            project_header = QtWidgets.QWidget(self.parent)
            identity_layout = QtWidgets.QHBoxLayout(project_header)
            identity_layout.setContentsMargins(4, 2, 4, 2)
            identity_layout.setSpacing(8)
            identity_layout.addWidget(self.destination_label, stretch=1)
            identity_layout.addWidget(self.validation_label)

            description_row = QtWidgets.QHBoxLayout()
            description_row.setSpacing(4)
            description_row.addWidget(QtWidgets.QLabel("Description:"))
            description_row.addWidget(self.description_label, stretch=1)
            description_row.addWidget(self.edit_description_button)

            pass_row = QtWidgets.QHBoxLayout()
            pass_row.setSpacing(4)
            for action_id in ("add", "remove", "up", "down", "inspector"):
                pass_row.addWidget(self.pass_buttons[action_id])

            editing_group = QtWidgets.QGroupBox("Active ordered passes", self.parent)
            editing_layout = QtWidgets.QVBoxLayout(editing_group)
            editing_layout.setContentsMargins(4, 4, 4, 4)
            editing_layout.setSpacing(4)
            editing_layout.addLayout(description_row)
            editing_layout.addWidget(self.pipeline_list, stretch=1)
            editing_layout.addLayout(pass_row)

            self._build_routing_controls()

            builder_layout = QtWidgets.QVBoxLayout(self.builder_page)
            builder_layout.setContentsMargins(0, 0, 0, 0)
            builder_layout.setSpacing(4)
            builder_layout.addWidget(editing_group, stretch=1)
            builder_layout.addWidget(self.routing_group)

            inspector_layout = QtWidgets.QVBoxLayout(self.inspector_page)
            inspector_layout.setContentsMargins(4, 4, 4, 4)
            inspector_layout.setSpacing(4)
            self._inspector_layout = inspector_layout

            inspector_header = QtWidgets.QWidget(self.inspector_page)
            inspector_header_layout = QtWidgets.QVBoxLayout(inspector_header)
            inspector_header_layout.setContentsMargins(0, 0, 0, 0)
            inspector_header_layout.setSpacing(4)
            inspector_header_layout.addWidget(self.pass_title_label)
            inspector_header_layout.addWidget(self.pass_purpose_label)

            inspector_action_layout = QtWidgets.QHBoxLayout(self.inspector_actions)
            inspector_action_layout.setContentsMargins(0, 0, 0, 0)
            inspector_action_layout.setSpacing(4)
            inspector_action_layout.addWidget(self.pipeline_button)
            inspector_action_layout.addWidget(self.details_toggle)
            inspector_action_layout.addWidget(self.raw_contract_button)
            inspector_action_layout.addStretch(1)
            inspector_header_layout.addWidget(self.inspector_actions)
            inspector_layout.addWidget(inspector_header)

            details_layout = QtWidgets.QFormLayout(self.details_body)
            details_layout.setContentsMargins(0, 0, 0, 0)
            details_layout.setSpacing(4)
            configure_left_aligned_form(details_layout)
            for name in ("Scope", "Backend", "Safety"):
                metadata_label = QtWidgets.QLabel(name)
                metadata_label.setToolTip(self._contract_metadata_tooltip)
                details_layout.addRow(metadata_label, self.contract_chip_labels[name])
            inspector_layout.addWidget(self.details_body)
            self._set_details_expanded(self.details_toggle.isChecked())
            inspector_layout.addWidget(self.summary_message_label)

            transforms_layout = QtWidgets.QVBoxLayout(self.transforms_group)
            transforms_layout.setContentsMargins(4, 4, 4, 4)
            transforms_layout.setSpacing(4)
            transforms_layout.addWidget(self.transform_catalog_widget)

            rules_layout = QtWidgets.QVBoxLayout(self.rules_group)
            rules_layout.setContentsMargins(4, 4, 4, 4)
            rules_layout.setSpacing(4)
            rules_layout.addWidget(self.rule_catalog_widget)
            self.primary_workspace.addWidget(self.transforms_group)
            self.primary_workspace.addWidget(self.rules_group)
            inspector_layout.addWidget(self.primary_workspace, stretch=1)

            options_layout = QtWidgets.QVBoxLayout(self.options_group)
            options_layout.setContentsMargins(4, 4, 4, 4)
            options_layout.setSpacing(4)
            options_layout.addWidget(self.typed_options_body)
            inspector_layout.addWidget(self.options_group, stretch=0)
            inspector_layout.addWidget(self.inspector_elastic_sink, stretch=0)

            footer = self._build_footer()

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(4)
            layout.addWidget(project_header)
            layout.addWidget(self.screen_stack, stretch=1)
            layout.addWidget(self.error_label)
            layout.addLayout(footer)
            self._render()

        def _build_routing_controls(self) -> None:
            self.routing_group = QtWidgets.QGroupBox("Auto routing", self.parent)
            self.routing_group.setCheckable(True)
            self.routing_group.setChecked(False)
            routing_layout = QtWidgets.QVBoxLayout(self.routing_group)
            routing_layout.setContentsMargins(6, 6, 6, 6)
            routing_layout.setSpacing(4)
            self.routing_body = QtWidgets.QWidget(self.routing_group)
            routing_layout.addWidget(self.routing_body)
            body_layout = QtWidgets.QVBoxLayout(self.routing_body)
            body_layout.setContentsMargins(0, 0, 0, 0)
            body_layout.setSpacing(4)

            self.routing_auto_check = QtWidgets.QCheckBox("Auto")
            body_layout.addWidget(self.routing_auto_check)

            require_row = QtWidgets.QHBoxLayout()
            require_row.addWidget(QtWidgets.QLabel("Require"))
            self.routing_require_combo = QtWidgets.QComboBox()
            self.routing_require_combo.addItem("Automatic", None)
            require_row.addWidget(self.routing_require_combo, stretch=1)
            body_layout.addLayout(require_row)

            self.routing_family_names = tuple(
                str(family.name) for family in registered_families()
            )
            for family_name in self.routing_family_names:
                self.routing_require_combo.addItem(family_name, family_name)

            body_layout.addWidget(QtWidgets.QLabel("Prefer"))
            self.routing_prefer_table = QtWidgets.QTableWidget(
                len(self.routing_family_names), 2
            )
            self.routing_prefer_table.setHorizontalHeaderLabels(["Family", "Bias"])
            self.routing_prefer_rows: dict[str, tuple[typing.Any, typing.Any]] = {}
            for row_index, family_name in enumerate(self.routing_family_names):
                family_item = QtWidgets.QTableWidgetItem(family_name)
                family_item.setFlags(
                    qt_flag_or(family_item.flags(), _checkable_flag())
                )
                family_item.setCheckState(_unchecked_state())
                bias = QtWidgets.QDoubleSpinBox()
                bias.setRange(-1000000.0, 1000000.0)
                bias.setDecimals(3)
                bias.setValue(0.0)
                self.routing_prefer_table.setItem(row_index, 0, family_item)
                self.routing_prefer_table.setCellWidget(row_index, 1, bias)
                self.routing_prefer_rows[family_name] = (family_item, bias)
            body_layout.addWidget(self.routing_prefer_table)

            body_layout.addWidget(QtWidgets.QLabel("Exclude"))
            self.routing_exclude_list = QtWidgets.QListWidget()
            for family_name in self.routing_family_names:
                item = QtWidgets.QListWidgetItem(family_name)
                item.setFlags(qt_flag_or(item.flags(), _checkable_flag()))
                item.setData(_user_role(), family_name)
                item.setCheckState(_unchecked_state())
                self.routing_exclude_list.addItem(item)
            body_layout.addWidget(self.routing_exclude_list)

            self.apply_routing_button = QtWidgets.QPushButton("Apply routing")
            self.apply_routing_button.clicked.connect(self._apply_routing_rows)
            body_layout.addWidget(self.apply_routing_button)
            self.routing_auto_check.toggled.connect(self._routing_auto_changed)
            self.routing_group.toggled.connect(self._set_routing_expanded)
            self._set_routing_expanded(self.routing_group.isChecked())

        def _build_footer(self) -> typing.Any:
            self.footer_dirty_label = QtWidgets.QLabel()
            self.footer_validation_label = QtWidgets.QLabel()
            self.footer_overflow_button = QtWidgets.QToolButton()
            configure_overflow_menu_button(self.footer_overflow_button)
            self.footer_overflow_button.setText("...")
            self.footer_overflow_menu = QtWidgets.QMenu(self.footer_overflow_button)
            self.footer_overflow_menu.addAction("Validate", self._validate)
            self.footer_overflow_menu.addAction(
                "Discard unsaved", self._discard_unsaved
            )
            self.footer_overflow_menu.addAction("Save as new...", self._save_as)
            self.footer_overflow_menu.addAction("View raw", self._show_raw_document)
            self.footer_overflow_menu.addAction(
                "Developer help", self._show_developer_help
            )
            self.footer_overflow_button.setMenu(self.footer_overflow_menu)
            try:
                self.footer_overflow_button.setPopupMode(
                    QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup
                )
            except AttributeError:
                self.footer_overflow_button.setPopupMode(
                    QtWidgets.QToolButton.InstantPopup
                )
            self.save_button = QtWidgets.QPushButton("Save")
            self.save_button.clicked.connect(self._save)

            footer = QtWidgets.QHBoxLayout()
            footer.addWidget(self.footer_dirty_label)
            footer.addWidget(QtWidgets.QLabel("|"))
            footer.addWidget(self.footer_validation_label)
            footer.addStretch(1)
            footer.addWidget(self.footer_overflow_button)
            footer.addWidget(self.save_button)
            return footer

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
            destination = str(self._adapter.destination)
            try:
                try:
                    elide = QtCore.Qt.TextElideMode.ElideMiddle
                except AttributeError:
                    elide = QtCore.Qt.ElideMiddle
                destination = self.destination_label.fontMetrics().elidedText(
                    destination, elide, 420
                )
            except (AttributeError, TypeError):
                pass
            self.destination_label.setText(destination)
            self.destination_label.setToolTip(str(self._adapter.destination))
            self.description_label.setText(self._view.description or "No description")

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
                if (
                    self._selected_pass_index is None
                    and self._screen is ConfigV2EditorScreen.BUILDER
                ):
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

            if self._validation.valid:
                self.validation_label.setText(
                    f"Ready | {len(self._validation.pass_ids)} pass(es)"
                )
            else:
                self.validation_label.setText(
                    f"Blocked | {len(self._validation.diagnostics)} diagnostic(s)"
                )
            self._render_routing()
            self._render_footer()
            self._render_raw_document_trees()
            self._render_inspector()
            self._set_current_screen()

        def _set_current_screen(self) -> None:
            page = (
                self.inspector_page
                if self._screen is ConfigV2EditorScreen.INSPECTOR
                else self.builder_page
            )
            if self.screen_stack.indexOf(page) < 0:
                logger.warning(
                    "Config-v2 editor screen is not attached: %r", self._screen
                )
                return
            self.screen_stack.setCurrentWidget(page)

        def _render_routing(self) -> None:
            if not hasattr(self, "routing_group"):
                return
            routing = self._editor_view.routing
            self._rendering_routing = True
            try:
                self.routing_group.setTitle(
                    "Auto routing" if routing.is_auto else "Routing override"
                )
                self.routing_auto_check.setChecked(routing.is_auto)
                required_index = self.routing_require_combo.findData(routing.require)
                self.routing_require_combo.setCurrentIndex(
                    required_index if required_index >= 0 else 0
                )
                preferred = dict(routing.preferred)
                for family_name, (item, bias) in self.routing_prefer_rows.items():
                    item.setCheckState(
                        _checked_state()
                        if family_name in preferred
                        else _unchecked_state()
                    )
                    bias.setValue(float(preferred.get(family_name, 0.0)))
                denied = set(routing.denied)
                for index in range(self.routing_exclude_list.count()):
                    item = self.routing_exclude_list.item(index)
                    item.setCheckState(
                        _checked_state()
                        if str(item.data(_user_role())) in denied
                        else _unchecked_state()
                    )
                self._routing_auto_changed(routing.is_auto)
            finally:
                self._rendering_routing = False

        def _routing_auto_changed(self, checked: bool) -> None:
            enabled = not bool(checked)
            for widget in (
                self.routing_require_combo,
                self.routing_prefer_table,
                self.routing_exclude_list,
            ):
                widget.setEnabled(enabled)

        def _set_routing_expanded(self, expanded: bool) -> None:
            self.routing_body.setVisible(bool(expanded))

        def _render_footer(self) -> None:
            if not hasattr(self, "footer_dirty_label"):
                return
            footer = self._editor_view.footer
            self.footer_dirty_label.setText(
                "Unsaved changes" if footer.dirty else "Clean"
            )
            validation_is_current = (
                self._validation.draft_id == self._draft.draft_id
                and self._validation.revision == self._draft.revision
            )
            if footer.save_enabled:
                validation_state = "Ready"
            elif validation_is_current:
                validation_state = "Blocked"
            else:
                validation_state = "Validate before saving"
            self.footer_validation_label.setText(validation_state)
            self.footer_validation_label.setToolTip(footer.validation_detail)
            self.save_button.setEnabled(footer.save_enabled)
            self.save_button.setToolTip(footer.validation_detail)

        def _render_raw_document_trees(self) -> None:
            document_tree = getattr(self, "_raw_document_tree", None)
            preserved_tree = getattr(self, "_raw_preserved_tree", None)
            if document_tree is not None:
                document_tree.set_json(
                    self._structured_raw_document(),
                    editable=bool(getattr(self, "_raw_document_editable", False)),
                )
            if preserved_tree is not None:
                preserved_tree.set_json(
                    self._editor_view.raw_document.preserved_fields,
                    editable=False,
                )

        def _structured_raw_document(self) -> dict[str, object]:
            """Project only fields declared editable by config-v2 serializers."""

            document = self._editor_view.raw_document.document
            structured: dict[str, object] = {}
            if "description" in document:
                structured["description"] = copy.deepcopy(document["description"])
            additional = document.get("additional_configuration")
            if isinstance(additional, dict):
                structured_additional: dict[str, object] = {}
                for field in ("pipeline_v2", "router_resolution"):
                    if field in additional:
                        structured_additional[field] = copy.deepcopy(additional[field])
                structured["additional_configuration"] = structured_additional
            return structured

        @staticmethod
        def _is_structured_raw_document(value: object) -> bool:
            if not isinstance(value, dict):
                return False
            if set(value).difference({"description", "additional_configuration"}):
                return False
            additional = value.get("additional_configuration", {})
            return isinstance(additional, dict) and not set(additional).difference(
                {"pipeline_v2", "router_resolution"}
            )

        def _complete_document_from_structured_raw(
            self, structured: dict[str, object]
        ) -> dict[str, object]:
            document = copy.deepcopy(self._editor_view.raw_document.document)
            if "description" in structured:
                document["description"] = structured["description"]
            else:
                document.pop("description", None)
            additional = document.get("additional_configuration")
            structured_additional = structured.get("additional_configuration", {})
            if not isinstance(additional, dict) or not isinstance(
                structured_additional, dict
            ):
                raise ValueError("config-v2 additional_configuration must be an object")
            for field in ("pipeline_v2", "router_resolution"):
                if field in structured_additional:
                    additional[field] = copy.deepcopy(structured_additional[field])
                else:
                    additional.pop(field, None)
            return document

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

        def _open_selected_inspector(self, checked: bool = False) -> None:
            del checked
            index = self._builder_selected_pass_index()
            if index is not None:
                self._show_inspector(index)

        def _current_inspector(self) -> typing.Any | None:
            index = self._selected_pass_index
            if index is None or not 0 <= index < len(self._editor_view.inspectors):
                return None
            inspector = self._editor_view.inspectors[index]
            if inspector.pass_index != index:
                return None
            return inspector

        def _set_primary_workspace(
            self, primary: ConfigV2InspectorPrimarySection
        ) -> None:
            pages = {
                ConfigV2InspectorPrimarySection.RULES: self.rules_group,
                ConfigV2InspectorPrimarySection.TRANSFORMS: self.transforms_group,
            }
            page = pages.get(primary)
            catalog_primary = page is not None
            options_primary = primary is ConfigV2InspectorPrimarySection.OPTIONS
            has_primary = catalog_primary or options_primary
            self.primary_workspace.setVisible(catalog_primary)
            self.inspector_elastic_sink.setVisible(not has_primary)
            if self._inspector_layout is not None:
                primary_index = self._inspector_layout.indexOf(self.primary_workspace)
                options_index = self._inspector_layout.indexOf(self.options_group)
                sink_index = self._inspector_layout.indexOf(
                    self.inspector_elastic_sink
                )
                if primary_index >= 0:
                    self._inspector_layout.setStretch(
                        primary_index, 1 if catalog_primary else 0
                    )
                if options_index >= 0:
                    self._inspector_layout.setStretch(
                        options_index, 1 if options_primary else 0
                    )
                if sink_index >= 0:
                    self._inspector_layout.setStretch(
                        sink_index, 0 if has_primary else 1
                    )
            if page is not None:
                if self.primary_workspace.indexOf(page) < 0:
                    logger.warning(
                        "Config-v2 editor primary workspace is not attached: %r",
                        primary,
                    )
                    return
                self.primary_workspace.setCurrentWidget(page)

        def _set_details_expanded(self, expanded: bool) -> None:
            self.details_body.setVisible(
                bool(expanded) and self._current_inspector() is not None
            )

        def _render_inspector(self) -> None:
            inspector = self._current_inspector()
            self._rendering_inspector = True
            try:
                if inspector is None:
                    self.pass_title_label.setText("No pass selected")
                    self.pass_title_label.setToolTip("")
                    self.pass_purpose_label.setText("")
                    self.pass_purpose_label.setToolTip("")
                    self.inspector_actions.setVisible(False)
                    self.details_body.setVisible(False)
                    for label in self.contract_chip_labels.values():
                        label.setText("")
                    self.transforms_group.setVisible(False)
                    self.transform_catalog_widget.set_catalog(None)
                    self.rules_group.setVisible(False)
                    self.rule_catalog_widget.set_catalog(None)
                    self._set_primary_workspace(
                        ConfigV2InspectorPrimarySection.NONE
                    )
                    self._render_typed_options(None)
                    self.summary_message_label.setText(
                        "Select a pass to inspect its declared controls."
                    )
                    self.summary_message_label.setVisible(True)
                    self.raw_contract_button.setEnabled(False)
                    return

                title = f"{inspector.display_name} ({inspector.pass_id})"
                self.pass_title_label.setText(title)
                self.pass_title_label.setToolTip(title)
                self.pass_purpose_label.setText(inspector.purpose)
                self.pass_purpose_label.setToolTip(inspector.purpose)
                self.inspector_actions.setVisible(True)
                for label in self.contract_chip_labels.values():
                    label.setText("")
                for name, value in inspector.contract_chips:
                    self.contract_chip_labels[name].setText(value)
                self.details_body.setVisible(self.details_toggle.isChecked())

                layout = inspector.layout
                if layout is None:
                    self.transforms_group.setVisible(False)
                    self.transform_catalog_widget.set_catalog(None)
                    self.rules_group.setVisible(False)
                    self.rule_catalog_widget.set_catalog(None)
                    self._set_primary_workspace(
                        ConfigV2InspectorPrimarySection.NONE
                    )
                    self._render_typed_options(None)
                    self.summary_message_label.setText(
                        "Pass presentation data is unavailable; reopen the editor after reload."
                    )
                    self.summary_message_label.setVisible(True)
                    self.raw_contract_button.setEnabled(False)
                    return

                transform_catalog = inspector.transform_catalog
                self.transforms_group.setVisible(layout.show_transform_catalog)
                if layout.show_transform_catalog and transform_catalog is not None:
                    self.transform_catalog_widget.set_catalog(
                        project_transform_catalog(
                            transform_catalog.pass_editor_spec,
                            set(transform_catalog.selected_ids),
                            query=self._transform_catalog_query,
                        )
                    )
                else:
                    self.transform_catalog_widget.set_catalog(None)

                rule_catalog = inspector.rule_catalog
                self.rules_group.setVisible(layout.show_rule_catalog)
                if layout.show_rule_catalog and rule_catalog is not None:
                    self.rule_catalog_widget.set_catalog(
                        project_rule_catalog(
                            rule_catalog.pass_editor_spec,
                            set(rule_catalog.selected_ids),
                            query=self._rule_catalog_query,
                        )
                    )
                else:
                    self.rule_catalog_widget.set_catalog(None)

                self._render_typed_options(inspector)
                self.summary_message_label.setText(layout.summary_message)
                self.summary_message_label.setVisible(layout.show_summary_message)
                self._set_primary_workspace(layout.primary_section)
                self.options_group.setVisible(layout.show_options)
                self.raw_contract_button.setEnabled(layout.can_view_contract)
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
            self.error_label.setText(message)
            self.error_label.setVisible(bool(message))

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

        def _transform_catalog_query_changed(self, query: str) -> None:
            self._transform_catalog_query = str(query)
            if not self._rendering_inspector:
                self._render_inspector()

        def _apply_transform_catalog_selection(
            self,
            target_id: str,
            selected: bool,
        ) -> None:
            if self._rendering_inspector:
                return
            inspector = self._current_inspector()
            catalog = self.transform_catalog_widget.current_catalog()
            if inspector is None or catalog is None:
                self._render()
                return
            transform_ids = apply_transform_catalog_selection(
                catalog,
                set(catalog.selected_ids),
                target_id=target_id,
                selected=bool(selected),
            )
            self._apply_edit(
                lambda: self._adapter.set_pass_transforms(
                    self._draft,
                    pass_index=inspector.pass_index,
                    transform_ids=transform_ids,
                )
            )

        def _rule_catalog_query_changed(self, query: str) -> None:
            self._rule_catalog_query = str(query)
            if not self._rendering_inspector:
                self._render_inspector()

        def _apply_rule_catalog_selection(
            self,
            target_id: str,
            selected: bool,
        ) -> None:
            if self._rendering_inspector:
                return
            inspector = self._current_inspector()
            catalog = self.rule_catalog_widget.current_catalog()
            if inspector is None or catalog is None:
                self._render()
                return
            rule_ids = apply_rule_catalog_selection(
                catalog,
                set(catalog.selected_ids),
                target_id=target_id,
                selected=bool(selected),
            )
            try:
                options = apply_rule_catalog_selection_to_options(
                    inspector.options,
                    catalog.pass_editor_spec,
                    rule_ids,
                )
            except ValueError as exc:
                self._render()
                self._set_status(f"Invalid rule selection: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.set_pass_options(
                    self._draft,
                    pass_index=inspector.pass_index,
                    options=options,
                )
            )

        def _apply_typed_option(
            self,
            field: FieldEditorSpec,
            value: object,
        ) -> None:
            inspector = self._current_inspector()
            if inspector is None:
                self._render()
                return
            try:
                options = apply_typed_field_option(inspector.options, field, value)
            except ValueError as exc:
                self._render()
                self._set_status(f"Invalid value for {field.label}: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.set_pass_options(
                    self._draft,
                    pass_index=inspector.pass_index,
                    options=options,
                )
            )

        def _render_typed_options(self, inspector: typing.Any | None) -> None:
            while self.typed_options_layout.count():
                item = self.typed_options_layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.hide()
                    widget.setParent(None)
                    widget.deleteLater()
            self.typed_options_body.setVisible(False)
            self.options_group.setVisible(False)
            if inspector is None:
                return
            entry = self._catalog_by_pass_id.get(inspector.pass_id)
            spec = entry.editor_spec if entry is not None else None
            fields = tuple(spec.fields) if spec is not None else ()
            if inspector.transform_catalog is not None:
                fields += transform_option_fields(
                    inspector.transform_catalog.pass_editor_spec,
                    set(inspector.transform_catalog.selected_ids),
                )
            if spec is None or not fields:
                return
            self.typed_options_body.setVisible(True)
            self.options_group.setVisible(True)
            for field in fields:
                control = self._typed_option_control(
                    field,
                    typed_field_option_value(inspector.options, field),
                )
                annotations: list[str] = []
                if field.experimental:
                    annotations.append(f"Experimental: {field.experimental_reason}")
                if field.advisory.value != "none":
                    annotations.append(
                        f"Advisory: {field.advisory_reason}"
                    )
                label = QtWidgets.QLabel(field.label)
                label.setToolTip("\n".join((field.description, *annotations)))
                control.setToolTip(field.description)
                if not annotations:
                    self.typed_options_layout.addRow(label, control)
                    continue
                annotated_control = QtWidgets.QWidget(self.typed_options_body)
                annotated_layout = QtWidgets.QVBoxLayout(annotated_control)
                annotated_layout.setContentsMargins(0, 0, 0, 0)
                annotated_layout.setSpacing(2)
                annotated_layout.addWidget(control)
                annotation = QtWidgets.QLabel("\n".join(annotations), annotated_control)
                annotation.setWordWrap(True)
                annotation.setToolTip("\n".join(annotations))
                annotated_layout.addWidget(annotation)
                self.typed_options_layout.addRow(label, annotated_control)

        def _typed_option_control(
            self,
            field: FieldEditorSpec,
            value: object,
        ) -> typing.Any:
            if field.control is FieldControlKind.BOOLEAN:
                control = QtWidgets.QCheckBox()
                control.setChecked(bool(value))
                control.toggled.connect(
                    lambda checked, field=field: self._apply_typed_option(
                        field, bool(checked)
                    )
                )
                return control
            if field.control is FieldControlKind.INTEGER:
                minimum = field.minimum if field.minimum is not None else -2147483648
                maximum = field.maximum if field.maximum is not None else 2147483647
                # Qt's QSpinBox is limited to a signed 32-bit range.  Several
                # Hex-Rays pass settings are deliberately wider (for example,
                # state constants), so use the same fixed numeric control with
                # the pure field validator rather than silently narrowing them.
                if minimum < -2147483648 or maximum > 2147483647:
                    control = QtWidgets.QLineEdit()
                    control.setText(str(value) if isinstance(value, int) else "")
                    control.setPlaceholderText(f"{minimum} to {maximum}")
                    control.editingFinished.connect(
                        lambda control=control, field=field: self._apply_typed_option(
                            field, control.text()
                        )
                    )
                    return control
                control = QtWidgets.QSpinBox()
                control.setRange(minimum, maximum)
                control.setValue(int(value) if isinstance(value, int) else 0)
                control.valueChanged.connect(
                    lambda number, field=field: self._apply_typed_option(
                        field, int(number)
                    )
                )
                return control
            if field.control is FieldControlKind.ENUM:
                control = QtWidgets.QComboBox()
                for choice in field.choices:
                    control.addItem(choice, choice)
                index = control.findData(value)
                control.setCurrentIndex(index if index >= 0 else 0)
                control.currentIndexChanged.connect(
                    lambda _index, control=control, field=field: self._apply_typed_option(
                        field, control.currentData()
                    )
                )
                return control
            control = QtWidgets.QLineEdit()
            if field.control is FieldControlKind.STRING_LIST:
                initial = (
                    ", ".join(str(item) for item in value)
                    if isinstance(value, (list, tuple))
                    else ""
                )
            else:
                initial = str(value) if isinstance(value, str) else ""
            control.setText(initial)
            control.editingFinished.connect(
                lambda control=control, field=field: self._apply_typed_option(
                    field, control.text()
                )
            )
            return control

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

        def _edit_description(self, checked: bool = False) -> None:
            del checked
            value, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                "Edit description",
                "Description:",
                self._view.description,
            )
            if accepted:
                self._apply_edit(
                    lambda: self._adapter.set_description(self._draft, str(value))
                )

        def _add_pass(self, checked: bool = False) -> None:
            del checked
            dialog = QtWidgets.QDialog(self.parent)
            dialog.setWindowTitle("Add pass")
            query = QtWidgets.QLineEdit(dialog)
            query.setPlaceholderText("Filter public pass catalog")
            catalog_list = QtWidgets.QListWidget(dialog)

            def populate(filter_text: str) -> None:
                catalog_list.clear()
                needle = str(filter_text).strip().casefold()
                for entry in sorted(self._catalog, key=lambda item: item.pass_id):
                    label = f"{entry.display_name} ({entry.pass_id})"
                    if needle and needle not in label.casefold():
                        continue
                    item = QtWidgets.QListWidgetItem(label)
                    item.setData(_user_role(), entry.pass_id)
                    catalog_list.addItem(item)
                if catalog_list.count():
                    catalog_list.setCurrentRow(0)

            populate("")
            query.textChanged.connect(populate)
            add_button = QtWidgets.QPushButton("Add")
            cancel_button = QtWidgets.QPushButton("Cancel")
            add_button.clicked.connect(dialog.accept)
            cancel_button.clicked.connect(dialog.reject)
            controls = QtWidgets.QHBoxLayout()
            controls.addStretch(1)
            controls.addWidget(cancel_button)
            controls.addWidget(add_button)
            layout = QtWidgets.QVBoxLayout(dialog)
            layout.addWidget(query)
            layout.addWidget(catalog_list, stretch=1)
            layout.addLayout(controls)
            try:
                accepted_code = QtWidgets.QDialog.DialogCode.Accepted
            except AttributeError:
                accepted_code = QtWidgets.QDialog.Accepted
            if dialog.exec_() != accepted_code:
                return
            selected_item = catalog_list.currentItem()
            if selected_item is None:
                return
            pass_id = selected_item.data(_user_role())
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

        def _apply_routing_rows(self, checked: bool = False) -> None:
            del checked
            if self.routing_auto_check.isChecked():
                self._apply_edit(
                    lambda: self._adapter.clear_routing_override(self._draft)
                )
                return
            prefer = {
                family_name: float(bias.value())
                for family_name, (item, bias) in self.routing_prefer_rows.items()
                if item.checkState() == _checked_state()
            }
            require_data = self.routing_require_combo.currentData()
            require = str(require_data) if require_data is not None else None
            deny = tuple(
                str(self.routing_exclude_list.item(index).data(_user_role()))
                for index in range(self.routing_exclude_list.count())
                if self.routing_exclude_list.item(index).checkState()
                == _checked_state()
            )
            self._apply_edit(
                lambda: self._adapter.set_routing_override(
                    self._draft,
                    prefer=prefer,
                    require=require,
                    deny=deny,
                )
            )

        def _show_raw_document(self, checked: bool = False) -> None:
            del checked
            dialog = QtWidgets.QDialog(self.parent)
            dialog.setWindowTitle("Config-v2 structured fields")
            document_tree = JsonTreeEditor(dialog)
            preserved_tree = JsonTreeEditor(dialog)
            document_tree.set_json(
                self._structured_raw_document(),
                editable=False,
            )
            preserved_tree.set_json(
                self._editor_view.raw_document.preserved_fields,
                editable=False,
            )
            document_tree.set_on_value_changed(self._apply_raw_document)
            self._raw_document_tree = document_tree
            self._raw_preserved_tree = preserved_tree
            self._raw_document_editable = False

            tabs = QtWidgets.QTabWidget(dialog)
            tabs.addTab(document_tree, "Structured document")
            tabs.addTab(preserved_tree, "Preserved fields")
            edit_raw_button = QtWidgets.QPushButton("Edit raw")
            open_json_button = QtWidgets.QPushButton("Open structured JSON...")
            close_button = QtWidgets.QPushButton("Close")

            def confirm_raw_edit() -> bool:
                if self._raw_document_editable:
                    return True
                warning = (
                    "Only declared config-v2 fields may change; all edits are fully "
                    "validated before save."
                )
                try:
                    yes = QtWidgets.QMessageBox.StandardButton.Yes
                    no = QtWidgets.QMessageBox.StandardButton.No
                except AttributeError:
                    yes = QtWidgets.QMessageBox.Yes
                    no = QtWidgets.QMessageBox.No
                response = QtWidgets.QMessageBox.question(
                    dialog,
                    "Edit raw config-v2 fields?",
                    warning,
                    yes | no,
                    no,
                )
                if response != yes:
                    return False
                self._raw_document_editable = True
                document_tree.set_json(
                    self._structured_raw_document(),
                    editable=True,
                )
                return True

            def edit_raw() -> None:
                confirm_raw_edit()

            def open_raw_json() -> None:
                if not confirm_raw_edit():
                    return
                raw_dialog = RawJsonDialog(
                    "Edit config-v2 structured fields",
                    self._structured_raw_document(),
                    editable=True,
                    on_apply=self._apply_raw_document,
                    parent=dialog,
                )
                raw_dialog.exec_()

            edit_raw_button.clicked.connect(edit_raw)
            open_json_button.clicked.connect(open_raw_json)
            close_button.clicked.connect(dialog.accept)
            controls = QtWidgets.QHBoxLayout()
            controls.addWidget(edit_raw_button)
            controls.addWidget(open_json_button)
            controls.addStretch(1)
            controls.addWidget(close_button)
            layout = QtWidgets.QVBoxLayout(dialog)
            layout.addWidget(tabs, stretch=1)
            layout.addLayout(controls)
            try:
                dialog.exec_()
            finally:
                self._raw_document_tree = None
                self._raw_preserved_tree = None
                self._raw_document_editable = False

        def _apply_raw_document(self, value: object) -> None:
            if not self._is_structured_raw_document(value):
                self._render_raw_document_trees()
                self._set_status("Only declared config-v2 fields may change.")
                return
            assert isinstance(value, dict)
            try:
                document = self._complete_document_from_structured_raw(value)
            except ValueError as exc:
                self._render_raw_document_trees()
                self._set_status(f"Edit failed: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.replace_document(self._draft, document)
            )

        def _discard_unsaved(self, checked: bool = False) -> None:
            del checked
            if not self._editor_view.footer.dirty:
                return
            try:
                discard = QtWidgets.QMessageBox.StandardButton.Discard
                cancel = QtWidgets.QMessageBox.StandardButton.Cancel
            except AttributeError:
                discard = QtWidgets.QMessageBox.Discard
                cancel = QtWidgets.QMessageBox.Cancel
            response = QtWidgets.QMessageBox.question(
                self.parent,
                "Discard unsaved changes?",
                "Discard every unsaved change and restore the current source?",
                discard | cancel,
                cancel,
            )
            if response == discard:
                self._apply_edit(lambda: self._adapter.reset())

        def _show_developer_help(self, checked: bool = False) -> None:
            del checked
            rows = project_serializer_rows(self._manifest)
            details = (
                "\n".join(
                    f"{row.label}: {row.value_kind} at {row.path}" for row in rows
                )
                or "No declared editable fields."
            )
            QtWidgets.QMessageBox.information(
                self.parent,
                "Config-v2 developer help",
                "Serializer manifest\n" + details,
            )

        def _validate(self, checked: bool = False) -> None:
            del checked
            try:
                self._validation = self._adapter.validate(self._draft)
            except Exception as exc:
                self._set_status(f"Validation failed: {exc}")
                return
            self._render()
            if self._validation.valid:
                self._set_status("")
            else:
                self._set_status(
                    "\n".join(item.message for item in self._validation.diagnostics)
                )

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
            self._render()
            self._set_status("")

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
            self._render()
            self._set_status("")

else:

    class ConfigV2EditingPanel:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ConfigV2EditingPanel requires IDA Pro")


__all__ = ["ConfigV2EditingPanel", "IDA_AVAILABLE"]
