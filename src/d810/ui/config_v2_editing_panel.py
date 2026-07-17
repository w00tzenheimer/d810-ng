"""Thin dockable Qt adapter for lossless config-v2 project editing."""

from __future__ import annotations

import json

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.config_v2_editing_logic import (
    config_v2_action_states,
    project_config_v2_document,
    project_serializer_rows,
)

logger = getLogger("D810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtWidgets

    WOPN_NOT_CLOSED_BY_ESC = getattr(
        ida_kernwin,
        "WOPN_NOT_CLOSED_BY_ESC",
        0x100,
    )

    class ConfigV2EditingPanel(ida_kernwin.PluginForm):
        """Render typed serializers while leaving policy in the state service."""

        TITLE = "d810-ng Config-v2 Project Editor"

        def __init__(
            self,
            adapter: typing.Any,
            *,
            on_saved: typing.Callable[[], None] | None = None,
        ) -> None:
            ida_kernwin.PluginForm.__init__(self)
            self._adapter = adapter
            self._on_saved = on_saved
            self._manifest = tuple(adapter.manifest())
            self._catalog = tuple(adapter.catalog())
            self._draft, self._validation = adapter.reset()
            self._view = project_config_v2_document(self._draft)
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
                ("rules", "Edit rules/options"),
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

            self.validate_button = QtWidgets.QPushButton("Validate full pipeline")
            self.reset_button = QtWidgets.QPushButton("Reset draft")
            self.reset_button.setToolTip(
                "Restore the complete runtime source and any originating recipe seed"
            )
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
            self.pass_buttons["rules"].clicked.connect(self._edit_pass_rules)
            self.routing_button.clicked.connect(self._edit_routing)
            self.validate_button.clicked.connect(self._validate)
            self.reset_button.clicked.connect(self._reset)
            self.save_button.clicked.connect(self._save)
            self._render()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            identity_group = QtWidgets.QGroupBox("Project", self.parent)
            identity_layout = QtWidgets.QFormLayout(identity_group)
            identity_layout.addRow("Destination:", self.destination_label)
            identity_layout.addRow("Validation:", self.validation_label)

            description_row = QtWidgets.QHBoxLayout()
            description_row.addWidget(QtWidgets.QLabel("Description:"))
            description_row.addWidget(self.description_edit)
            description_row.addWidget(self.description_button)

            pass_row = QtWidgets.QHBoxLayout()
            pass_row.addWidget(self.catalog_combo)
            for action_id in ("add", "remove", "up", "down", "rules"):
                pass_row.addWidget(self.pass_buttons[action_id])

            typed_splitter = QtWidgets.QSplitter()
            try:
                typed_splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                typed_splitter.setOrientation(QtCore.Qt.Horizontal)
            typed_splitter.addWidget(self.manifest_list)
            typed_splitter.addWidget(self.pipeline_list)
            typed_splitter.addWidget(self.routing_view)
            typed_splitter.setStretchFactor(0, 1)
            typed_splitter.setStretchFactor(1, 2)
            typed_splitter.setStretchFactor(2, 2)

            raw_tabs = QtWidgets.QTabWidget()
            raw_tabs.addTab(self.unsupported_document, "Unsupported fields (read-only)")
            raw_tabs.addTab(self.complete_document, "Complete document (read-only)")

            editing_group = QtWidgets.QGroupBox("Structured fields", self.parent)
            editing_layout = QtWidgets.QVBoxLayout(editing_group)
            editing_layout.addLayout(description_row)
            editing_layout.addLayout(pass_row)
            editing_layout.addWidget(typed_splitter, stretch=1)

            raw_group = QtWidgets.QGroupBox("Preserved document", self.parent)
            raw_layout = QtWidgets.QVBoxLayout(raw_group)
            raw_layout.addWidget(raw_tabs)

            action_row = QtWidgets.QHBoxLayout()
            action_row.addWidget(self.routing_button)
            action_row.addWidget(self.reset_button)
            action_row.addStretch(1)
            action_row.addWidget(self.validate_button)
            action_row.addWidget(self.save_button)

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(6)
            layout.addWidget(identity_group)
            layout.addWidget(editing_group, stretch=2)
            layout.addWidget(raw_group, stretch=1)
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

            selected = self.pipeline_list.currentRow()
            self.pipeline_list.clear()
            for row in self._view.pipeline_rows:
                item = QtWidgets.QListWidgetItem(f"{row.index + 1}. {row.pass_id}")
                item.setToolTip(row.config_json)
                self.pipeline_list.addItem(item)
            if self._view.pipeline_rows:
                self.pipeline_list.setCurrentRow(
                    min(max(selected, 0), len(self._view.pipeline_rows) - 1)
                )

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

        def _selected_pass_index(self) -> int | None:
            index = self.pipeline_list.currentRow()
            if not 0 <= index < len(self._view.pipeline_rows):
                return None
            return index

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
                self._set_status(f"Edit failed: {exc}")
                return False
            self._set_status("")
            self._render()
            return True

        def _set_description(self, checked: bool = False) -> None:
            del checked
            value = self.description_edit.toPlainText()
            self._apply_edit(lambda: self._adapter.set_description(self._draft, value))

        def _add_pass(self, checked: bool = False) -> None:
            del checked
            pass_id = self.catalog_combo.currentData()
            if not pass_id:
                return
            selected = self._selected_pass_index()
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
            index = self._selected_pass_index()
            if index is not None:
                self._apply_edit(lambda: self._adapter.remove_pass(self._draft, index))

        def _move_pass(self, delta: int) -> None:
            index = self._selected_pass_index()
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

        def _edit_pass_rules(self, checked: bool = False) -> None:
            del checked
            index = self._selected_pass_index()
            if index is None:
                return
            row = self._view.pipeline_rows[index]
            current = json.loads(row.rules_json)
            payload = {
                "include": current.get("include", []),
                "exclude": current.get("exclude", []),
                "options": current.get("options", {}),
            }
            text, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                f"Rules/options for {row.pass_id}",
                "Typed JSON object with include, exclude, and options:",
                json.dumps(payload, indent=2, sort_keys=True),
            )
            if not accepted:
                return
            try:
                value = json.loads(str(text))
                if not isinstance(value, dict) or set(value) != {
                    "include",
                    "exclude",
                    "options",
                }:
                    raise ValueError(
                        "rules must contain exactly include, exclude, and options"
                    )
                include = value["include"]
                exclude = value["exclude"]
                options = value["options"]
                if (
                    not isinstance(include, list)
                    or not all(isinstance(item, str) for item in include)
                    or not isinstance(exclude, list)
                    or not all(isinstance(item, str) for item in exclude)
                    or not isinstance(options, dict)
                ):
                    raise ValueError(
                        "include/exclude must be string lists and options an object"
                    )
            except (json.JSONDecodeError, ValueError) as exc:
                self._set_status(f"Invalid pass rule selection: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.set_pass_rules(
                    self._draft,
                    pass_index=index,
                    include=include,
                    exclude=exclude,
                    options=options,
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
