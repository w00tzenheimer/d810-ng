"""Thin dockable Qt adapter for registered-pass recipe composition."""

from __future__ import annotations

import json

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.workbench_recipe_logic import (
    project_catalog_rows,
    project_draft_rows,
    recipe_action_states,
    should_accept_recipe_result,
)

logger = getLogger("D810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtGui, QtWidgets

    WOPN_NOT_CLOSED_BY_ESC = getattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100)

    def _user_role() -> int:
        try:
            return int(QtCore.Qt.ItemDataRole.UserRole)
        except AttributeError:
            return int(QtCore.Qt.UserRole)

    class WorkbenchRecipePanel(ida_kernwin.PluginForm):
        """Companion dock whose policy and mutations remain service-owned."""

        TITLE = "d810-ng Recipe Composer"
        _SORT_KEYS = ("name", "pass_id", "maturity", "backend")

        def __init__(
            self,
            adapter: typing.Any,
            *,
            refresh_workbench: typing.Callable[[], None] | None = None,
        ) -> None:
            ida_kernwin.PluginForm.__init__(self)
            self._adapter = adapter
            self._refresh_workbench = refresh_workbench
            self._catalog_entries = tuple(adapter.catalog())
            self._draft, self._validation = adapter.reset()
            self._catalog_by_id = {
                entry.pass_id: entry for entry in self._catalog_entries
            }
            self._catalog_rows: tuple[typing.Any, ...] = ()
            self._draft_rows: tuple[typing.Any, ...] = ()
            self._draft_by_item: dict[str, typing.Any] = {}
            self._closed = False
            self.parent: typing.Any = None

            self.context_label = QtWidgets.QLabel()
            self.validation_label = QtWidgets.QLabel()
            self.search_edit = QtWidgets.QLineEdit()
            self.search_edit.setPlaceholderText(
                "Search registered passes and transforms"
            )
            self.sort_combo = QtWidgets.QComboBox()
            for label in ("Name", "Pass ID", "Maturity", "Backend"):
                self.sort_combo.addItem(label)

            self.catalog_model = QtGui.QStandardItemModel()
            self.catalog_model.setHorizontalHeaderLabels(
                ["Registered pass / transform", "Contract summary"]
            )
            self.catalog_tree = QtWidgets.QTreeView()
            self.catalog_tree.setModel(self.catalog_model)
            self.catalog_tree.setRootIsDecorated(True)
            self.catalog_tree.setEditTriggers(
                QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
            )

            self.draft_model = QtGui.QStandardItemModel()
            self.draft_model.setHorizontalHeaderLabels(
                ["Order", "Enabled", "Status", "Stable pass ID"]
            )
            self.draft_tree = QtWidgets.QTreeView()
            self.draft_tree.setModel(self.draft_model)
            self.draft_tree.setRootIsDecorated(False)
            self.draft_tree.setSortingEnabled(False)
            self.draft_tree.setEditTriggers(
                QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
            )

            self.detail = QtWidgets.QPlainTextEdit()
            self.detail.setReadOnly(True)

            self.edit_buttons: dict[str, typing.Any] = {}
            for action_id, label in (
                ("add", "Add"),
                ("remove", "Remove"),
                ("toggle", "Enable / disable"),
                ("up", "Move up"),
                ("down", "Move down"),
                ("options", "Edit options"),
            ):
                self.edit_buttons[action_id] = QtWidgets.QPushButton(label)

            self.action_buttons: dict[str, typing.Any] = {}
            for action_id, label in (
                ("reset", "Reset to effective pipeline"),
                ("analyze", "Analyze recipe"),
                ("apply_once", "Apply once"),
                ("save_function", "Save for this function"),
                ("save_project", "Save as project profile"),
            ):
                self.action_buttons[action_id] = QtWidgets.QPushButton(label)

            self.search_edit.textChanged.connect(self._render)
            self.sort_combo.currentIndexChanged.connect(self._render)
            self.catalog_tree.selectionModel().currentChanged.connect(
                self._catalog_selection_changed
            )
            self.draft_tree.selectionModel().currentChanged.connect(
                self._draft_selection_changed
            )
            self.edit_buttons["add"].clicked.connect(self._add_pass)
            self.edit_buttons["remove"].clicked.connect(self._remove_pass)
            self.edit_buttons["toggle"].clicked.connect(self._toggle_pass)
            self.edit_buttons["up"].clicked.connect(
                lambda checked=False: self._move_pass(-1)
            )
            self.edit_buttons["down"].clicked.connect(
                lambda checked=False: self._move_pass(1)
            )
            self.edit_buttons["options"].clicked.connect(self._edit_options)
            self.action_buttons["reset"].clicked.connect(self._reset)
            self.action_buttons["analyze"].clicked.connect(self._analyze)
            self.action_buttons["apply_once"].clicked.connect(self._apply_once)
            self.action_buttons["save_function"].clicked.connect(self._save_function)
            # save_project intentionally has no handler until Slice 5 live acceptance.

            self._render()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)
            catalog_controls = QtWidgets.QHBoxLayout()
            catalog_controls.addWidget(self.search_edit)
            catalog_controls.addWidget(self.sort_combo)

            edit_layout = QtWidgets.QHBoxLayout()
            for action_id in ("add", "remove", "toggle", "up", "down", "options"):
                edit_layout.addWidget(self.edit_buttons[action_id])
            edit_layout.addStretch(1)

            panes = QtWidgets.QSplitter()
            try:
                panes.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                panes.setOrientation(QtCore.Qt.Horizontal)
            panes.addWidget(self.catalog_tree)
            panes.addWidget(self.draft_tree)
            panes.addWidget(self.detail)
            panes.setStretchFactor(0, 2)
            panes.setStretchFactor(1, 2)
            panes.setStretchFactor(2, 2)

            actions = QtWidgets.QHBoxLayout()
            for action_id in (
                "reset",
                "analyze",
                "apply_once",
                "save_function",
                "save_project",
            ):
                actions.addWidget(self.action_buttons[action_id])
            actions.addStretch(1)

            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(4, 4, 4, 4)
            layout.addWidget(self.context_label)
            layout.addWidget(self.validation_label)
            layout.addLayout(catalog_controls)
            layout.addWidget(panes)
            layout.addLayout(edit_layout)
            layout.addLayout(actions)
            self.parent.setLayout(layout)
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
                    "d810-ng Deobfuscation Workbench",
                    ida_kernwin.DP_RIGHT,
                )
                self._render()
            return shown

        def _render(self, ignored: typing.Any = None) -> None:
            del ignored
            sort_index = max(0, min(self.sort_combo.currentIndex(), 3))
            self._catalog_rows = project_catalog_rows(
                self._catalog_entries,
                query=self.search_edit.text(),
                sort_by=self._SORT_KEYS[sort_index],
            )
            self._draft_rows = project_draft_rows(self._draft, self._validation)
            self._draft_by_item = {row.item_id: row for row in self._draft_rows}
            states = recipe_action_states(
                self._draft,
                self._validation,
                workbench_current=self._adapter.is_current(self._draft),
                engine_started=self._adapter.engine_started(),
                project_profile_save_available=False,
            )
            self.context_label.setText(
                f"Function 0x{self._draft.function_ea:X}; draft revision "
                f"{self._draft.revision}; execution order is top to bottom"
            )
            if self._validation.satisfied:
                self.validation_label.setText("Contract preflight: ready")
            else:
                self.validation_label.setText(
                    f"Contract preflight: blocked ({len(self._validation.diagnostics)} diagnostic(s))"
                )
            self._render_catalog()
            self._render_draft()
            by_id = {state.action_id: state for state in states}
            for action_id, button in self.action_buttons.items():
                state = by_id[action_id]
                button.setText(state.label)
                button.setEnabled(state.enabled)
                button.setToolTip(state.reason)

        def _render_catalog(self) -> None:
            self.catalog_model.removeRows(0, self.catalog_model.rowCount())
            role = _user_role()
            for row in self._catalog_rows:
                label = QtGui.QStandardItem(f"{row.label} ({row.pass_id})")
                summary = QtGui.QStandardItem(row.summary)
                label.setData(row.pass_id, role)
                label.setToolTip(row.detail)
                summary.setToolTip(row.detail)
                self.catalog_model.appendRow([label, summary])
                for transform in row.transform_children:
                    child = QtGui.QStandardItem(f"transform: {transform}")
                    child.setToolTip(
                        "Explanatory owned transform; add its registered pass instead"
                    )
                    label.appendRow([child, QtGui.QStandardItem("explanatory")])
            self.catalog_tree.expandAll()
            self.catalog_tree.header().setStretchLastSection(True)

        def _render_draft(self) -> None:
            selected = self._selected_draft_item_id()
            self.draft_model.removeRows(0, self.draft_model.rowCount())
            role = _user_role()
            selected_index = None
            for model_row, row in enumerate(self._draft_rows):
                items = [
                    QtGui.QStandardItem(str(row.ordinal + 1)),
                    QtGui.QStandardItem("yes" if row.enabled else "no"),
                    QtGui.QStandardItem(row.status.value),
                    QtGui.QStandardItem(row.pass_id),
                ]
                for item in items:
                    item.setData(row.item_id, role)
                    item.setToolTip("\n".join(row.diagnostics) or row.config_json)
                self.draft_model.appendRow(items)
                if row.item_id == selected:
                    selected_index = self.draft_model.index(model_row, 0)
            if selected_index is not None:
                self.draft_tree.setCurrentIndex(selected_index)
            self.draft_tree.header().setStretchLastSection(True)

        def _selected_catalog_pass_id(self) -> str | None:
            index = self.catalog_tree.currentIndex()
            if not index.isValid():
                return None
            value = index.sibling(index.row(), 0).data(_user_role())
            return str(value) if value else None

        def _selected_draft_item_id(self) -> str | None:
            index = self.draft_tree.currentIndex()
            if not index.isValid():
                return None
            value = index.sibling(index.row(), 0).data(_user_role())
            return str(value) if value else None

        def _apply_edit(
            self, operation: typing.Callable[[], tuple[typing.Any, typing.Any]]
        ) -> None:
            try:
                self._draft, self._validation = operation()
            except Exception as exc:
                logger.warning("Recipe edit failed: %s", exc)
                self.detail.setPlainText(f"Recipe edit failed: {exc}")
                return
            self._render()

        def _add_pass(self, checked: bool = False) -> None:
            del checked
            pass_id = self._selected_catalog_pass_id()
            if pass_id is not None:
                self._apply_edit(lambda: self._adapter.add_pass(self._draft, pass_id))

        def _remove_pass(self, checked: bool = False) -> None:
            del checked
            item_id = self._selected_draft_item_id()
            if item_id is not None:
                self._apply_edit(
                    lambda: self._adapter.remove_pass(self._draft, item_id)
                )

        def _toggle_pass(self, checked: bool = False) -> None:
            del checked
            item_id = self._selected_draft_item_id()
            row = self._draft_by_item.get(item_id or "")
            if row is not None:
                self._apply_edit(
                    lambda: self._adapter.set_enabled(
                        self._draft,
                        row.item_id,
                        not row.enabled,
                    )
                )

        def _move_pass(self, delta: int) -> None:
            item_id = self._selected_draft_item_id()
            row = self._draft_by_item.get(item_id or "")
            if row is None:
                return
            new_index = row.ordinal + int(delta)
            if 0 <= new_index < len(self._draft_rows):
                self._apply_edit(
                    lambda: self._adapter.reorder_pass(
                        self._draft,
                        row.item_id,
                        new_index,
                    )
                )

        def _edit_options(self, checked: bool = False) -> None:
            del checked
            item_id = self._selected_draft_item_id()
            row = self._draft_by_item.get(item_id or "")
            if row is None:
                return
            current = json.loads(row.config_json).get("options", {})
            text, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                f"Structured options for {row.pass_id}",
                "JSON object:",
                json.dumps(current, indent=2, sort_keys=True),
            )
            if not accepted:
                return
            try:
                options = json.loads(str(text))
                if not isinstance(options, dict):
                    raise ValueError("options must be a JSON object")
            except (json.JSONDecodeError, ValueError) as exc:
                self.detail.setPlainText(f"Invalid structured options: {exc}")
                return
            self._apply_edit(
                lambda: self._adapter.replace_options(
                    self._draft,
                    row.item_id,
                    options,
                )
            )

        def _reset(self, checked: bool = False) -> None:
            del checked
            self._apply_edit(lambda: self._adapter.reset())

        def _analyze(self, checked: bool = False) -> None:
            del checked
            try:
                self._validation = self._adapter.analyze(self._draft)
            except Exception as exc:
                self.detail.setPlainText(f"Analyze recipe failed: {exc}")
                return
            self._render()

        def _apply_once(self, checked: bool = False) -> None:
            del checked
            result = self._adapter.apply_once(self._draft, self._validation)
            self.detail.setPlainText(result.message)
            if (
                should_accept_recipe_result(self._draft, result)
                and result.refresh_requested
            ):
                if self._refresh_workbench is not None:
                    self._refresh_workbench()
                self._render()

        def _save_function(self, checked: bool = False) -> None:
            del checked
            result = self._adapter.save_function(self._draft, self._validation)
            self.detail.setPlainText(result.message)
            if (
                should_accept_recipe_result(self._draft, result)
                and result.refresh_requested
            ):
                if self._refresh_workbench is not None:
                    self._refresh_workbench()
                self._render()

        def _catalog_selection_changed(
            self,
            current: typing.Any = None,
            previous: typing.Any = None,
        ) -> None:
            del current, previous
            pass_id = self._selected_catalog_pass_id()
            row = next(
                (item for item in self._catalog_rows if item.pass_id == pass_id),
                None,
            )
            self.detail.setPlainText(row.detail if row is not None else "")

        def _draft_selection_changed(
            self,
            current: typing.Any = None,
            previous: typing.Any = None,
        ) -> None:
            del current, previous
            row = self._draft_by_item.get(self._selected_draft_item_id() or "")
            if row is None:
                self.detail.setPlainText("")
                return
            diagnostics = "\n".join(row.diagnostics) or "No preflight diagnostics"
            self.detail.setPlainText(
                f"{row.label}\nstatus: {row.status.value}\n{diagnostics}\n\n{row.config_json}"
            )

else:

    class WorkbenchRecipePanel:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("WorkbenchRecipePanel requires IDA Pro")


__all__ = ["IDA_AVAILABLE", "WorkbenchRecipePanel"]
