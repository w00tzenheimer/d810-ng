"""Thin IDA/Qt adapter for the read-only deobfuscation workbench."""

from __future__ import annotations

import pathlib

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.workbench_logic import (
    WorkbenchActionState,
    WorkbenchRow,
    WorkbenchSection,
    action_states,
    detail_text,
    export_evidence_json,
    filter_workbench_rows,
    project_workbench_rows,
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

    WOPN_NOT_CLOSED_BY_ESC = getattr(
        ida_kernwin,
        "WOPN_NOT_CLOSED_BY_ESC",
        0x100,
    )

    def _user_role() -> int:
        try:
            return int(QtCore.Qt.ItemDataRole.UserRole)
        except AttributeError:
            return int(QtCore.Qt.UserRole)


    class DeobfuscationWorkbenchPanel(ida_kernwin.PluginForm):
        """Persistent native dock that renders manager-owned snapshots."""

        TITLE = "d810-ng Deobfuscation Workbench"

        def __init__(self, state: typing.Any) -> None:
            ida_kernwin.PluginForm.__init__(self)
            self._state = state
            self._func_ea: int | None = None
            self._func_name = ""
            self._fingerprint: str | None = None
            self._snapshot: typing.Any = None
            self._rows: tuple[WorkbenchRow, ...] = ()
            self._visible_rows: tuple[WorkbenchRow, ...] = ()
            self._row_by_key: dict[str, WorkbenchRow] = {}
            self._pending_focus: WorkbenchSection | None = None
            self._closed = False
            self.parent: typing.Any = None

            self.function_label = QtWidgets.QLabel("No function selected")
            self.runtime_label = QtWidgets.QLabel("No runtime project")
            self.attack_label = QtWidgets.QLabel("Attack: not analyzed")

            self.filter_edit = QtWidgets.QLineEdit()
            self.filter_edit.setPlaceholderText("Filter workbench evidence")
            self.filter_edit.setToolTip(
                "Filter by item, summary, detail, or approved outcome status"
            )

            self.model = QtGui.QStandardItemModel()
            self.model.setHorizontalHeaderLabels(
                ["Section", "Status", "Item", "Summary"]
            )
            self.tree = QtWidgets.QTreeView()
            self.tree.setModel(self.model)
            self.tree.setRootIsDecorated(False)
            self.tree.setUniformRowHeights(True)
            self.tree.setSortingEnabled(False)
            self.tree.setSelectionBehavior(
                QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
            )
            self.tree.setEditTriggers(
                QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
            )

            self.detail = QtWidgets.QPlainTextEdit()
            self.detail.setReadOnly(True)
            self.detail.setPlaceholderText("Select an item to inspect its evidence")

            self.action_buttons: dict[str, typing.Any] = {}
            action_layout = QtWidgets.QHBoxLayout()
            for action_id, label in (
                ("refresh", "Refresh"),
                ("export", "Export evidence"),
                ("analyze", "Analyze"),
                ("deobfuscate", "Deobfuscate"),
                ("compare", "Compare"),
                ("recipe", "Recipe"),
                ("diagnostics", "Diagnostics"),
            ):
                button = QtWidgets.QPushButton(label)
                self.action_buttons[action_id] = button
                action_layout.addWidget(button)
            action_layout.addStretch(1)
            self.action_layout = action_layout

            self.filter_edit.textChanged.connect(self._on_filter_changed)
            self.tree.selectionModel().selectionChanged.connect(
                self._on_selection_changed
            )
            self.action_buttons["refresh"].clicked.connect(self.refresh)
            self.action_buttons["export"].clicked.connect(self._export_evidence)

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            context_layout = QtWidgets.QVBoxLayout()
            context_layout.setContentsMargins(0, 0, 0, 0)
            context_layout.addWidget(self.function_label)
            context_layout.addWidget(self.runtime_label)
            context_layout.addWidget(self.attack_label)

            splitter = QtWidgets.QSplitter()
            try:
                splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                splitter.setOrientation(QtCore.Qt.Horizontal)
            splitter.addWidget(self.tree)
            splitter.addWidget(self.detail)
            splitter.setStretchFactor(0, 3)
            splitter.setStretchFactor(1, 2)

            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(4, 4, 4, 4)
            layout.addLayout(context_layout)
            layout.addWidget(self.filter_edit)
            layout.addWidget(splitter)
            layout.addLayout(self.action_layout)
            self.parent.setLayout(layout)

            self.tree.header().setStretchLastSection(True)
            for column in range(3):
                self.tree.resizeColumnToContents(column)
            self._render_rows(self._visible_rows)

        def OnClose(self, form: typing.Any) -> None:
            del form
            self._closed = True
            try:
                self.filter_edit.textChanged.disconnect()
                self.tree.selectionModel().selectionChanged.disconnect()
                for button in self.action_buttons.values():
                    button.clicked.disconnect()
            except (RuntimeError, TypeError):
                pass
            self.parent = None

        def Show(self) -> bool:
            return ida_kernwin.PluginForm.Show(
                self,
                self.TITLE,
                options=ida_kernwin.PluginForm.WOPN_PERSIST,
            )

        def show(self, focus_section: str | WorkbenchSection | None = None) -> bool:
            if focus_section is None:
                self._pending_focus = None
            elif isinstance(focus_section, WorkbenchSection):
                self._pending_focus = focus_section
            else:
                try:
                    self._pending_focus = WorkbenchSection(str(focus_section))
                except ValueError:
                    self._pending_focus = None

            shown = self.Show()
            if shown:
                ida_kernwin.display_widget(
                    self.GetWidget(),
                    WOPN_NOT_CLOSED_BY_ESC,
                    None,
                )
                ida_kernwin.set_dock_pos(
                    self.TITLE,
                    "IDA View-A",
                    ida_kernwin.DP_TAB,
                )
                self.refresh()
                self._focus_section(self._pending_focus)
                self.tree.setFocus()
            return shown

        def set_function(
            self,
            func_ea: int | None,
            func_name: str | None,
            fingerprint: str | None = None,
        ) -> None:
            self._func_ea = None if func_ea is None else int(func_ea)
            self._func_name = str(func_name or "")
            self._fingerprint = fingerprint
            self.refresh()

        def refresh(self) -> None:
            if self._func_ea is None:
                self._snapshot = None
                self._rows = ()
                self._visible_rows = ()
                self._row_by_key = {}
                self.function_label.setText("No function selected")
                self.runtime_label.setText("No runtime project")
                self.attack_label.setText("Attack: not analyzed")
                self._render_rows(())
                self._render_action_states(())
                return

            snapshot = self._state.get_workbench_snapshot(
                self._func_ea,
                self._func_name,
                self._fingerprint,
            )
            rows = project_workbench_rows(snapshot)
            visible_rows = filter_workbench_rows(rows, self.filter_edit.text())
            states = action_states(snapshot)

            self._snapshot = snapshot
            self._rows = rows
            self._visible_rows = visible_rows
            self._row_by_key = {row.key: row for row in rows}
            self._render_context()
            self._render_rows(visible_rows)
            self._render_action_states(states)
            self._focus_section(self._pending_focus)

        def _render_context(self) -> None:
            snapshot = self._snapshot
            if snapshot is None:
                return
            function_name = snapshot.function.name or f"sub_{snapshot.function.ea:X}"
            self.function_label.setText(
                f"Function: {function_name} @ 0x{snapshot.function.ea:X} "
                f"(generation {snapshot.generation})"
            )
            routed = " routed from " + snapshot.runtime.source_name \
                if snapshot.runtime.routed else ""
            self.runtime_label.setText(
                f"Runtime: {snapshot.runtime.runtime_name}{routed} "
                f"[{snapshot.runtime.mode}]"
            )
            confidence = (
                "unavailable"
                if snapshot.attack.confidence is None
                else f"{snapshot.attack.confidence:.2f}"
            )
            self.attack_label.setText(
                f"Attack: {snapshot.attack.observed_shape}; "
                f"confidence {confidence}; selection {snapshot.attack.selection_mode}"
            )

        def _render_rows(self, rows: tuple[WorkbenchRow, ...]) -> None:
            selected_key = self._selected_key()
            self.model.removeRows(0, self.model.rowCount())
            role = _user_role()
            selected_index = None
            for model_row, row in enumerate(rows):
                values = (
                    row.section.value.title(),
                    row.status.value,
                    row.label,
                    row.summary,
                )
                items = [QtGui.QStandardItem(value) for value in values]
                for item in items:
                    item.setEditable(False)
                    item.setToolTip(row.tooltip)
                    item.setData(row.key, role)
                    item.setData(row.color_role, role + 1)
                self.model.appendRow(items)
                if row.key == selected_key:
                    selected_index = self.model.index(model_row, 0)
            if selected_index is not None:
                self.tree.setCurrentIndex(selected_index)
            for column in range(self.model.columnCount()):
                self.tree.resizeColumnToContents(column)

        def _render_action_states(
            self,
            states: tuple[WorkbenchActionState, ...],
        ) -> None:
            by_id = {state.action_id: state for state in states}
            for action_id, button in self.action_buttons.items():
                state = by_id.get(action_id)
                if state is None:
                    button.setEnabled(action_id in {"refresh", "export"})
                    button.setToolTip("")
                    continue
                button.setText(state.label)
                button.setEnabled(state.enabled)
                button.setToolTip(state.reason)

        def _selected_key(self) -> str | None:
            index = self.tree.currentIndex()
            if not index.isValid():
                return None
            value = index.data(_user_role())
            return str(value) if value else None

        def _on_filter_changed(self, text: str = "") -> None:
            del text
            self._visible_rows = filter_workbench_rows(
                self._rows,
                self.filter_edit.text(),
            )
            self._render_rows(self._visible_rows)

        def _on_selection_changed(
            self,
            selected: typing.Any = None,
            deselected: typing.Any = None,
        ) -> None:
            del selected, deselected
            key = self._selected_key()
            row = self._row_by_key.get(key or "")
            self.detail.setPlainText(detail_text(row) if row is not None else "")

        def _focus_section(self, section: WorkbenchSection | None) -> None:
            if section is None:
                return
            for row_number, row in enumerate(self._visible_rows):
                if row.section is section:
                    self.tree.setCurrentIndex(self.model.index(row_number, 0))
                    return

        def _export_evidence(self) -> None:
            if self._snapshot is None:
                ida_kernwin.warning("No workbench evidence is available to export.")
                return
            file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self.parent,
                "Export D810 workbench evidence",
                f"d810-workbench-{self._func_ea:X}.json",
                "JSON Files (*.json);;All Files (*)",
            )
            if not file_path:
                return
            try:
                pathlib.Path(file_path).write_text(
                    export_evidence_json(self._snapshot),
                    encoding="utf-8",
                )
                ida_kernwin.msg(
                    f"d810-ng: Exported workbench evidence to {file_path}\n"
                )
            except OSError as exc:
                logger.warning("Failed to export workbench evidence: %s", exc)
                ida_kernwin.warning(f"Failed to export workbench evidence: {exc}")


else:

    class DeobfuscationWorkbenchPanel:
        """Import-safe stub used outside IDA."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("DeobfuscationWorkbenchPanel requires IDA Pro")


__all__ = ["DeobfuscationWorkbenchPanel", "IDA_AVAILABLE"]
