"""Thin IDA/Qt adapter for the read-only deobfuscation workbench."""

from __future__ import annotations

import pathlib

from d810.core import typing
from d810.core.logging import getLogger
from d810.manager.workbench_models import WorkbenchCommandResult
from d810.ui.workbench_logic import (
    WorkbenchActionState,
    WorkbenchRow,
    WorkbenchSection,
    action_states,
    command_request,
    comparison_view,
    detail_text,
    export_evidence_json,
    filter_workbench_rows,
    project_workbench_rows,
    should_accept_command_result,
    stale_snapshot,
)
from d810.ui.workbench_workflow_logic import project_workbench_workflow

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
            self._command_adapter: typing.Any = None
            self._comparison_dialog: typing.Any = None
            self._recipe_panel: typing.Any = None
            self._config_v2_editor: typing.Any = None
            self._diagnostics_panel: typing.Any = None
            self._workflow_running = False
            self._workflow_result: WorkbenchCommandResult | None = None
            self._workflow_comparison: typing.Any = None
            self._workflow_comparison_error: str | None = None
            self._workflow_primary_action_id = ""
            self._pending_post_run_refresh = False
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

            self.workflow_headline = QtWidgets.QLabel()
            self.workflow_detail = QtWidgets.QLabel()
            self.workflow_detail.setWordWrap(True)
            self.workflow_primary_button = QtWidgets.QPushButton()
            self.workflow_secondary_layout = QtWidgets.QHBoxLayout()
            self.workflow_secondary_buttons: dict[str, typing.Any] = {}
            for action_id in (
                "diagnostics",
                "recipe",
                "function_override",
                "compare",
            ):
                button = QtWidgets.QPushButton()
                self.workflow_secondary_buttons[action_id] = button
                self.workflow_secondary_layout.addWidget(button)
            self.workflow_secondary_layout.addStretch(1)

            self.action_buttons: dict[str, typing.Any] = {}
            action_layout = QtWidgets.QHBoxLayout()
            for action_id, label in (
                ("refresh", "Refresh"),
                ("export", "Export evidence"),
                ("analyze", "Analyze"),
                ("deobfuscate", "Deobfuscate"),
                ("function_override", "Function override"),
                ("compare", "Compare"),
                ("recipe", "Recipe"),
                ("diagnostics", "Diagnostics"),
            ):
                button = QtWidgets.QPushButton(label)
                self.action_buttons[action_id] = button
                if action_id != "deobfuscate":
                    action_layout.addWidget(button)
            action_layout.addStretch(1)
            self.action_layout = action_layout

            self.filter_edit.textChanged.connect(self._on_filter_changed)
            self.tree.selectionModel().selectionChanged.connect(
                self._on_selection_changed
            )
            self.action_buttons["refresh"].clicked.connect(self.refresh)
            self.action_buttons["export"].clicked.connect(self._export_evidence)
            for action_id in ("analyze", "deobfuscate", "function_override"):
                button = self.action_buttons[action_id]

                def _dispatch(
                    checked: bool = False,
                    *,
                    action_id: str = action_id,
                ) -> None:
                    del checked
                    self._run_command(action_id)

                button.clicked.connect(_dispatch)
            self.action_buttons["compare"].clicked.connect(self._run_comparison)
            self.action_buttons["recipe"].clicked.connect(self._run_recipe)
            self.action_buttons["diagnostics"].clicked.connect(self._run_diagnostics)
            self.workflow_primary_button.clicked.connect(
                self._run_workflow_primary_action
            )
            self.workflow_secondary_buttons["diagnostics"].clicked.connect(
                self._run_diagnostics
            )
            self.workflow_secondary_buttons["recipe"].clicked.connect(
                self._run_recipe
            )
            self.workflow_secondary_buttons["function_override"].clicked.connect(
                self._run_function_override
            )
            self.workflow_secondary_buttons["compare"].clicked.connect(
                self._run_comparison
            )

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            context_group = QtWidgets.QGroupBox("Function", self.parent)
            context_layout = QtWidgets.QFormLayout(context_group)
            context_layout.addRow("Function:", self.function_label)
            context_layout.addRow("Runtime:", self.runtime_label)
            context_layout.addRow("Attack:", self.attack_label)

            attack_group = QtWidgets.QGroupBox("Attack", self.parent)
            attack_layout = QtWidgets.QVBoxLayout(attack_group)
            attack_layout.addWidget(self.workflow_headline)
            attack_layout.addWidget(self.workflow_detail)
            attack_layout.addWidget(self.workflow_primary_button)
            attack_layout.addLayout(self.workflow_secondary_layout)

            advanced_group = QtWidgets.QGroupBox("Advanced", self.parent)
            advanced_layout = QtWidgets.QVBoxLayout(advanced_group)
            advanced_layout.addLayout(self.action_layout)

            splitter = QtWidgets.QSplitter()
            try:
                splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                splitter.setOrientation(QtCore.Qt.Horizontal)
            splitter.addWidget(self.tree)
            splitter.addWidget(self.detail)
            splitter.setStretchFactor(0, 3)
            splitter.setStretchFactor(1, 2)

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(6)
            layout.addWidget(context_group)
            layout.addWidget(attack_group)
            layout.addWidget(self.filter_edit)
            layout.addWidget(splitter, stretch=1)
            layout.addWidget(advanced_group)

            self.tree.header().setStretchLastSection(True)
            for column in range(3):
                self.tree.resizeColumnToContents(column)
            self._render_rows(self._visible_rows)
            self._render_workflow()

        def OnClose(self, form: typing.Any) -> None:
            del form
            self._closed = True
            try:
                self.filter_edit.textChanged.disconnect()
                self.tree.selectionModel().selectionChanged.disconnect()
                for action_id in (
                    "refresh",
                    "export",
                    "analyze",
                    "deobfuscate",
                    "function_override",
                    "compare",
                    "recipe",
                    "diagnostics",
                ):
                    self.action_buttons[action_id].clicked.disconnect()
                self.workflow_primary_button.clicked.disconnect()
                for button in self.workflow_secondary_buttons.values():
                    button.clicked.disconnect()
            except (RuntimeError, TypeError):
                pass
            if self._comparison_dialog is not None:
                self._comparison_dialog.close()
                self._comparison_dialog = None
            if self._recipe_panel is not None:
                self._recipe_panel.close()
                self._recipe_panel = None
            if self._config_v2_editor is not None:
                self._config_v2_editor.close()
                self._config_v2_editor = None
            if self._diagnostics_panel is not None:
                self._diagnostics_panel.close()
                self._diagnostics_panel = None
            self.parent = None

        def close(self) -> None:
            """Close the owned dock before its action module is unloaded."""
            if self._closed:
                return
            self._closed = True
            if self.GetWidget() is None:
                self.parent = None
                return
            self.Close(ida_kernwin.PluginForm.WCLS_SAVE)

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

        def set_command_adapter(self, adapter: typing.Any) -> None:
            self._command_adapter = adapter

        def _run_command(
            self,
            action_id: str,
            *,
            refresh_after: bool = True,
        ) -> WorkbenchCommandResult | None:
            snapshot = self._snapshot
            adapter = self._command_adapter
            if snapshot is None or adapter is None:
                return None
            handler = getattr(adapter, action_id, None)
            if not callable(handler):
                return None

            request = command_request(snapshot, action_id)
            stale = stale_snapshot(snapshot)
            stale_rows = project_workbench_rows(stale)
            self._snapshot = stale
            self._rows = stale_rows
            self._visible_rows = filter_workbench_rows(
                stale_rows,
                self.filter_edit.text(),
            )
            self._row_by_key = {row.key: row for row in stale_rows}
            self._render_context()
            self._render_rows(self._visible_rows)
            self._render_action_states(action_states(stale))
            self._render_workflow()

            try:
                result = handler(request)
            except Exception as exc:
                logger.warning("Workbench command %s failed: %s", action_id, exc)
                self.detail.setPlainText(f"{action_id} failed: {exc}")
                return None

            if not should_accept_command_result(snapshot, result):
                self.detail.setPlainText(result.message)
                return result
            if result.refresh_requested and refresh_after:
                self.refresh()
            else:
                self.detail.setPlainText(result.message)
            return result

        def _run_recommended_attack(self, checked: bool = False) -> None:
            del checked
            snapshot = self._snapshot
            self._workflow_running = True
            self._render_workflow()
            result = self._run_command("deobfuscate", refresh_after=False)
            self._workflow_running = False
            self._workflow_result = result
            self._workflow_comparison = None
            self._workflow_comparison_error = None
            if (
                snapshot is not None
                and result is not None
                and should_accept_command_result(snapshot, result)
                and result.refresh_requested
            ):
                self._pending_post_run_refresh = True
                try:
                    self.refresh()
                finally:
                    self._pending_post_run_refresh = False
                self._run_comparison()
            self._render_workflow()

        def _run_function_override(self, checked: bool = False) -> None:
            del checked
            self._run_command("function_override")

        def _run_workflow_primary_action(self, checked: bool = False) -> None:
            del checked
            if self._workflow_primary_action_id == "deobfuscate":
                self._run_recommended_attack()
            elif self._workflow_primary_action_id == "compare":
                if (
                    self._workflow_comparison is not None
                    and self._workflow_comparison_error is None
                ):
                    self._show_comparison(self._workflow_comparison)
                else:
                    self._run_comparison()
            elif self._workflow_primary_action_id == "diagnostics":
                self._run_diagnostics()

        def _run_comparison(self, checked: bool = False) -> None:
            del checked
            snapshot = self._snapshot
            adapter = self._command_adapter
            if snapshot is None or adapter is None:
                self._workflow_comparison = None
                self._workflow_comparison_error = (
                    "Comparison adapter is not available for the current function."
                )
                self._render_workflow()
                return
            compare = getattr(adapter, "compare", None)
            if not callable(compare):
                self._workflow_comparison = None
                self._workflow_comparison_error = "Comparison capture is unavailable."
                self._render_workflow()
                return
            try:
                view = comparison_view(compare(snapshot))
            except Exception as exc:
                logger.warning("Workbench comparison failed: %s", exc)
                self.detail.setPlainText(f"Compare failed: {exc}")
                self._workflow_comparison = None
                self._workflow_comparison_error = f"Compare failed: {exc}"
                self._render_workflow()
                return
            self._workflow_comparison = view
            self._workflow_comparison_error = None
            self._render_workflow()
            self._show_comparison(view)

        def _show_comparison(self, view: typing.Any) -> None:
            from d810.ui.workbench_comparison_dialog import (
                WorkbenchComparisonDialog,
            )

            if self._comparison_dialog is not None:
                self._comparison_dialog.close()
            dialog = WorkbenchComparisonDialog(view, parent=self.parent)
            self._comparison_dialog = dialog
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()

        def _run_recipe(self, checked: bool = False) -> None:
            del checked
            snapshot = self._snapshot
            adapter = self._command_adapter
            if snapshot is None or adapter is None:
                return
            recipe = getattr(adapter, "recipe", None)
            if not callable(recipe):
                return
            try:
                recipe_adapter = recipe(snapshot)
            except Exception as exc:
                logger.warning("Recipe Composer failed: %s", exc)
                self.detail.setPlainText(f"Recipe Composer failed: {exc}")
                return
            self._show_recipe(recipe_adapter)

        def _show_recipe(self, recipe_adapter: typing.Any) -> None:
            from d810.ui.workbench_recipe_panel import WorkbenchRecipePanel

            if self._recipe_panel is not None:
                self._recipe_panel.close()
            panel = WorkbenchRecipePanel(
                recipe_adapter,
                refresh_workbench=self.refresh,
                open_project_profile=self._open_recipe_project_profile,
            )
            self._recipe_panel = panel
            panel.show()

        def _run_diagnostics(self, checked: bool = False) -> None:
            del checked
            from d810.ui.workbench_diagnostics_commands import (
                WorkbenchDiagnosticsAdapter,
            )

            adapter = WorkbenchDiagnosticsAdapter(
                self._state,
                navigate=ida_kernwin.jumpto,
            )
            self._show_diagnostics(adapter)

        def _show_diagnostics(self, adapter: typing.Any) -> None:
            from d810.ui.workbench_diagnostics_graph import (
                create_ida_diagnostic_graph_controller,
            )
            from d810.ui.workbench_diagnostics_panel import (
                WorkbenchDiagnosticsPanel,
            )

            if self._diagnostics_panel is not None:
                self._diagnostics_panel.close()
            controller = create_ida_diagnostic_graph_controller(adapter)
            panel = WorkbenchDiagnosticsPanel(
                adapter,
                function_ea=self._func_ea,
                function_name=self._func_name or None,
                graph_controller=controller,
            )
            self._diagnostics_panel = panel
            panel.show()

        def _open_recipe_project_profile(self, recipe: typing.Any) -> None:
            from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter
            from d810.ui.config_v2_editing_panel import ConfigV2EditingPanel

            config_dir = pathlib.Path(self._state.d810_config.config_dir)
            default = config_dir / f"recipe_{int(recipe.function_ea):X}.json"
            destination, _ = QtWidgets.QFileDialog.getSaveFileName(
                self.parent,
                "Save recipe as a config-v2 project profile",
                str(default),
                "D810 project configurations (*.json)",
            )
            if not destination:
                return
            try:
                adapter = ConfigV2EditingAdapter(
                    self._state,
                    destination=pathlib.Path(destination),
                    recipe=recipe,
                )
                if self._config_v2_editor is not None:
                    self._config_v2_editor.close()
                editor = ConfigV2EditingPanel(
                    adapter,
                    on_saved=self.refresh,
                )
            except Exception as exc:
                logger.warning("Config-v2 project editor failed: %s", exc)
                self.detail.setPlainText(f"Project profile editor failed: {exc}")
                return
            self._config_v2_editor = editor
            editor.show()

        def refresh(self) -> None:
            if self._func_ea is None:
                self._clear_workflow_state()
                self._snapshot = None
                self._rows = ()
                self._visible_rows = ()
                self._row_by_key = {}
                self.function_label.setText("No function selected")
                self.runtime_label.setText("No runtime project")
                self.attack_label.setText("Attack: not analyzed")
                self._render_rows(())
                self._render_action_states(())
                self._render_workflow()
                return

            previous_identity = self._workflow_snapshot_identity(self._snapshot)
            snapshot = self._state.get_workbench_snapshot(
                self._func_ea,
                self._func_name,
                self._fingerprint,
            )
            current_identity = self._workflow_snapshot_identity(snapshot)
            if (
                previous_identity is not None
                and previous_identity != current_identity
                and not self._pending_post_run_refresh
            ):
                self._clear_workflow_state()
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
            self._render_workflow()
            self._focus_section(self._pending_focus)

        @staticmethod
        def _workflow_snapshot_identity(snapshot: typing.Any) -> typing.Any:
            if snapshot is None:
                return None
            return (
                snapshot.function.ea,
                snapshot.function.fingerprint,
                snapshot.generation,
            )

        def _clear_workflow_state(self) -> None:
            self._workflow_running = False
            self._workflow_result = None
            self._workflow_comparison = None
            self._workflow_comparison_error = None

        def _render_workflow(self) -> None:
            view = project_workbench_workflow(
                self._snapshot,
                comparison=self._workflow_comparison,
                last_result=self._workflow_result,
                running=self._workflow_running,
                comparison_error=self._workflow_comparison_error,
            )
            self.workflow_headline.setText(view.headline)
            self.workflow_detail.setText(view.detail)
            self._workflow_primary_action_id = view.primary.action_id
            self.workflow_primary_button.setText(view.primary.label)
            self.workflow_primary_button.setEnabled(view.primary.enabled)
            self.workflow_primary_button.setToolTip(view.primary.reason)

            secondary_by_id = {
                action.action_id: action for action in view.secondary
            }
            for action_id, button in self.workflow_secondary_buttons.items():
                action = secondary_by_id.get(action_id)
                button.setVisible(action is not None)
                if action is None:
                    button.setText("")
                    button.setEnabled(False)
                    button.setToolTip("")
                    continue
                button.setText(action.label)
                button.setEnabled(action.enabled)
                button.setToolTip(action.reason)

        def _render_context(self) -> None:
            snapshot = self._snapshot
            if snapshot is None:
                return
            function_name = snapshot.function.name or f"sub_{snapshot.function.ea:X}"
            self.function_label.setText(
                f"{function_name} @ 0x{snapshot.function.ea:X} "
                f"(generation {snapshot.generation})"
            )
            routed = (
                " routed from " + snapshot.runtime.source_name
                if snapshot.runtime.routed
                else ""
            )
            self.runtime_label.setText(
                f"{snapshot.runtime.runtime_name}{routed} " f"[{snapshot.runtime.mode}]"
            )
            confidence = (
                "unavailable"
                if snapshot.attack.confidence is None
                else f"{snapshot.attack.confidence:.2f}"
            )
            self.attack_label.setText(
                f"{snapshot.attack.observed_shape}; "
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
