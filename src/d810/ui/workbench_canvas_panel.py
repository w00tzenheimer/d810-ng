"""Dockable maturity canvas backed by the registered recipe adapter."""

from __future__ import annotations

import json

from d810.core import typing
from d810.core.logging import getLogger
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets
from d810.ui.workbench_canvas_logic import linked_case_findings, project_maturity_canvas
from d810.ui.workbench_canvas_palette import CanvasPassPickerPopup
from d810.ui.workbench_recipe_logic import (
    enables_dangerous_executable_readonly,
    should_accept_recipe_result,
)

logger = getLogger("D810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


def _evidence_lines(snapshot: typing.Any) -> tuple[str, ...]:
    case = getattr(snapshot, "case", None)
    evidence = getattr(case, "evidence", None)
    findings = tuple(getattr(evidence, "findings", ()) or ())
    lines: list[str] = []
    for finding in findings:
        native_ea = getattr(finding, "native_ea", None)
        anchor = "" if native_ea is None else f" @ 0x{int(native_ea):X}"
        provenance = ", ".join(getattr(finding, "provenance", ()) or ())
        lines.append(
            f"{getattr(finding, 'finding_id', 'finding')}{anchor}: "
            f"{getattr(finding, 'summary', '')}"
            + (f" [{provenance}]" if provenance else "")
        )
    return tuple(lines)


if IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE:
    from d810.ui.workbench_canvas_renderer import MaturityCanvasRenderer

    WOPN_NOT_CLOSED_BY_ESC = getattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100)

    class WorkbenchCanvasPanel(ida_kernwin.PluginForm):
        """Dense stage canvas; recipe mutation remains adapter-owned."""

        TITLE = "d810-ng Maturity Canvas"

        def __init__(
            self,
            adapter: typing.Any,
            snapshot: typing.Any,
            *,
            refresh_workbench: typing.Callable[[], None] | None = None,
            open_diagnostic_record: typing.Callable[[str, int], None] | None = None,
        ) -> None:
            ida_kernwin.PluginForm.__init__(self)
            self._adapter = adapter
            self._snapshot = snapshot
            self._refresh_workbench = refresh_workbench
            self._open_diagnostic_record = open_diagnostic_record
            self._collapsed_stages: set[str] = set()
            self._catalog_entries: tuple[typing.Any, ...] = ()
            self._draft: typing.Any = None
            self._validation: typing.Any = None
            self._projection: typing.Any = None
            self._selected_node_id: str | None = None
            self._selected_finding: typing.Any = None
            self._add_palette: typing.Any = None
            self._closed = False
            self.parent: typing.Any = None

            self.evidence_summary = QtWidgets.QPlainTextEdit()
            self.evidence_summary.setReadOnly(True)
            self.evidence_summary.setPlaceholderText("No case evidence")
            self.node_inspector = QtWidgets.QPlainTextEdit()
            self.node_inspector.setReadOnly(True)
            self.node_inspector.setPlaceholderText("Select a registered node")
            self.canvas_scene = QtWidgets.QGraphicsScene()
            self.canvas_view = QtWidgets.QGraphicsView(self.canvas_scene)
            self.canvas_view.setToolTip(
                "Automatic contract edges are read-only; select nodes to inspect"
            )
            self.renderer = MaturityCanvasRenderer(self.canvas_scene)
            self.renderer.bind_actions(
                self._select_node,
                self._add_pass,
                self._edit_options,
                self._save_recipe,
            )

            self.stage_selector = QtWidgets.QComboBox()
            self.stage_selector.setToolTip(
                "Maturity stage for add and collapse actions"
            )
            self.collapse_button = QtWidgets.QToolButton()
            self.collapse_button.setText("Collapse stage")
            self.add_registered_node_button = QtWidgets.QToolButton()
            self.add_registered_node_button.setText("Add registered node")
            self.edit_options_button = QtWidgets.QToolButton()
            self.edit_options_button.setText("Edit options")
            self.open_diagnostic_button = QtWidgets.QToolButton()
            self.open_diagnostic_button.setText("Open linked diagnostic")
            self.open_diagnostic_button.setEnabled(False)
            self.save_recipe_button = QtWidgets.QPushButton("Save for Deobfuscate This")

            self.stage_selector.currentIndexChanged.connect(self._update_collapse_label)
            self.collapse_button.clicked.connect(self._toggle_stage)
            self.add_registered_node_button.clicked.connect(self._show_add_palette)
            self.edit_options_button.clicked.connect(self._edit_selected_options)
            self.open_diagnostic_button.clicked.connect(self._open_selected_diagnostic)
            self.save_recipe_button.clicked.connect(
                lambda checked=False: self.renderer.request_save_recipe()
            )
            self.set_session(adapter, snapshot)

        def set_session(self, adapter: typing.Any, snapshot: typing.Any) -> None:
            """Replace the immutable Build session while keeping the dock."""
            self._adapter = adapter
            self._snapshot = snapshot
            self._catalog_entries = tuple(adapter.catalog())
            self._draft, self._validation = adapter.reset()
            self._selected_node_id = None
            self._selected_finding = None
            self._collapsed_stages.clear()
            self._render_evidence()
            self._render_projection()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)
            self._add_palette = CanvasPassPickerPopup(
                on_pass_selected=self._request_add_pass,
                parent=self.parent,
            )
            controls = QtWidgets.QHBoxLayout()
            controls.setContentsMargins(0, 0, 0, 0)
            controls.setSpacing(4)
            controls.addWidget(self.stage_selector)
            controls.addWidget(self.collapse_button)
            controls.addWidget(self.add_registered_node_button)
            controls.addWidget(self.edit_options_button)
            controls.addWidget(self.open_diagnostic_button)
            controls.addStretch(1)
            controls.addWidget(self.save_recipe_button)

            panes = QtWidgets.QSplitter()
            try:
                panes.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                panes.setOrientation(QtCore.Qt.Horizontal)
            panes.addWidget(self.evidence_summary)
            panes.addWidget(self.canvas_view)
            panes.addWidget(self.node_inspector)
            panes.setStretchFactor(0, 1)
            panes.setStretchFactor(1, 4)
            panes.setStretchFactor(2, 2)
            panes.setSizes([220, 760, 320])

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(4)
            layout.addLayout(controls)
            layout.addWidget(panes, stretch=1)
            self._render_projection()

        def OnClose(self, form: typing.Any) -> None:
            del form
            self._closed = True
            self.parent = None

        @property
        def closed(self) -> bool:
            return self._closed

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
                self._render_projection()
            return shown

        def _render_evidence(self) -> None:
            lines = _evidence_lines(self._snapshot)
            case = getattr(self._snapshot, "case", None)
            strategy = getattr(case, "strategy", None)
            strategy_summary = getattr(strategy, "summary", None)
            content = ["Build evidence"]
            if strategy_summary:
                content.extend(("", "Strategy", str(strategy_summary)))
            content.extend(("", "References"))
            content.extend(lines or ("No anchored case evidence",))
            diagnostics = tuple(getattr(self._projection, "diagnostics", ()) or ())
            if diagnostics:
                content.extend(("", "Canvas diagnostics", *diagnostics))
            self.evidence_summary.setPlainText("\n".join(content))

        def _render_projection(self) -> None:
            selected_stage = self.stage_selector.currentData()
            self._projection = project_maturity_canvas(
                self._draft,
                self._catalog_entries,
                self._validation,
                getattr(self._snapshot, "case", None),
            )
            self.stage_selector.blockSignals(True)
            self.stage_selector.clear()
            for stage in self._projection.maturities:
                self.stage_selector.addItem(stage.label, stage.stage_id)
            if selected_stage is not None:
                index = self.stage_selector.findData(selected_stage)
                if index >= 0:
                    self.stage_selector.setCurrentIndex(index)
            self.stage_selector.blockSignals(False)
            self.renderer.set_collapsed_stages(self._collapsed_stages)
            self.renderer.render(self._projection)
            self._update_collapse_label()
            self._render_evidence()
            if self._selected_node_id is not None:
                self._select_node(self._selected_node_id)

        def _selected_stage_id(self) -> str | None:
            value = self.stage_selector.currentData()
            return str(value) if value else None

        def _update_collapse_label(self, ignored: typing.Any = None) -> None:
            del ignored
            stage_id = self._selected_stage_id()
            collapsed = stage_id is not None and stage_id in self._collapsed_stages
            self.collapse_button.setText(
                "Expand stage" if collapsed else "Collapse stage"
            )
            self.collapse_button.setEnabled(stage_id is not None)
            self.add_registered_node_button.setEnabled(stage_id is not None)

        def _toggle_stage(self, checked: bool = False) -> None:
            del checked
            stage_id = self._selected_stage_id()
            if stage_id is None:
                return
            if stage_id in self._collapsed_stages:
                self._collapsed_stages.remove(stage_id)
            else:
                self._collapsed_stages.add(stage_id)
            self._render_projection()

        def _show_add_palette(self, checked: bool = False) -> None:
            del checked
            stage_id = self._selected_stage_id()
            if stage_id is None or self._add_palette is None:
                return
            self._add_palette.show_for(
                self.add_registered_node_button,
                self._catalog_entries,
                stage_id,
                self._draft,
            )

        def _request_add_pass(self, stage_id: str, pass_id: str) -> None:
            self.renderer.request_add_pass(stage_id, pass_id)

        def _add_pass(self, stage_id: str, pass_id: str) -> None:
            try:
                self._draft, self._validation = self._adapter.add_canvas_pass(
                    self._draft,
                    stage_id,
                    pass_id,
                )
            except Exception as exc:
                logger.warning("Canvas add failed: %s", exc)
                self.node_inspector.setPlainText(f"Add registered node failed: {exc}")
                return
            self._render_projection()

        def _selected_recipe_pass(self, node_id: str) -> typing.Any | None:
            return next(
                (item for item in self._draft.passes if item.item_id == node_id),
                None,
            )

        @staticmethod
        def _options(item: typing.Any) -> dict[str, object]:
            try:
                payload = json.loads(item.config_json)
            except (AttributeError, TypeError, json.JSONDecodeError):
                return {}
            options = payload.get("options", {}) if isinstance(payload, dict) else {}
            return dict(options) if isinstance(options, dict) else {}

        def _select_node(self, node_id: str | None) -> None:
            self._selected_node_id = node_id
            self._selected_finding = None
            node = next(
                (
                    value
                    for value in getattr(self._projection, "nodes", ())
                    if value.node_id == node_id
                ),
                None,
            )
            item = self._selected_recipe_pass(node_id or "")
            self.edit_options_button.setEnabled(item is not None)
            if node is None:
                self.open_diagnostic_button.setEnabled(False)
                self.node_inspector.setPlainText("")
                return
            findings = linked_case_findings(
                node,
                getattr(self._snapshot, "case", None),
            )
            self._selected_finding = findings[0] if findings else None
            self.open_diagnostic_button.setEnabled(
                self._selected_finding is not None
                and self._open_diagnostic_record is not None
            )
            options = self._options(item) if item is not None else {}
            prerequisites = [
                f"{port.artifact_type}: {port.label}" for port in node.inputs
            ]
            evidence_references = _evidence_lines(self._snapshot)
            self.node_inspector.setPlainText(
                "\n".join(
                    (
                        f"{node.label} ({node.pass_id})",
                        f"State: {node.state}",
                        "",
                        "Contract",
                        node.detail,
                        "",
                        "Options",
                        json.dumps(options, indent=2, sort_keys=True),
                        "",
                        "Prerequisites",
                        *(prerequisites or ("None",)),
                        "",
                        "Evidence references",
                        *(evidence_references or ("None",)),
                    )
                )
            )

        def _open_selected_diagnostic(self, checked: bool = False) -> None:
            del checked
            finding = self._selected_finding
            if finding is None or self._open_diagnostic_record is None:
                return
            self._open_diagnostic_record(
                str(finding.finding_id),
                int(finding.native_ea),
            )

        def _edit_selected_options(self, checked: bool = False) -> None:
            del checked
            node_id = self._selected_node_id
            item = self._selected_recipe_pass(node_id or "")
            if item is None:
                return
            current = self._options(item)
            text, accepted = QtWidgets.QInputDialog.getMultiLineText(
                self.parent,
                f"Structured options for {item.pass_id}",
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
                self.node_inspector.setPlainText(f"Invalid structured options: {exc}")
                return
            if (
                enables_dangerous_executable_readonly(
                    item.pass_id,
                    current,
                    options,
                )
                and not self._confirm_dangerous_options()
            ):
                return
            self.renderer.request_edit_options(node_id or "", options)

        def _confirm_dangerous_options(self) -> bool:
            try:
                yes = QtWidgets.QMessageBox.StandardButton.Yes
                no = QtWidgets.QMessageBox.StandardButton.No
            except AttributeError:
                yes = QtWidgets.QMessageBox.Yes
                no = QtWidgets.QMessageBox.No
            response = QtWidgets.QMessageBox.question(
                self.parent,
                "Confirm VERY DANGEROUS operation",
                "This can treat code or unresolved executable read-only bytes "
                "as constant data and produce incorrect decompilation.",
                yes | no,
                no,
            )
            return response == yes

        def _edit_options(
            self,
            node_id: str,
            options: dict[str, object],
        ) -> None:
            try:
                self._draft, self._validation = self._adapter.replace_options(
                    self._draft,
                    node_id,
                    options,
                )
            except Exception as exc:
                logger.warning("Canvas option edit failed: %s", exc)
                self.node_inspector.setPlainText(f"Edit options failed: {exc}")
                return
            self._render_projection()

        def _save_recipe(self) -> None:
            try:
                result = self._adapter.save_function(
                    self._draft,
                    self._validation,
                )
            except Exception as exc:
                logger.warning("Canvas recipe save failed: %s", exc)
                self.node_inspector.setPlainText(f"Save recipe failed: {exc}")
                return
            self.node_inspector.setPlainText(result.message)
            if (
                should_accept_recipe_result(self._draft, result)
                and result.refresh_requested
                and self._refresh_workbench is not None
            ):
                self._refresh_workbench()

else:

    class WorkbenchCanvasPanel:
        """Unavailable canvas placeholder for headless and idalib imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("The maturity canvas requires IDA GUI graphics support")


__all__ = ["WorkbenchCanvasPanel"]
