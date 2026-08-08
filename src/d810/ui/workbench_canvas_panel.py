"""Dockable maturity canvas backed by the registered recipe adapter."""

from __future__ import annotations

import json

from d810.core import typing
from d810.core.logging import getLogger
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets, qt_flag_or
from d810.ui.workbench_canvas_graphics import (
    ReadOnlyDataflowScene,
    ReadOnlyDataflowView,
)
from d810.ui.workbench_canvas_logic import (
    linked_case_findings,
    project_maturity_canvas,
)
from d810.ui.workbench_canvas_palette import CanvasPassPickerPopup
from d810.ui.workbench_recipe_logic import (
    enables_dangerous_executable_readonly,
    should_accept_recipe_result,
)
from d810.ui.workbench_structured_details import NodeInspectorView
from d810.ui.workbench_structured_details_logic import (
    build_node_sections,
    parse_contract_detail,
)

logger = getLogger("d810.ui")

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


def evidence_summary_lines(
    snapshot: typing.Any,
    diagnostics: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Describe the current Build evidence without implying a case exists."""

    lines = _evidence_lines(snapshot)
    case = getattr(snapshot, "case", None)
    strategy = getattr(case, "strategy", None)
    strategy_summary = getattr(strategy, "summary", None)
    content = ["Build evidence"]
    if strategy_summary:
        content.extend(("", "Strategy", str(strategy_summary)))
    if lines:
        content.extend(("", "References", *lines))
    else:
        content.extend(
            (
                "",
                "Protection evidence",
                "No protection-specific case evidence captured yet.",
                "",
                "Pipeline state",
                "Generic cleanup pipeline - no protection-specific strategy or "
                "diagnostic lineage is available yet.",
            )
        )
    if diagnostics:
        content.extend(("", "Canvas diagnostics", *diagnostics))
    return tuple(content)


def _top_left_alignment() -> typing.Any:
    try:
        return qt_flag_or(
            QtCore.Qt.AlignmentFlag.AlignLeft,
            QtCore.Qt.AlignmentFlag.AlignTop,
        )
    except AttributeError:
        return qt_flag_or(QtCore.Qt.AlignLeft, QtCore.Qt.AlignTop)


def reset_canvas_view_origin(view: typing.Any) -> None:
    """Show the first maturity stage after a scene resize or fresh render."""

    for scroll_bar in (view.horizontalScrollBar(), view.verticalScrollBar()):
        scroll_bar.setValue(scroll_bar.minimum())


def stage_selector_presentation(
    stages: tuple[typing.Any, ...],
    selected_stage_id: str | None,
) -> tuple[str, str, bool]:
    """Describe whether selecting a maturity has a meaningful alternative."""

    selected = next(
        (stage for stage in stages if stage.stage_id == selected_stage_id),
        None,
    )
    if selected is None:
        return "Select maturity", "Choose a maturity stage", False
    if len(stages) == 1:
        if selected.stage_id == "any":
            return (
                "Any maturity - all active passes",
                "All active recipe nodes support Any maturity.",
                False,
            )
        return (
            f"{selected.label} - only available stage",
            "This recipe has one eligible maturity stage.",
            False,
        )
    return selected.label, "Maturity stage for add and collapse actions", True


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
            self._selected_stage: str | None = None
            self._add_palette: typing.Any = None
            self._closed = False
            self._fit_after_session = True
            self.parent: typing.Any = None

            self.evidence_summary = QtWidgets.QPlainTextEdit()
            self.evidence_summary.setReadOnly(True)
            self.evidence_summary.setPlaceholderText("No case evidence")
            self.node_inspector = NodeInspectorView()
            self.canvas_scene = ReadOnlyDataflowScene()
            self.canvas_view = ReadOnlyDataflowView(self.canvas_scene)
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

            self.stage_selector = QtWidgets.QToolButton()
            self.stage_selector.setToolTip(
                "Maturity stage for add and collapse actions"
            )
            self.stage_menu = QtWidgets.QMenu(self.stage_selector)
            self.stage_selector.setMenu(self.stage_menu)
            try:
                self.stage_selector.setPopupMode(
                    QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup
                )
            except AttributeError:
                self.stage_selector.setPopupMode(QtWidgets.QToolButton.InstantPopup)
            self.collapse_button = QtWidgets.QToolButton()
            self.collapse_button.setText("Collapse stage")
            self.fit_workspace_button = QtWidgets.QToolButton()
            self.fit_workspace_button.setText("Fit workspace")
            self.reset_zoom_button = QtWidgets.QToolButton()
            self.reset_zoom_button.setText("100%")
            self.add_registered_node_button = QtWidgets.QToolButton()
            self.add_registered_node_button.setText("Add registered node")
            self.edit_options_button = QtWidgets.QToolButton()
            self.edit_options_button.setText("Edit options")
            self.raw_contract_button = QtWidgets.QToolButton()
            self.raw_contract_button.setText("View pass contract")
            self.raw_contract_button.setToolTip(
                "View the read-only contract JSON for the selected node"
            )
            self.open_diagnostic_button = QtWidgets.QToolButton()
            self.open_diagnostic_button.setText("Open linked diagnostic")
            self.open_diagnostic_button.setEnabled(False)
            self.save_recipe_button = QtWidgets.QPushButton("Save for Deobfuscate This")

            self.collapse_button.clicked.connect(self._toggle_stage)
            self.fit_workspace_button.clicked.connect(self._fit_workspace)
            self.reset_zoom_button.clicked.connect(self._reset_zoom)
            self.add_registered_node_button.clicked.connect(self._show_add_palette)
            self.edit_options_button.clicked.connect(self._edit_selected_options)
            self.raw_contract_button.clicked.connect(self._show_selected_contract)
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
            self._fit_after_session = True
            self._render_evidence()
            self._render_projection()
            if self.parent is not None:
                self._fit_fresh_session()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)
            self._add_palette = CanvasPassPickerPopup(
                on_pass_selected=self._request_add_pass,
                parent=self.parent,
            )
            navigation_panel = QtWidgets.QWidget()
            navigation_controls = QtWidgets.QVBoxLayout()
            navigation_controls.setContentsMargins(0, 0, 0, 0)
            navigation_controls.setSpacing(4)
            navigation_controls.addWidget(self.stage_selector)
            navigation_controls.addWidget(self.collapse_button)
            navigation_controls.addWidget(self.fit_workspace_button)
            navigation_controls.addWidget(self.reset_zoom_button)
            navigation_controls.addWidget(self.add_registered_node_button)
            navigation_controls.addWidget(self.evidence_summary, stretch=1)
            navigation_panel.setLayout(navigation_controls)

            inspector_panel = QtWidgets.QWidget()
            inspector_layout = QtWidgets.QVBoxLayout()
            inspector_layout.setContentsMargins(0, 0, 0, 0)
            inspector_layout.setSpacing(4)
            inspector_controls = QtWidgets.QHBoxLayout()
            inspector_controls.setContentsMargins(0, 0, 0, 0)
            inspector_controls.setSpacing(4)
            inspector_controls.addWidget(self.edit_options_button)
            inspector_controls.addWidget(self.raw_contract_button)
            inspector_controls.addWidget(self.open_diagnostic_button)
            inspector_layout.addLayout(inspector_controls)
            inspector_layout.addWidget(self.node_inspector, stretch=1)
            inspector_layout.addWidget(self.save_recipe_button)
            inspector_panel.setLayout(inspector_layout)

            panes = QtWidgets.QSplitter()
            try:
                panes.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                panes.setOrientation(QtCore.Qt.Horizontal)
            panes.addWidget(navigation_panel)
            panes.addWidget(self.canvas_view)
            panes.addWidget(inspector_panel)
            panes.setStretchFactor(0, 1)
            panes.setStretchFactor(1, 4)
            panes.setStretchFactor(2, 2)
            panes.setSizes([220, 760, 320])

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(4)
            layout.addWidget(panes, stretch=1)
            self.canvas_view.setAlignment(_top_left_alignment())
            self._render_projection()

        def OnClose(self, form: typing.Any) -> None:
            del form
            palette = self._add_palette
            self._add_palette = None
            if palette is not None:
                palette.dispose()
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
                self._fit_fresh_session()
            return shown

        def _render_evidence(self) -> None:
            diagnostics = tuple(getattr(self._projection, "diagnostics", ()) or ())
            self.evidence_summary.setPlainText(
                "\n".join(evidence_summary_lines(self._snapshot, diagnostics))
            )

        def _render_projection(self) -> None:
            selected_stage = self._selected_stage
            self._projection = project_maturity_canvas(
                self._draft,
                self._catalog_entries,
                self._validation,
                getattr(self._snapshot, "case", None),
            )
            stages = tuple(self._projection.maturities)
            stage_ids = {stage.stage_id for stage in stages}
            self._selected_stage = (
                selected_stage
                if selected_stage in stage_ids
                else (stages[0].stage_id if stages else None)
            )
            self._rebuild_stage_menu()
            self.renderer.set_collapsed_stages(self._collapsed_stages)
            self.renderer.render(self._projection)
            self._update_collapse_label()
            self._render_evidence()
            if self._selected_node_id is not None:
                self._select_node(self._selected_node_id)

        def _fit_fresh_session(self) -> None:
            if not self._fit_after_session:
                return
            self.canvas_view.reset_to_workspace()
            self._fit_after_session = False

        def _fit_workspace(self, checked: bool = False) -> None:
            del checked
            self.canvas_view.fit_workspace()

        def _reset_zoom(self, checked: bool = False) -> None:
            del checked
            self.canvas_view.reset_zoom()

        def _selected_stage_id(self) -> str | None:
            return self._selected_stage

        def _rebuild_stage_menu(self) -> None:
            self.stage_menu.clear()
            stages = tuple(getattr(self._projection, "maturities", ()) or ())
            label, tooltip, has_choices = stage_selector_presentation(
                stages,
                self._selected_stage,
            )
            self.stage_selector.setText(label)
            self.stage_selector.setToolTip(tooltip)
            self.stage_selector.setMenu(self.stage_menu if has_choices else None)
            for stage in stages:
                action = self.stage_menu.addAction(stage.label)
                action.setCheckable(True)
                action.setChecked(stage.stage_id == self._selected_stage)
                action.triggered.connect(
                    lambda checked=False, stage_id=stage.stage_id: self._select_stage(
                        stage_id
                    )
                )

        def _select_stage(self, stage_id: str) -> None:
            if not any(
                stage.stage_id == str(stage_id)
                for stage in getattr(self._projection, "maturities", ())
            ):
                return
            self._selected_stage = str(stage_id)
            self._rebuild_stage_menu()
            self._update_collapse_label()

        def _update_collapse_label(self, ignored: typing.Any = None) -> None:
            del ignored
            stage_id = self._selected_stage_id()
            collapsed = stage_id is not None and stage_id in self._collapsed_stages
            self.collapse_button.setText(
                "Expand stage" if collapsed else "Collapse stage"
            )
            self.collapse_button.setEnabled(stage_id is not None)
            self.add_registered_node_button.setEnabled(stage_id is not None)

        def _show_selected_contract(self, checked: bool = False) -> None:
            del checked
            if self._selected_node_id is not None:
                self.node_inspector.show_contract_raw()

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
                self.node_inspector.show_empty(f"Add registered node failed: {exc}")
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
            self.raw_contract_button.setEnabled(node is not None)
            if node is None:
                self.open_diagnostic_button.setEnabled(False)
                self.node_inspector.show_empty()
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
            evidence_references = tuple(
                f"{finding.finding_id} @ 0x{finding.native_ea:X}: "
                f"{finding.summary}"
                for finding in findings
            )
            self.node_inspector.show_node(
                build_node_sections(node, evidence_references),
                options,
                parse_contract_detail(node.detail),
                editable_options=item is not None,
                on_options_changed=(
                    lambda updated, selected_node_id=node_id: self._update_node_options(
                        selected_node_id,
                        updated,
                    )
                ),
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
            self.node_inspector.show_options_raw()

        def _update_node_options(
            self,
            node_id: str | None,
            updated: object,
        ) -> None:
            item = self._selected_recipe_pass(node_id or "")
            if item is None or not isinstance(updated, dict):
                return
            current = self._options(item)
            if (
                enables_dangerous_executable_readonly(
                    item.pass_id,
                    current,
                    updated,
                )
                and not self._confirm_dangerous_options()
            ):
                self._select_node(node_id)
                return
            self.renderer.request_edit_options(node_id or "", updated)

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
                self.node_inspector.show_empty(f"Edit options failed: {exc}")
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
                self.node_inspector.show_empty(f"Save recipe failed: {exc}")
                return
            self.node_inspector.show_empty(result.message)
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
