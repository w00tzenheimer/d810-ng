"""Primary dock for building and running one function deobfuscator.

The manager-owned Workbench remains the command authority.  This panel only
renders the current Build session and asks the Workbench to perform Build,
Deobfuscate, or diagnostic navigation actions.
"""

from __future__ import annotations

from d810.core import typing
from d810.core.logging import getLogger
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets
from d810.ui.workbench_build_workspace_logic import build_workspace_projection
from d810.ui.workbench_canvas_panel import (
    IDA_AVAILABLE,
    WorkbenchCanvasPanel,
    _top_left_alignment,
    ida_kernwin,
    reset_canvas_view_origin,
)
from d810.ui.workbench_recipe_logic import (
    should_accept_recipe_result,
)
from d810.ui.workbench_structured_details import StructuredDetailsView
from d810.ui.workbench_structured_details_logic import build_dossier_sections
from d810.ui.workbench_workspace_layout_logic import (
    WorkspaceRailState,
    collapse_rail,
    default_workspace_rail_state,
    expand_rail,
    splitter_sizes,
)
from d810.ui.workbench_workspace_rail import CollapsibleWorkspaceRail


logger = getLogger("d810.ui")


def _horizontal_orientation() -> typing.Any:
    try:
        return QtCore.Qt.Orientation.Horizontal
    except AttributeError:
        return QtCore.Qt.Horizontal


if IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE:

    class BuildDeobfuscatorPanel(WorkbenchCanvasPanel):
        """Dense function dossier, maturity timeline, and selected-node inspector."""

        TITLE = "D810-ng Build Deobfuscator"

        def __init__(
            self,
            adapter: typing.Any,
            snapshot: typing.Any,
            *,
            refresh_build: typing.Callable[[], None] | None = None,
            deobfuscate_function: typing.Callable[[], None] | None = None,
            open_diagnostics: typing.Callable[[], None] | None = None,
            refresh_workbench: typing.Callable[[], None] | None = None,
            open_diagnostic_record: typing.Callable[[str, int], None] | None = None,
        ) -> None:
            self._refresh_build = refresh_build
            self._deobfuscate_function = deobfuscate_function
            self._open_diagnostics = open_diagnostics
            self._workspace_chrome_ready = False
            self._unsubscribe_capture: typing.Callable[[], None] = lambda: None
            self._applying_rail_sizes = False
            self._workspace_settings = QtCore.QSettings(
                "D810",
                "BuildDeobfuscatorWorkspace",
            )
            self._rail_state = self._load_rail_state()
            super().__init__(
                adapter,
                snapshot,
                refresh_workbench=refresh_workbench,
                open_diagnostic_record=open_diagnostic_record,
            )
            subscribe_capture = getattr(adapter, "subscribe_diagnostics_capture", None)
            if callable(subscribe_capture):
                self._unsubscribe_capture = subscribe_capture(self._capture_state_changed)

            self.function_header_label = QtWidgets.QLabel()
            self.protection_header_label = QtWidgets.QLabel()
            self.build_deobfuscator_button = QtWidgets.QPushButton(
                "Build Deobfuscator"
            )
            self.deobfuscate_function_button = QtWidgets.QPushButton(
                "Deobfuscate Function"
            )
            self.diagnostics_button = QtWidgets.QToolButton()
            self.diagnostics_button.setText("Diagnostics")
            self.workspace_layout_button = QtWidgets.QToolButton()
            self.workspace_layout_button.setText("Workspace")
            self.dossier_panel = StructuredDetailsView()
            self.dossier_panel.setMinimumWidth(0)
            self.timeline_view = self.canvas_view
            self.timeline_view.setMinimumWidth(350)
            self.inspector_panel = QtWidgets.QWidget()
            self.node_inspector.setMinimumWidth(0)
            self.left_rail: typing.Any = None
            self.right_rail: typing.Any = None
            self.footer_capture_label = QtWidgets.QLabel()
            self.footer_maturity_label = QtWidgets.QLabel()
            self.footer_project_label = QtWidgets.QLabel()
            self.footer_engine_label = QtWidgets.QLabel()

            self.build_deobfuscator_button.clicked.connect(self._request_build)
            self.deobfuscate_function_button.clicked.connect(self._request_deobfuscate)
            self.diagnostics_button.clicked.connect(self._request_open_diagnostics)
            self._workspace_chrome_ready = True
            self._render_projection()

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)
            self._add_palette = self._create_add_palette()

            header_layout = QtWidgets.QHBoxLayout()
            header_layout.setContentsMargins(0, 0, 0, 0)
            header_layout.setSpacing(8)
            header_layout.addWidget(self.function_header_label, stretch=1)
            header_layout.addWidget(self.protection_header_label)
            header_layout.addWidget(self.deobfuscate_function_button)
            header_layout.addWidget(self.build_deobfuscator_button)
            header_layout.addWidget(self.diagnostics_button)
            self.workspace_layout_menu = QtWidgets.QMenu(self.workspace_layout_button)
            self.workspace_layout_menu.addAction(
                "Float workspace",
                self._float_workspace,
            )
            self.workspace_layout_menu.addAction(
                "Dock workspace",
                self._dock_workspace,
            )
            self.workspace_layout_menu.addAction(
                "Reset workspace layout",
                self._reset_workspace_layout,
            )
            self.workspace_layout_button.setMenu(self.workspace_layout_menu)
            try:
                self.workspace_layout_button.setPopupMode(
                    QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup
                )
            except AttributeError:
                self.workspace_layout_button.setPopupMode(
                    QtWidgets.QToolButton.InstantPopup
                )
            header_layout.addWidget(self.workspace_layout_button)

            dossier_container = QtWidgets.QWidget()
            dossier_layout = QtWidgets.QVBoxLayout()
            dossier_layout.setContentsMargins(0, 0, 0, 0)
            dossier_layout.setSpacing(4)
            dossier_layout.addWidget(self.dossier_panel, stretch=1)
            self.stage_selector.setToolTip("Show nodes for one Hex-Rays maturity")
            self.add_registered_node_button.setText("Add node")
            self.add_registered_node_button.setToolTip(
                "Add a legal registered node to the selected maturity"
            )
            self.collapse_button.setToolTip(
                "Collapse or expand the selected maturity stage"
            )
            self.fit_workspace_button.setToolTip("Fit all visible stages in the workspace")
            self.reset_zoom_button.setToolTip("Reset workspace zoom to 100%")
            canvas_controls = QtWidgets.QGridLayout()
            canvas_controls.setContentsMargins(0, 0, 0, 0)
            canvas_controls.setSpacing(4)
            canvas_controls.setColumnStretch(0, 1)
            canvas_controls.setColumnStretch(1, 1)
            canvas_controls.addWidget(self.stage_selector, 0, 0, 1, 2)
            canvas_controls.addWidget(self.collapse_button, 1, 0)
            canvas_controls.addWidget(self.add_registered_node_button, 1, 1)
            canvas_controls.addWidget(self.fit_workspace_button, 2, 0)
            canvas_controls.addWidget(self.reset_zoom_button, 2, 1)
            dossier_layout.addLayout(canvas_controls)
            dossier_container.setLayout(dossier_layout)

            inspector_layout = QtWidgets.QVBoxLayout()
            inspector_layout.setContentsMargins(0, 0, 0, 0)
            inspector_layout.setSpacing(4)
            inspector_controls = QtWidgets.QHBoxLayout()
            inspector_controls.setContentsMargins(0, 0, 0, 0)
            inspector_controls.setSpacing(4)
            inspector_controls.addWidget(self.edit_options_button)
            inspector_controls.addWidget(self.raw_contract_button)
            inspector_layout.addLayout(inspector_controls)
            inspector_diagnostic_controls = QtWidgets.QHBoxLayout()
            inspector_diagnostic_controls.setContentsMargins(0, 0, 0, 0)
            inspector_diagnostic_controls.setSpacing(4)
            inspector_diagnostic_controls.addWidget(self.open_diagnostic_button)
            inspector_diagnostic_controls.addStretch(1)
            inspector_layout.addLayout(inspector_diagnostic_controls)
            inspector_layout.addWidget(self.node_inspector, stretch=1)
            inspector_layout.addWidget(self.save_recipe_button)
            self.inspector_panel.setLayout(inspector_layout)

            self.left_rail = CollapsibleWorkspaceRail(
                "Function",
                dossier_container,
                minimum_width=190,
                preferred_width=self._rail_state.left_width,
                on_expanded_changed=self._on_left_rail_expanded_changed,
            )
            self.right_rail = CollapsibleWorkspaceRail(
                "Inspector",
                self.inspector_panel,
                minimum_width=220,
                preferred_width=self._rail_state.right_width,
                on_expanded_changed=self._on_right_rail_expanded_changed,
            )

            panes = QtWidgets.QSplitter()
            panes.setOrientation(_horizontal_orientation())
            panes.addWidget(self.left_rail)
            panes.addWidget(self.timeline_view)
            panes.addWidget(self.right_rail)
            panes.setStretchFactor(0, 1)
            panes.setStretchFactor(1, 5)
            panes.setStretchFactor(2, 2)
            panes.setChildrenCollapsible(False)
            panes.setSizes(list(splitter_sizes(self._rail_state, center_width=800)))
            panes.splitterMoved.connect(self._remember_rail_widths)
            self.workspace_splitter = panes
            if not self._rail_state.left_expanded:
                self.left_rail.set_expanded(False)
            if not self._rail_state.right_expanded:
                self.right_rail.set_expanded(False)

            footer_layout = QtWidgets.QHBoxLayout()
            footer_layout.setContentsMargins(0, 0, 0, 0)
            footer_layout.setSpacing(12)
            footer_layout.addWidget(self.footer_capture_label)
            footer_layout.addWidget(self.footer_maturity_label)
            footer_layout.addStretch(1)
            footer_layout.addWidget(self.footer_project_label)
            footer_layout.addWidget(self.footer_engine_label)

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(4)
            layout.addLayout(header_layout)
            layout.addWidget(panes, stretch=1)
            layout.addLayout(footer_layout)
            self.timeline_view.setAlignment(_top_left_alignment())
            self._render_workspace_chrome()
            self._render_projection()

        def show(self) -> bool:
            """Open wide on first use, then leave placement to IDA persistence."""

            options = ida_kernwin.PluginForm.WOPN_PERSIST
            if not self._workspace_initialized():
                options |= getattr(ida_kernwin, "WOPN_DP_FLOATING", 0)
                options |= getattr(ida_kernwin, "WOPN_DP_SZHINT", 0)
            shown = ida_kernwin.PluginForm.Show(self, self.TITLE, options=options)
            if shown:
                ida_kernwin.display_widget(
                    self.GetWidget(),
                    getattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100),
                    None,
                )
                if not self._workspace_initialized():
                    self._float_workspace()
                    # Some IDA/X11 combinations restore a minimum-size child
                    # widget before applying set_dock_pos() to the floating
                    # shell.  Size the actual form window as well so a first
                    # Build session is useful immediately, not a narrow rail.
                    self.parent.window().resize(1500, 980)
                    self._workspace_settings.setValue("initialized", True)
                self._render_projection()
                self._fit_fresh_session()
            return shown

        def _workspace_initialized(self) -> bool:
            value = self._workspace_settings.value("initialized", False)
            if isinstance(value, str):
                return value.strip().casefold() in {"1", "true", "yes"}
            return bool(value)

        def _settings_bool(self, key: str, default: bool) -> bool:
            value = self._workspace_settings.value(key, default)
            if isinstance(value, str):
                return value.strip().casefold() in {"1", "true", "yes"}
            return bool(value)

        def _settings_int(self, key: str, default: int) -> int:
            try:
                return max(1, int(self._workspace_settings.value(key, default)))
            except (TypeError, ValueError):
                return default

        def _load_rail_state(self) -> WorkspaceRailState:
            defaults = default_workspace_rail_state()
            return WorkspaceRailState(
                left_expanded=self._settings_bool("left_expanded", defaults.left_expanded),
                right_expanded=self._settings_bool(
                    "right_expanded",
                    defaults.right_expanded,
                ),
                left_width=self._settings_int("left_width", defaults.left_width),
                right_width=self._settings_int("right_width", defaults.right_width),
            )

        def _save_rail_state(self) -> None:
            self._workspace_settings.setValue(
                "left_expanded",
                self._rail_state.left_expanded,
            )
            self._workspace_settings.setValue(
                "right_expanded",
                self._rail_state.right_expanded,
            )
            self._workspace_settings.setValue("left_width", self._rail_state.left_width)
            self._workspace_settings.setValue("right_width", self._rail_state.right_width)

        def _float_workspace(self, checked: bool = False) -> None:
            del checked
            ida_kernwin.set_dock_pos(
                self.TITLE,
                None,
                ida_kernwin.DP_FLOATING,
                80,
                60,
                1500,
                980,
            )

        def _dock_workspace(self, checked: bool = False) -> None:
            del checked
            ida_kernwin.set_dock_pos(
                self.TITLE,
                "IDA View-A",
                ida_kernwin.DP_TAB,
            )

        def _reset_workspace_layout(self, checked: bool = False) -> None:
            del checked
            defaults = default_workspace_rail_state()
            self._rail_state = defaults
            for key in (
                "initialized",
                "left_expanded",
                "right_expanded",
                "left_width",
                "right_width",
            ):
                self._workspace_settings.remove(key)
            if self.left_rail is not None:
                self.left_rail.set_preferred_width(defaults.left_width)
                self.left_rail.set_expanded(defaults.left_expanded)
            if self.right_rail is not None:
                self.right_rail.set_preferred_width(defaults.right_width)
                self.right_rail.set_expanded(defaults.right_expanded)
            self._apply_rail_sizes()
            self._float_workspace()
            self._workspace_settings.setValue("initialized", True)

        def _create_add_palette(self) -> typing.Any:
            from d810.ui.workbench_canvas_palette import CanvasPassPickerPopup

            return CanvasPassPickerPopup(
                on_pass_selected=self._request_add_pass,
                parent=self.parent,
            )

        def _render_projection(self) -> None:
            super()._render_projection()
            if self._workspace_chrome_ready:
                self._render_workspace_chrome()

        def _render_workspace_chrome(self) -> None:
            projection = build_workspace_projection(
                self._snapshot,
                self._projection,
                diagnostics_capture_enabled=bool(
                    getattr(self._adapter, "diagnostics_capture_enabled", lambda: False)()
                ),
            )
            header = projection.header
            dossier = projection.dossier
            footer = projection.footer
            self.function_header_label.setText(f"Function: {header.function_label}")
            self.protection_header_label.setText(f"Protection: {header.protection_label}")
            self.deobfuscate_function_button.setEnabled(header.deobfuscate_enabled)
            self.deobfuscate_function_button.setToolTip(header.deobfuscate_reason)
            self.dossier_panel.set_sections(build_dossier_sections(dossier))
            self.footer_capture_label.setText(footer.diagnostics_capture)
            self.footer_maturity_label.setText(footer.maturity_summary)
            self.footer_project_label.setText(footer.project_summary)
            self.footer_engine_label.setText(footer.engine_summary)

        def _capture_state_changed(self, _enabled: bool) -> None:
            if self._workspace_chrome_ready:
                self._render_workspace_chrome()

        def OnClose(self, form: typing.Any) -> None:
            self._unsubscribe_capture()
            super().OnClose(form)

        def _on_left_rail_expanded_changed(
            self,
            expanded: bool,
            width: int,
        ) -> None:
            if expanded:
                self._rail_state = expand_rail(self._rail_state, "left")
            else:
                self._rail_state = collapse_rail(
                    self._rail_state,
                    "left",
                    current_width=width,
                )
            self._apply_rail_sizes()
            self._save_rail_state()

        def _on_right_rail_expanded_changed(
            self,
            expanded: bool,
            width: int,
        ) -> None:
            if expanded:
                self._rail_state = expand_rail(self._rail_state, "right")
            else:
                self._rail_state = collapse_rail(
                    self._rail_state,
                    "right",
                    current_width=width,
                )
            self._apply_rail_sizes()
            self._save_rail_state()

        def _apply_rail_sizes(self) -> None:
            if getattr(self, "workspace_splitter", None) is None:
                return
            # QSplitter emits splitterMoved() for programmatic sizing too.
            # Those moves redistribute an unavailable canvas width and must
            # never overwrite the rail width that the user asked us to retain.
            self._applying_rail_sizes = True
            try:
                self.workspace_splitter.setSizes(
                    list(splitter_sizes(self._rail_state, center_width=800))
                )
            finally:
                self._applying_rail_sizes = False

        def _remember_rail_widths(self, position: int, index: int) -> None:
            del position, index
            if (
                getattr(self, "workspace_splitter", None) is None
                or self._applying_rail_sizes
            ):
                return
            left, _center, right = self.workspace_splitter.sizes()
            if self.left_rail is not None:
                self.left_rail.remember_width(left)
            if self.right_rail is not None:
                self.right_rail.remember_width(right)
            self._rail_state = WorkspaceRailState(
                left_expanded=self.left_rail.expanded,
                right_expanded=self.right_rail.expanded,
                left_width=self.left_rail.expanded_width,
                right_width=self.right_rail.expanded_width,
            )
            self._save_rail_state()

        def _fit_fresh_session(self) -> None:
            """Start the vertical timeline at native card scale, not a tiny fit."""

            if not self._fit_after_session:
                return
            self.canvas_view.reset_zoom()
            reset_canvas_view_origin(self.canvas_view)
            self._fit_after_session = False

        def _request_build(self, checked: bool = False) -> None:
            del checked
            if self._refresh_build is not None:
                self._refresh_build()

        def _request_deobfuscate(self, checked: bool = False) -> None:
            del checked
            if self.deobfuscate_function_button.isEnabled() and self._deobfuscate_function is not None:
                self._deobfuscate_function()

        def _request_open_diagnostics(self, checked: bool = False) -> None:
            del checked
            if self._open_diagnostics is not None:
                self._open_diagnostics()

        def _add_pass(self, stage_id: str, pass_id: str) -> None:
            was_empty = not self._draft.passes
            try:
                self._draft, self._validation = self._adapter.add_canvas_pass(
                    self._draft,
                    stage_id,
                    pass_id,
                )
            except Exception as exc:
                logger.warning("Build workspace add failed: %s", exc)
                self.node_inspector.show_empty(f"Add registered node failed: {exc}")
                return
            self._render_projection()
            if was_empty:
                self.canvas_view.reset_zoom()
                reset_canvas_view_origin(self.canvas_view)

        def _edit_options(self, node_id: str, options: dict[str, object]) -> None:
            try:
                self._draft, self._validation = self._adapter.replace_options(
                    self._draft,
                    node_id,
                    options,
                )
            except Exception as exc:
                logger.warning("Build workspace option edit failed: %s", exc)
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
                logger.warning("Build workspace recipe save failed: %s", exc)
                self.node_inspector.show_empty(f"Save recipe failed: {exc}")
                return
            self.node_inspector.show_empty(result.message)
            if (
                should_accept_recipe_result(self._draft, result)
                and result.refresh_requested
                and self._refresh_workbench is not None
            ):
                self._refresh_workbench()

        def _edit_selected_options(self, checked: bool = False) -> None:
            del checked
            node_id = self._selected_node_id
            item = self._selected_recipe_pass(node_id or "")
            if item is None:
                return
            self.node_inspector.show_options_raw()


else:

    class BuildDeobfuscatorPanel:
        """Unavailable primary-workspace placeholder for headless imports."""

        TITLE = "D810-ng Build Deobfuscator"

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("The Build Deobfuscator workspace requires IDA GUI graphics support")


__all__ = ["BuildDeobfuscatorPanel"]
