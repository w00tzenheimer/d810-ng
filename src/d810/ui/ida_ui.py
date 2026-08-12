# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import pathlib

import ida_kernwin
import idaapi

from d810.core import logging, typing
from d810.qt_shim import (
    QFrame,
    QGroupBox,
    QMenu,
    QtCore,
    QToolButton,
    QtWidgets,
    qt_flag_or,
)

if typing.TYPE_CHECKING:
    from d810.manager import D810State, ProjectRuntimeSnapshot

from d810.core.logging import LoggerConfigurator, getLogger
from d810.core.function_storage_config import (
    FunctionStorageConfigurationError,
    parse_function_recipe_storage,
)
from d810.ui.about_dialog import show_about_dialog
from d810.ui.about_logic import PRODUCT_NAME, package_version
from d810.ui.icon_assets import bundled_icon
from d810.ui.panel_density_logic import plan_panel_density
from d810.ui.config_v2_editing_logic import (
    ConfigV2EditorScreen,
    ConfigV2PipelineOverview,
    project_config_v2_editor_view,
)
from d810.ui.config_v2_pipeline_overview import ConfigV2PipelineOverviewWidget
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigV2FocusTarget,
    ProjectConfigView,
    build_project_config_view,
    config_v2_user_destination,
    resolve_config_v2_focus_target,
    select_config_edit_policy,
)
from d810.ui.project_picker_logic import build_project_picker_entries
from d810.ui.project_picker_popup import ProjectPickerPopup
from d810.ui.qt_layout_policy import (
    configure_left_aligned_button,
    configure_left_aligned_form,
    configure_overflow_menu_button,
)
from d810.ui.testbed import TestRunnerForm

logger = getLogger("d810.ui")


def _config_action_icon(name: str):
    """Load a bundled SVG instead of relying on the host font's glyph set."""

    return bundled_icon(name)


class LoggingConfigDialog(QtWidgets.QDialog):
    """Logging configuration dialog for D-810.

    This small utility window allows the user to inspect all registered
    `logging.Logger` instances whose name starts with a given *module prefix*
    (e.g. ``D810``) and interactively change their log-level via a drop-down
    list that lets the user tweak logger levels on the fly.
    The changes take effect immediately and persist for the lifetime of
    this IDA session (the regular persistence mechanism already serialises the
    chosen level on reload).

    The dialog relies on :pymod:`PyQt5` for the UI layer and the existing
    :class:`~d810.conf.loggers.LoggerConfigurator` helper for the heavy
    lifting.
    """

    LOG_LEVELS: typing.Final[list[str]] = [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ]

    # Color map for level visualization
    LEVEL_COLORS: typing.Final[dict[str, str]] = {
        "DEBUG": "#64B5F6",  # blue
        "INFO": "",  # default
        "WARNING": "#FFA726",  # orange
        "ERROR": "#EF5350",  # red
        "CRITICAL": "#EF5350",  # red
    }

    def __init__(self, module_prefix: str, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Logging for {module_prefix}...")
        self.setMinimumSize(700, 500)
        self.resize(800, 500)

        self.module_prefix = module_prefix
        self._logger_mgr = LoggerConfigurator

        # UI setup ---------------------------------------------------------
        vbox = QtWidgets.QVBoxLayout(self)
        vbox.setContentsMargins(8, 8, 8, 8)
        vbox.setSpacing(6)

        # Top row: Filter bar + Set All button
        top_row = QtWidgets.QHBoxLayout()
        top_row.setSpacing(6)

        self._filter_edit = QtWidgets.QLineEdit()
        self._filter_edit.setPlaceholderText("Filter loggers...")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._apply_filter)
        top_row.addWidget(self._filter_edit, stretch=1)

        self._set_all_btn = QtWidgets.QPushButton("Set All *")
        self._set_all_btn.setToolTip("Set all visible loggers to the same level")
        self._set_all_menu = QMenu(self._set_all_btn)
        for level_name in self.LOG_LEVELS:
            action = self._set_all_menu.addAction(level_name)
            action.triggered.connect(
                lambda checked=False, lvl=level_name: self._set_all_levels(lvl)
            )
        self._set_all_btn.setMenu(self._set_all_menu)
        top_row.addWidget(self._set_all_btn)

        vbox.addLayout(top_row)

        # Tree widget
        self._tree = QtWidgets.QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Logger", "Level"])

        # Configure column resize modes for better proportions
        header = self._tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
        self._tree.setColumnWidth(1, 120)  # Fixed 120px for Level column

        vbox.addWidget(self._tree)

        # Button box
        btn_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        btn_box.rejected.connect(self.reject)
        vbox.addWidget(btn_box, alignment=QtCore.Qt.AlignRight)

        self._populate()

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------
    def _populate(self) -> None:
        """Build hierarchical tree from logger names under *module_prefix*."""
        self._tree.clear()

        # Collect all logger names and their current levels
        logger_names = sorted(
            self._logger_mgr.available_loggers(
                self.module_prefix, case_insensitive=True
            )
        )

        loggers: list[tuple[str, str]] = []
        for name in logger_names:
            lvl_num = getLogger(name).getEffectiveLevel()
            lvl_name = logging.getLevelName(lvl_num)
            loggers.append((name, lvl_name))

        # Build the hierarchical tree
        self._build_tree(loggers)

        # Expand first 2 levels by default
        self._tree.expandToDepth(2)

    def _build_tree(self, loggers: list[tuple[str, str]]) -> None:
        """Build hierarchical tree from logger names.

        Args:
            loggers: List of (full_logger_name, current_level) tuples
        """
        # Track nodes by path for hierarchy building
        nodes: dict[str, QtWidgets.QTreeWidgetItem] = {}
        # Track which paths are actual loggers (vs just intermediate nodes)
        logger_paths: dict[str, str] = {}

        for full_name, level in loggers:
            # Strip d810. prefix for display
            display_name = full_name
            for prefix in ["d810.", "D810."]:
                if display_name.startswith(prefix):
                    display_name = display_name[len(prefix) :]
                    break

            parts = display_name.split(".")

            # Build/find parent nodes
            for i in range(len(parts)):
                path = ".".join(parts[: i + 1])
                if path not in nodes:
                    parent_path = ".".join(parts[:i]) if i > 0 else None
                    parent = nodes[parent_path] if parent_path else None

                    item = QtWidgets.QTreeWidgetItem()
                    item.setText(0, parts[i])  # Just this segment

                    if parent:
                        parent.addChild(item)
                    else:
                        self._tree.addTopLevelItem(item)

                    nodes[path] = item

            # Mark this path as an actual logger and store its level
            logger_paths[display_name] = level
            leaf_item = nodes[display_name]
            leaf_item.setToolTip(0, full_name)  # Full name on hover

        # Now add combo boxes to all nodes that are actual loggers
        # (Some intermediate nodes may also be loggers themselves)
        for full_name, level in loggers:
            # Strip d810. prefix for display
            display_name = full_name
            for prefix in ["d810.", "D810."]:
                if display_name.startswith(prefix):
                    display_name = display_name[len(prefix) :]
                    break

            item = nodes[display_name]

            # Add combo box for level
            combo = QtWidgets.QComboBox(self._tree)
            combo.addItems(self.LOG_LEVELS)
            combo.setCurrentText(level)
            # Apply color styling
            self._update_combo_color(combo, level)
            combo.currentTextChanged.connect(
                lambda new_level, name=full_name, cb=combo: self._on_level_changed(
                    name, new_level, cb
                )
            )
            self._tree.setItemWidget(item, 1, combo)

    def _update_combo_color(self, combo: QtWidgets.QComboBox, level: str) -> None:
        """Update combo box text color based on log level."""
        color = self.LEVEL_COLORS.get(level, "")
        if color:
            combo.setStyleSheet(f"QComboBox {{ color: {color}; }}")
        else:
            combo.setStyleSheet("")

    def _apply_filter(self, text: str) -> None:
        """Filter tree nodes based on logger name, showing matching nodes and their ancestors."""
        text = text.lower()
        if not text:
            # Show all
            self._set_all_visible(self._tree.invisibleRootItem(), True)
            return
        # Hide all, then show matches and their ancestors
        self._set_all_visible(self._tree.invisibleRootItem(), False)
        self._show_matching(self._tree.invisibleRootItem(), text)

    def _set_all_visible(
        self, parent: QtWidgets.QTreeWidgetItem, visible: bool
    ) -> None:
        """Recursively set visibility for all items under parent."""
        for i in range(parent.childCount()):
            child = parent.child(i)
            child.setHidden(not visible)
            self._set_all_visible(child, visible)

    def _show_matching(self, parent: QtWidgets.QTreeWidgetItem, text: str) -> bool:
        """Recursively show nodes matching filter and their ancestors.

        Returns:
            True if any descendant matches, False otherwise
        """
        any_visible = False
        for i in range(parent.childCount()):
            child = parent.child(i)
            child_matches = text in child.text(0).lower()
            descendant_matches = self._show_matching(child, text)
            if child_matches or descendant_matches:
                child.setHidden(False)
                any_visible = True
        return any_visible

    def _set_all_levels(self, level: str) -> None:
        """Set all visible loggers to the specified level."""
        self._set_all_levels_recursive(self._tree.invisibleRootItem(), level)

    def _set_all_levels_recursive(
        self, parent: QtWidgets.QTreeWidgetItem, level: str
    ) -> None:
        """Recursively set level for all visible items with combo boxes."""
        for i in range(parent.childCount()):
            item = parent.child(i)
            if not item.isHidden():
                combo = self._tree.itemWidget(item, 1)
                if isinstance(combo, QtWidgets.QComboBox):
                    combo.setCurrentText(level)
                # Recurse to children
                self._set_all_levels_recursive(item, level)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
    def _on_level_changed(
        self, logger_name: str, new_level: str, combo: QtWidgets.QComboBox
    ) -> None:
        """Slot triggered when the user selects a new level from the drop-down."""
        try:
            self._logger_mgr.set_level(logger_name, new_level)
            # Update combo color to reflect new level
            self._update_combo_color(combo, new_level)
        except ValueError as exc:
            QtWidgets.QMessageBox.critical(self, "Error", str(exc))
            return


class PluginConfigurationFileForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        logger.debug("Initializing PluginConfigurationFileForm_t")
        super().__init__(parent)
        self.state = state
        self.log_dir_changed = False

        self.log_dir = self.state.d810_config.get("log_dir")
        self.erase_logs_on_reload = self.state.d810_config.get("erase_logs_on_reload")
        self.generate_z3_code = self.state.d810_config.get("generate_z3_code")
        self.dump_intermediate_microcode = self.state.d810_config.get(
            "dump_intermediate_microcode"
        )
        raw_storage = self.state.d810_config.get(
            "function_recipe_storage",
            {"backend": "netnode"},
        )
        if not isinstance(raw_storage, dict):
            raw_storage = {"backend": "netnode"}
        self.function_storage_backend = str(raw_storage.get("backend", "netnode"))
        self.function_storage_path = str(raw_storage.get("path", ""))

        self.setWindowTitle("Plugin Configuration")

        # Main layout with tight spacing and top alignment
        self.config_layout = QtWidgets.QVBoxLayout(self)
        self.config_layout.setContentsMargins(12, 12, 12, 12)
        self.config_layout.setSpacing(8)
        self.config_layout.setAlignment(QtCore.Qt.AlignTop)

        # Settings group box
        settings_group = QGroupBox("Settings")
        settings_layout = QtWidgets.QVBoxLayout()
        settings_layout.setSpacing(8)

        # Log directory row
        self.layout_log_dir = QtWidgets.QHBoxLayout()
        self.lbl_log_dir_info = QtWidgets.QLabel(self)
        self.lbl_log_dir_info.setText("Log directory:")
        self.layout_log_dir.addWidget(self.lbl_log_dir_info)
        self.lbl_log_dir = QtWidgets.QLabel(self)
        self.lbl_log_dir.setText(self.log_dir)
        self.lbl_log_dir.setWordWrap(True)
        self.layout_log_dir.addWidget(self.lbl_log_dir, 1)
        self.button_change_log_dir = QtWidgets.QPushButton(self)
        self.button_change_log_dir.setText("Change")
        self.button_change_log_dir.clicked.connect(self.choose_log_dir)
        self.layout_log_dir.addWidget(self.button_change_log_dir)

        settings_layout.addLayout(self.layout_log_dir)

        storage_layout = QtWidgets.QHBoxLayout()
        storage_layout.addWidget(QtWidgets.QLabel("Function recipe storage:", self))
        self.combo_function_storage_backend = QtWidgets.QComboBox(self)
        self.combo_function_storage_backend.addItem("IDB-local netnode", "netnode")
        self.combo_function_storage_backend.addItem("SQLite file", "sqlite")
        backend_index = self.combo_function_storage_backend.findData(
            self.function_storage_backend
        )
        self.combo_function_storage_backend.setCurrentIndex(max(0, backend_index))
        self.combo_function_storage_backend.currentIndexChanged.connect(
            self._update_function_storage_controls
        )
        storage_layout.addWidget(self.combo_function_storage_backend)
        self.edit_function_storage_path = QtWidgets.QLineEdit(self)
        self.edit_function_storage_path.setText(self.function_storage_path)
        self.edit_function_storage_path.setPlaceholderText(
            "Absolute path to recipes.sqlite3"
        )
        storage_layout.addWidget(self.edit_function_storage_path, 1)
        self.button_choose_function_storage_path = QtWidgets.QPushButton("Choose", self)
        self.button_choose_function_storage_path.clicked.connect(
            self.choose_function_storage_path
        )
        storage_layout.addWidget(self.button_choose_function_storage_path)
        settings_layout.addLayout(storage_layout)
        self._update_function_storage_controls()

        # Checkboxes
        self.checkbox_generate_z3_code = QtWidgets.QCheckBox(
            "Generate Z3 code for simplification performed", self
        )
        self.checkbox_generate_z3_code.setChecked(
            bool(self.state.d810_config.get("generate_z3_code", False))
        )
        settings_layout.addWidget(self.checkbox_generate_z3_code)

        self.checkbox_dump_intermediate_microcode = QtWidgets.QCheckBox(
            "Dump functions microcode at each maturity", self
        )
        self.checkbox_dump_intermediate_microcode.setChecked(
            bool(self.state.d810_config.get("dump_intermediate_microcode", False))
        )
        settings_layout.addWidget(self.checkbox_dump_intermediate_microcode)

        self.checkbox_erase_logs_on_reload = QtWidgets.QCheckBox(
            "Erase log directory content when plugin is reloaded", self
        )
        self.checkbox_erase_logs_on_reload.setChecked(
            bool(self.state.d810_config.get("erase_logs_on_reload", False))
        )
        settings_layout.addWidget(self.checkbox_erase_logs_on_reload)

        settings_group.setLayout(settings_layout)
        self.config_layout.addWidget(settings_group)

        # Button row (right-aligned)
        self.layout_button = QtWidgets.QHBoxLayout()
        self.layout_button.addStretch(1)
        self.button_save = QtWidgets.QPushButton(self)
        self.button_save.setText("Save")
        self.button_save.clicked.connect(self.save_config)
        self.layout_button.addWidget(self.button_save)
        self.button_cancel = QtWidgets.QPushButton(self)
        self.button_cancel.setText("Cancel")
        self.button_cancel.clicked.connect(self.reject)
        self.layout_button.addWidget(self.button_cancel)
        self.config_layout.addLayout(self.layout_button)

        self.setLayout(self.config_layout)

        # Resize to fit content
        self.adjustSize()
        self.setMinimumWidth(600)

    def choose_log_dir(self):
        logger.debug("Calling save_rule_configuration")
        log_dir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Open Directory",
            os.path.expanduser("~"),
            qt_flag_or(
                QtWidgets.QFileDialog.ShowDirsOnly,
                QtWidgets.QFileDialog.DontResolveSymlinks,
            ),
        )
        if log_dir != "":
            self.log_dir = log_dir
            self.log_dir_changed = True
            self.lbl_log_dir.setText(self.log_dir)

    def _update_function_storage_controls(self, _index: int = -1) -> None:
        sqlite_selected = self.combo_function_storage_backend.currentData() == "sqlite"
        self.edit_function_storage_path.setEnabled(sqlite_selected)
        self.button_choose_function_storage_path.setEnabled(sqlite_selected)

    def choose_function_storage_path(self) -> None:
        current = self.edit_function_storage_path.text().strip()
        initial = current or str(pathlib.Path.home() / "d810-recipes.sqlite3")
        selected, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Select function recipe database",
            initial,
            "SQLite database (*.sqlite3 *.db);;All files (*)",
        )
        if selected:
            self.function_storage_path = selected
            self.edit_function_storage_path.setText(selected)

    def _function_storage_payload(self) -> dict[str, str]:
        backend = str(self.combo_function_storage_backend.currentData())
        if backend == "netnode":
            return {"backend": "netnode"}
        return {
            "backend": "sqlite",
            "path": self.edit_function_storage_path.text().strip(),
        }

    def save_config(self):
        storage_payload = self._function_storage_payload()
        effective_log_dir = pathlib.Path(self.state.log_dir)
        if self.log_dir_changed:
            effective_log_dir = pathlib.Path(self.log_dir) / effective_log_dir.name
        try:
            storage_config = parse_function_recipe_storage(
                storage_payload,
                log_dir=effective_log_dir,
            )
        except FunctionStorageConfigurationError as exc:
            QtWidgets.QMessageBox.critical(self, "Invalid recipe storage", str(exc))
            return
        if self.log_dir_changed:
            self.state.d810_config.set("log_dir", self.log_dir)
        self.state.d810_config.set(
            "erase_logs_on_reload", self.checkbox_erase_logs_on_reload.isChecked()
        )
        self.state.d810_config.set(
            "generate_z3_code", self.checkbox_generate_z3_code.isChecked()
        )
        self.state.d810_config.set(
            "dump_intermediate_microcode",
            self.checkbox_dump_intermediate_microcode.isChecked(),
        )
        self.state.d810_config.set("function_recipe_storage", storage_payload)
        self.state.d810_config.save()
        self.state.manager.reconfigure_function_storage(storage_config)
        self.accept()


class _DensityHost(QtWidgets.QWidget):
    """Panel body that reports its own resizes to the density planner.

    ``PluginForm`` is not a ``QObject`` and the widget IDA hands back cannot be
    subclassed, so the panel owns one widget of its own and reads height
    changes from it directly rather than through an event filter.
    """

    def __init__(self, on_resize, parent=None) -> None:
        super().__init__(parent)
        self._on_resize = on_resize

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._on_resize()


class D810ConfigForm_t(ida_kernwin.PluginForm):
    def __init__(self, state: "D810State"):
        super().__init__()
        self.state = state
        self.shown = False
        self.created = False
        self.parent = None
        self.test_runner: TestRunnerForm | None = None
        self._config_v2_editor = None
        self._config_v2_overview: ConfigV2PipelineOverview | None = None

        self._view_passes_title = "Pass pipeline"

        # Disclosure state: what the user asked for, and what the project makes
        # mandatory. Divergent identity outranks the request.
        self._details_requested = False
        self._identity_is_divergent = False

        # Initialize all widget attributes to None (defensive pattern)
        # These are created in OnCreate() but may be accessed before OnCreate() runs
        self._header_fixed = None
        self._config_summary_value = None
        self._details_toggle = None
        self._details_panel = None
        self._engine_bar = None
        self._engine_menu = None
        self._engine_actions = ()
        self.btn_engine_overflow = None
        self._density_host = None
        self._status_indicator = None
        self._diagnostics_capture_indicator = None
        self.curlabel = None
        self.cfg_select = None
        self.btn_new_cfg = None
        self.btn_duplicate_cfg = None
        self.btn_edit_cfg = None
        self.btn_delele_cfg = None
        self._config_mode_value = None
        self._config_source_value = None
        self._config_runtime_value = None
        self._config_passes_value = None
        self.cfg_description = None
        self._pipeline_overview = None
        self.btn_start = None
        self.btn_stop = None
        self.btn_config = None
        self.btn_logger_cfg = None
        self.btn_start_profiling = None
        self.btn_test_runner = None

    def OnClose(self, form):
        """Called when IDA destroys the form. Clean up to prevent shutdown crash."""
        logger.debug("Calling OnClose")
        self.shown = False

        # Disconnect all signals to prevent PySide6 crash during Python finalization
        try:
            if hasattr(self, "cfg_select") and self.cfg_select is not None:
                self.cfg_select.clicked.disconnect()

            if (
                hasattr(self, "_pipeline_overview")
                and self._pipeline_overview is not None
            ):
                self._pipeline_overview.inspect_requested.disconnect()
                self._pipeline_overview.edit_pipeline_requested.disconnect()

            if self._details_toggle is not None:
                self._details_toggle.toggled.disconnect()

            # Overflow-menu actions hold the same kind of Python-side
            # connection as the buttons and need the same teardown.
            for action in self._engine_actions:
                try:
                    action.triggered.disconnect()
                except (TypeError, RuntimeError):
                    pass

            # Disconnect all button signals
            for btn_attr in [
                "btn_new_cfg",
                "btn_duplicate_cfg",
                "btn_edit_cfg",
                "btn_delele_cfg",
                "btn_start",
                "btn_stop",
            ]:
                btn = getattr(self, btn_attr, None)
                if btn is not None:
                    try:
                        btn.clicked.disconnect()
                    except (TypeError, RuntimeError):
                        # Signal may already be disconnected or widget already deleted
                        # during IDA shutdown/finalization; safe to ignore.
                        pass

        except (TypeError, RuntimeError) as e:
            logger.debug("Signal disconnect error (expected during shutdown): %s", e)

        # Clear widget references
        self._pipeline_overview = None
        self._config_v2_overview = None
        self.cfg_select = None
        self._engine_menu = None
        self._engine_actions = ()
        self._density_host = None
        self._details_toggle = None
        self._details_panel = None
        self._config_mode_value = None
        self._config_source_value = None
        self._config_runtime_value = None
        self._config_passes_value = None

        if self.test_runner is not None:
            self.test_runner.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            self.test_runner = None
        if self._config_v2_editor is not None:
            self._config_v2_editor.close()
            self._config_v2_editor = None

    def Show(self):
        logger.debug("Calling Show")
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self,
            f"D-810 Configuration - {package_version()}",
            options=(
                ida_kernwin.PluginForm.WOPN_PERSIST
                | ida_kernwin.PluginForm.WCLS_SAVE
                | ida_kernwin.PluginForm.WOPN_MENU
                | ida_kernwin.PluginForm.WOPN_RESTORE
                | ida_kernwin.PluginForm.WOPN_TAB
            ),
        )

    def OnCreate(self, form):
        logger.debug("Calling OnCreate")
        self.created = True

        # Get parent widget. The body lives in a widget we own so the panel can
        # re-plan its optional chrome whenever the dock height changes.
        self.parent = self.FormToPyQtWidget(form)
        host_layout = QtWidgets.QVBoxLayout(self.parent)
        host_layout.setContentsMargins(0, 0, 0, 0)
        self._density_host = _DensityHost(self._apply_panel_density, self.parent)
        host_layout.addWidget(self._density_host)

        main_layout = QtWidgets.QVBoxLayout(self._density_host)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(6)

        # =====================================================================
        # Header (always visible, compact). No group frame: in a dock the
        # title and border cost a row and carry nothing.
        # =====================================================================
        self._header_fixed = QtWidgets.QWidget(self.parent)
        main_layout.addWidget(self._header_fixed)

        # Use VBoxLayout to stack config row and summary
        project_vbox = QtWidgets.QVBoxLayout(self._header_fixed)
        project_vbox.setContentsMargins(4, 4, 4, 4)
        project_vbox.setSpacing(4)

        # Config row with status indicator
        config_row = QtWidgets.QHBoxLayout()
        project_vbox.addLayout(config_row)

        # Status indicator (bundled SVG avoids host-font glyph fallbacks).
        self._status_indicator = QtWidgets.QLabel()
        self._status_indicator.setFixedSize(20, 20)
        self._status_indicator.setToolTip("D810 is stopped")
        config_row.addWidget(self._status_indicator)

        self._diagnostics_capture_indicator = QtWidgets.QLabel()
        self._diagnostics_capture_indicator.setFixedSize(20, 20)
        config_row.addWidget(self._diagnostics_capture_indicator)

        # Config selector
        self.curlabel = QtWidgets.QLabel("Config:")
        config_row.addWidget(self.curlabel)

        self.cfg_select = QtWidgets.QPushButton(self.parent)
        configure_left_aligned_button(self.cfg_select)
        self.cfg_select.setToolTip("Choose a D-810 configuration")
        config_row.addWidget(self.cfg_select, stretch=1)

        # Project buttons (icon-only toolbuttons)
        self.btn_new_cfg = QToolButton()
        self.btn_new_cfg.setIcon(_config_action_icon("new"))
        self.btn_new_cfg.setToolTip("Create new configuration")
        self.btn_new_cfg.setFixedSize(32, 32)
        self.btn_new_cfg.setIconSize(QtCore.QSize(20, 20))
        self.btn_new_cfg.clicked.connect(self._create_config)
        config_row.addWidget(self.btn_new_cfg)

        self.btn_duplicate_cfg = QToolButton()
        self.btn_duplicate_cfg.setIcon(_config_action_icon("duplicate"))
        self.btn_duplicate_cfg.setToolTip("Duplicate current configuration")
        self.btn_duplicate_cfg.setFixedSize(32, 32)
        self.btn_duplicate_cfg.setIconSize(QtCore.QSize(20, 20))
        self.btn_duplicate_cfg.clicked.connect(self._duplicate_config)
        config_row.addWidget(self.btn_duplicate_cfg)

        self.btn_edit_cfg = QToolButton()
        self.btn_edit_cfg.setIcon(_config_action_icon("edit"))
        self.btn_edit_cfg.setToolTip("Edit current configuration")
        self.btn_edit_cfg.setFixedSize(32, 32)
        self.btn_edit_cfg.setIconSize(QtCore.QSize(20, 20))
        self.btn_edit_cfg.clicked.connect(self._edit_config)
        config_row.addWidget(self.btn_edit_cfg)

        self.btn_delele_cfg = QToolButton()
        self.btn_delele_cfg.setIcon(_config_action_icon("delete"))
        self.btn_delele_cfg.setToolTip("Delete current configuration")
        self.btn_delele_cfg.setFixedSize(32, 32)
        self.btn_delele_cfg.setIconSize(QtCore.QSize(20, 20))
        self.btn_delele_cfg.clicked.connect(self._delete_config)
        config_row.addWidget(self.btn_delele_cfg)

        # About (ticket d81-zijs). Last in the row so it reads as help rather
        # than as another configuration action.
        self.btn_about = QToolButton()
        self.btn_about.setText("?")
        self.btn_about.setToolTip(f"About {PRODUCT_NAME}")
        self.btn_about.setFixedSize(32, 32)
        self.btn_about.clicked.connect(self._show_about)
        config_row.addWidget(self.btn_about)

        # Summary row: mode and pass count always visible, everything else
        # behind the disclosure.
        summary_row = QtWidgets.QHBoxLayout()
        project_vbox.addLayout(summary_row)

        self._config_summary_value = QtWidgets.QLabel()
        self._config_summary_value.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        summary_row.addWidget(self._config_summary_value)
        summary_row.addStretch(1)

        self._details_toggle = QToolButton()
        self._details_toggle.setText("Details")
        self._details_toggle.setCheckable(True)
        self._details_toggle.setAutoRaise(True)
        self._details_toggle.setArrowType(QtCore.Qt.RightArrow)
        self._details_toggle.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self._details_toggle.toggled.connect(self._on_details_toggled)
        summary_row.addWidget(self._details_toggle)

        # Details disclosure: identity form plus description, collapsed by
        # default and force-expanded whenever source and runtime differ.
        self._details_panel = QtWidgets.QWidget(self._header_fixed)
        project_vbox.addWidget(self._details_panel)
        details_layout = QtWidgets.QVBoxLayout(self._details_panel)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(4)

        identity_layout = QtWidgets.QFormLayout()
        configure_left_aligned_form(identity_layout)
        self._config_mode_value = QtWidgets.QLabel()
        self._config_source_value = QtWidgets.QLabel()
        self._config_runtime_value = QtWidgets.QLabel()
        self._config_passes_value = QtWidgets.QLabel()
        for value_label in (
            self._config_mode_value,
            self._config_source_value,
            self._config_runtime_value,
            self._config_passes_value,
        ):
            value_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self._config_passes_value.setWordWrap(True)
        identity_layout.addRow("Mode:", self._config_mode_value)
        identity_layout.addRow("Source:", self._config_source_value)
        identity_layout.addRow("Runtime:", self._config_runtime_value)
        identity_layout.addRow("Effective passes:", self._config_passes_value)
        details_layout.addLayout(identity_layout)

        # Description wraps in place instead of reserving a fixed 60px box.
        self.cfg_description = QtWidgets.QLabel()
        self.cfg_description.setWordWrap(True)
        self.cfg_description.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.cfg_description.setText("No description")
        details_layout.addWidget(self.cfg_description)

        self._details_panel.setVisible(False)

        # =====================================================================
        # Horizontal divider between header and pass pipeline
        # =====================================================================
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(divider)

        self._pipeline_overview = ConfigV2PipelineOverviewWidget(self.parent)
        self._pipeline_overview.setAccessibleName(self._view_passes_title)
        self._pipeline_overview.inspect_requested.connect(self._inspect_config_v2_pass)
        self._pipeline_overview.edit_pipeline_requested.connect(self._edit_config)
        main_layout.addWidget(self._pipeline_overview, stretch=1)

        # =====================================================================
        # Engine bar (always visible, compact)
        # =====================================================================
        engine_divider = QFrame()
        engine_divider.setFrameShape(QFrame.HLine)
        engine_divider.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(engine_divider)

        self._engine_bar = QtWidgets.QWidget(self.parent)
        main_layout.addWidget(self._engine_bar)

        engine_layout = QtWidgets.QHBoxLayout(self._engine_bar)
        engine_layout.setContentsMargins(4, 4, 4, 4)
        engine_layout.setSpacing(4)

        self.btn_start = QtWidgets.QPushButton("Start")
        self.btn_start.clicked.connect(self._start_d810)
        engine_layout.addWidget(self.btn_start)

        self.btn_stop = QtWidgets.QPushButton("Stop")
        self.btn_stop.clicked.connect(self._stop_d810)
        engine_layout.addWidget(self.btn_stop)

        # The stretch keeps Start/Stop at their size hint instead of letting
        # them span a sixth of the dock each.
        engine_layout.addStretch(1)

        # Occasional controls collapse into one overflow menu.
        self._engine_menu = QMenu(self.parent)
        self._engine_menu.setToolTipsVisible(True)
        actions = []

        self.btn_config = self._engine_menu.addAction("Config")
        self.btn_config.triggered.connect(self._configure_plugin)
        actions.append(self.btn_config)

        self.btn_logger_cfg = self._engine_menu.addAction("Loggers")
        self.btn_logger_cfg.setToolTip("Adjust log-levels at runtime")
        self.btn_logger_cfg.triggered.connect(self._configure_logging)
        actions.append(self.btn_logger_cfg)

        self.btn_start_profiling = self._engine_menu.addAction("Profile")
        self.btn_start_profiling.setToolTip(
            "Toggle profiling: start to capture, stop to save report"
        )
        self.btn_start_profiling.triggered.connect(self._toggle_profiling)
        actions.append(self.btn_start_profiling)

        if TestRunnerForm is not None:
            self.btn_test_runner = self._engine_menu.addAction("TestRunner")
            self.btn_test_runner.triggered.connect(self._show_test_runner)
            actions.append(self.btn_test_runner)

        self._engine_actions = tuple(actions)

        self.btn_engine_overflow = QToolButton()
        configure_overflow_menu_button(self.btn_engine_overflow)
        self.btn_engine_overflow.setText("...")
        self.btn_engine_overflow.setToolTip("Configuration, loggers, profiling, tests")
        self.btn_engine_overflow.setPopupMode(QToolButton.InstantPopup)
        self.btn_engine_overflow.setMenu(self._engine_menu)
        engine_layout.addWidget(self.btn_engine_overflow)

        # Status is now shown via the circle indicator in the header row
        self._update_status(loaded=False)
        self._update_diagnostics_capture_indicator()

        # =====================================================================
        # Final initialization
        # =====================================================================
        self.update_cfg_select()
        self.cfg_select.clicked.connect(self._open_config_picker)

        # Load the current config to populate the pass tree immediately
        self._load_config(self.state.current_project_index)
        self._apply_panel_density()

    def _on_details_toggled(self, checked: bool) -> None:
        """Record the user's disclosure preference and re-plan the panel."""
        self._details_requested = bool(checked)
        self._apply_panel_density()

    def _apply_panel_density(self) -> None:
        """Show or hide optional chrome for the height the dock actually has."""
        if self._pipeline_overview is None or self._density_host is None:
            return
        if self._details_panel is None or self._details_toggle is None:
            return

        # Measure against fixed chrome only. Subtracting the disclosure itself
        # would make the plan depend on its own outcome and oscillate.
        # A widget whose layout is not populated yet reports a height of -1.
        fixed_px = 0
        for widget in (self._header_fixed, self._engine_bar):
            if widget is not None:
                fixed_px += max(0, widget.sizeHint().height())
        available_px = max(0, self._density_host.height() - fixed_px)

        plan = plan_panel_density(
            available_px=available_px,
            row_px=self._pipeline_overview.row_height(),
            filter_has_text=False,
            details_requested=self._details_requested,
            identity_is_divergent=self._identity_is_divergent,
        )

        self._details_panel.setVisible(plan.show_details)
        self._details_toggle.setEnabled(not plan.details_locked)
        self._details_toggle.setToolTip(
            "Source and runtime projects differ; identity stays visible."
            if plan.details_locked
            else "Show project mode, identity, and effective passes"
        )
        self._details_toggle.setArrowType(
            QtCore.Qt.DownArrow if plan.show_details else QtCore.Qt.RightArrow
        )
        # setChecked would re-enter _on_details_toggled and overwrite the
        # user's preference with a height-driven decision.
        self._details_toggle.blockSignals(True)
        self._details_toggle.setChecked(plan.show_details)
        self._details_toggle.blockSignals(False)

    def _update_status(self, loaded: bool) -> None:
        """Update the status indicator circle."""
        if self._status_indicator is None:
            logger.debug("Cannot update status indicator: widget not created yet")
            return
        if loaded:
            self._status_indicator.setPixmap(
                _config_action_icon("status-running").pixmap(QtCore.QSize(16, 16))
            )
            self._status_indicator.setToolTip("D810 is running")
        else:
            self._status_indicator.setPixmap(
                _config_action_icon("status-stopped").pixmap(QtCore.QSize(16, 16))
            )
            self._status_indicator.setToolTip("D810 is stopped")

    def _update_diagnostics_capture_indicator(self) -> None:
        """Show capture independently from the D810 running/stopped state."""
        if self._diagnostics_capture_indicator is None:
            return
        enabled = self.state.diagnostics_capture_enabled()
        icon_name = (
            "diagnostics-capture-enabled" if enabled else "diagnostics-capture-disabled"
        )
        tooltip = (
            "Diagnostics capture enabled - the next decompilation will record "
            "snapshots and structured evidence."
            if enabled
            else "Diagnostics capture disabled"
        )
        self._diagnostics_capture_indicator.setPixmap(
            _config_action_icon(icon_name).pixmap(QtCore.QSize(16, 16))
        )
        self._diagnostics_capture_indicator.setToolTip(tooltip)

    def update_cfg_select(self):
        """Synchronize the current-project button without loading a project."""

        projects = self.state.project_manager.projects()
        if not projects:
            self.cfg_select.setText("No configurations available")
            self.cfg_select.setToolTip(
                "No D-810 configuration projects were discovered"
            )
            self.cfg_select.setEnabled(False)
            return
        project_index = min(
            max(0, self.state.current_project_index),
            len(projects) - 1,
        )
        self.cfg_select.setText(f"{projects[project_index].path.name}  ▼")
        self.cfg_select.setToolTip(
            f"Choose D-810 configuration ({len(projects)} discovered)"
        )
        self.cfg_select.setEnabled(True)

    def _open_config_picker(self, checked: bool = False) -> None:
        del checked
        projects = tuple(self.state.project_manager.projects())
        if not projects:
            return
        existing_popup = getattr(self, "_config_picker_popup", None)
        if existing_popup is not None:
            existing_popup.close()
        popup_parent = self.parent or QtWidgets.QApplication.activeWindow()
        self._config_picker_popup = ProjectPickerPopup(
            build_project_picker_entries(projects),
            current_project_index=self.state.current_project_index,
            on_project_selected=self._load_config,
            parent=popup_parent,
        )
        self._config_picker_popup.show_for(self.cfg_select)

    # =========================================================================
    # Edit state machine
    # =========================================================================

    def _create_config(self):
        QtWidgets.QMessageBox.information(
            self.parent,
            "Create config-v2 project",
            "Duplicate an existing config-v2 project, then edit its ordered pass "
            "pipeline and typed options.",
        )

    def _duplicate_config(self):
        logger.debug("Calling _duplicate_config")
        snapshot = self.state.get_project_runtime_snapshot()
        policy = select_config_edit_policy(ConfigEditMode.DUPLICATE, snapshot)
        if not policy.allowed:
            QtWidgets.QMessageBox.information(
                self.parent,
                "Configuration cannot be duplicated",
                policy.explanation,
            )
            return
        destination = self._choose_config_v2_destination(
            snapshot,
            duplicate=True,
        )
        if destination is not None:
            self._open_config_v2_editor(
                destination,
                screen=ConfigV2EditorScreen.BUILDER,
            )

    def _edit_config(self):
        logger.debug("Calling _edit_config")
        snapshot = self.state.get_project_runtime_snapshot()
        policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
        if not policy.allowed:
            QtWidgets.QMessageBox.information(
                self.parent,
                "Configuration is read-only",
                policy.explanation,
            )
            return
        destination = self._choose_config_v2_destination(
            snapshot,
            duplicate=False,
        )
        if destination is not None:
            self._open_config_v2_editor(
                destination,
                screen=ConfigV2EditorScreen.BUILDER,
            )

    def _inspect_config_v2_pass(self, index: int) -> None:
        if self._config_v2_overview is None:
            return
        rows = self._config_v2_overview.rows
        if not 0 <= index < len(rows):
            return
        row = rows[index]
        if row.index != index:
            return
        snapshot = self.state.get_project_runtime_snapshot()
        policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
        if not policy.allowed:
            return
        destination = self._choose_config_v2_destination(snapshot, duplicate=False)
        if destination is None:
            return
        focus_target = resolve_config_v2_focus_target(
            row.pass_id,
            tuple(candidate.pass_id for candidate in rows),
            pass_index=index,
        )
        if not focus_target.unambiguous:
            logger.warning(
                "Config-v2 pass inspection refused: %s", focus_target.message
            )
            return
        self._open_config_v2_editor(
            destination,
            screen=ConfigV2EditorScreen.INSPECTOR,
            focus_target=focus_target,
        )

    def _choose_config_v2_destination(
        self,
        snapshot: "ProjectRuntimeSnapshot",
        *,
        duplicate: bool,
    ) -> pathlib.Path | None:
        config_dir = pathlib.Path(self.state.d810_config.config_dir).resolve()
        runtime_path = pathlib.Path(snapshot.runtime.path).resolve()
        default = config_v2_user_destination(config_dir, runtime_path)
        if not duplicate:
            return default
        default = config_dir / f"{runtime_path.stem}_copy.json"
        destination, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.parent,
            "Choose a lossless config-v2 project destination",
            str(default),
            "D810 project configurations (*.json)",
        )
        return pathlib.Path(destination) if destination else None

    def _open_config_v2_editor(
        self,
        destination: pathlib.Path,
        *,
        screen: ConfigV2EditorScreen,
        focus_target: ConfigV2FocusTarget | None = None,
    ) -> None:
        from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter
        from d810.ui.config_v2_editing_panel import ConfigV2EditingPanel

        try:
            adapter = ConfigV2EditingAdapter(
                self.state,
                destination=destination,
            )
            editor = ConfigV2EditingPanel(
                adapter,
                on_saved=self._refresh_config_v2_project_view,
                screen=screen,
                focus_target=focus_target,
            )
        except Exception as exc:
            logger.warning("Config-v2 project editor failed: %s", exc)
            QtWidgets.QMessageBox.critical(
                self.parent,
                "Config-v2 project editor",
                str(exc),
            )
            return
        if self._config_v2_editor is not None:
            self._config_v2_editor.close()
        self._config_v2_editor = editor
        editor.show()

    def _refresh_config_v2_project_view(self) -> None:
        self.update_cfg_select()
        snapshot = self.state.get_project_runtime_snapshot()
        self.cfg_description.setText(
            self.state.current_project.description or "No description"
        )
        self._apply_project_config_view(build_project_config_view(snapshot))

    # callback when the "Delete" button is clicked
    def _delete_config(self):
        logger.debug("Calling _delete_config")
        self.state.project_manager.delete(self.state.current_project)
        self.update_cfg_select()

    def _apply_project_config_view(self, view: ProjectConfigView) -> None:
        self._config_mode_value.setText(view.mode_text)
        self._config_source_value.setText(view.source_text)
        self._config_source_value.setToolTip(view.source_tooltip)
        # Name the divergence in the row itself: a routed runtime must never
        # look like the project the user picked.
        self._config_runtime_value.setText(
            f"{view.runtime_text}  (differs from source)"
            if view.identity_is_divergent
            else view.runtime_text
        )
        self._config_runtime_value.setToolTip(view.runtime_tooltip)
        self._config_passes_value.setText(view.effective_passes_text)
        self._config_summary_value.setText(view.header_summary_text)
        self.btn_edit_cfg.setEnabled(view.edit_enabled)
        self.btn_edit_cfg.setToolTip(view.edit_tooltip)
        self._view_passes_title = view.pass_tree_title
        self._pipeline_overview.setAccessibleName(view.pass_tree_title)

        overview = None
        if view.edit_enabled:
            from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter

            config_dir = pathlib.Path(self.state.d810_config.config_dir).resolve()
            runtime_path = pathlib.Path(view.runtime_tooltip).resolve()
            destination = config_v2_user_destination(config_dir, runtime_path)
            try:
                adapter = ConfigV2EditingAdapter(
                    self.state,
                    destination=destination,
                )
                draft, validation = adapter.load_view()
                catalog = adapter.catalog()
                overview = project_config_v2_editor_view(
                    draft,
                    validation,
                    catalog,
                ).overview
            except Exception as exc:
                logger.warning("Config-v2 pipeline overview failed: %s", exc)
        self._config_v2_overview = overview
        self._pipeline_overview.set_overview(overview)
        self._identity_is_divergent = view.identity_is_divergent
        self._apply_panel_density()

    # Called when the edit combo is changed
    def _load_config(self, index: int):
        projects = self.state.project_manager.projects()
        if not projects:
            logger.warning("No project configurations available to load.")
            return
        if index < 0 or index >= len(projects):
            logger.warning(
                "Ignoring _load_config with invalid index %s (available 0..%s)",
                index,
                len(projects) - 1,
            )
            return
        if logger.debug_on:
            current_idx = self.state.current_project_index
            current_name = (
                projects[current_idx].path.name
                if 0 <= current_idx < len(projects)
                else "n/a"
            )
            logger.debug(
                "Calling _load_config with index %s (%s), current project index %s (%s)",
                index,
                projects[index].path.name,
                current_idx,
                current_name,
            )
        project = self.state.load_project(index)
        self.update_cfg_select()
        if project is None:
            # Malformed project: keep the panel responsive and say why rather
            # than raising into the Qt slot (ticket lpccp-8c87).
            name = projects[index].path.name if index < len(projects) else str(index)
            reason = self.state.invalid_projects.get(name, "unknown error")
            self.cfg_description.setText(f"Cannot load {name} - {reason}")
            return
        snapshot = self.state.get_project_runtime_snapshot()
        view = build_project_config_view(snapshot)
        self.cfg_description.setText(project.description or "No description")
        self._apply_project_config_view(view)
        return

    def _show_about(self):
        """Open the About dialog (ticket d81-zijs).

        Guarded: a failure here is cosmetic and must not raise into the Qt slot
        and take the panel down -- same reasoning as ``_load_config``.
        """
        try:
            show_about_dialog(self.parent)
        except Exception:  # noqa: BLE001 - About is never worth a broken panel
            logger.warning("Could not open the About dialog", exc_info=True)

    def _configure_plugin(self):
        editdlg = PluginConfigurationFileForm_t(self.parent, self.state)
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            return
        return

    def _configure_logging(self):
        """Open the dynamic logging configuration dialog."""
        try:
            dlg = LoggingConfigDialog("D810", self.parent)
            dlg.exec_()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to open LoggingConfigDialog: %s", exc)
            QtWidgets.QMessageBox.critical(
                self.parent,
                "Error",
                f"Unable to open logging configuration dialog:\n{exc}",
            )

    def _start_d810(self):
        logger.debug("Calling _start_d810")
        self.state.start_d810()
        self._update_status(loaded=True)
        return

    def _stop_d810(self):
        logger.debug("Calling _stop_d810")
        self._stop_profiling()
        self.state.stop_d810()
        self._update_status(loaded=False)
        return

    def _toggle_profiling(self):
        """Start or stop profiling based on current state."""
        if not hasattr(self.state, "manager") or not self.state.manager:
            logger.warning(
                "D810 manager not initialized; cannot profile. Start D810 first."
            )
            QtWidgets.QMessageBox.warning(
                self.parent,
                "Profiling",
                "D810 must be started before profiling. Click Start first.",
            )
            return
        mgr = self.state.manager
        if mgr.is_profiling:
            logger.debug("Stopping profiling")
            output_path = mgr.stop_profiling()
            if output_path:
                logger.info("Profiling stopped. Report saved to: %s", output_path)
                QtWidgets.QMessageBox.information(
                    self.parent,
                    "Profiling Stopped",
                    f"Profiling report saved to:\n{output_path}",
                )
            self.btn_start_profiling.setText("Profile")
        else:
            logger.debug("Starting profiling")
            mgr.enable_profiling()
            logger.info(
                "Profiling started. Click Profile again to stop and save report."
            )
            self.btn_start_profiling.setText("Stop Profile")

    def _stop_profiling(self):
        """Stop profiling if running (used e.g. on manager stop)."""
        if (
            hasattr(self.state, "manager")
            and self.state.manager
            and self.state.manager.is_profiling
        ):
            self.state.manager.stop_profiling()
        if (
            hasattr(self, "btn_start_profiling")
            and self.btn_start_profiling is not None
        ):
            self.btn_start_profiling.setText("Profile")

    def _show_test_runner(self):
        if self.test_runner is None:
            self.test_runner = TestRunnerForm()
        self.test_runner.Show(
            "D810 Test Runner",
            options=(
                ida_kernwin.PluginForm.WOPN_PERSIST
                | ida_kernwin.PluginForm.WCLS_SAVE
                | ida_kernwin.PluginForm.WOPN_RESTORE
                | ida_kernwin.PluginForm.WOPN_TAB
            ),
        )


class D810GUI(object):
    def __init__(self, state: "D810State"):
        """
        Instantiate D-810 views
        """
        logger.debug("Initializing D810GUI")
        self.state = state
        self.d810_config_form: D810ConfigForm_t | None = D810ConfigForm_t(self.state)

        # -- Context menu for pseudocode right-click -----------------------
        from d810.ui.context_menu import D810ContextMenu

        self.context_menu = D810ContextMenu()
        self.context_menu.install(self.state)

        # TODO(w00tzenheimer): fix (what?)
        idaapi.set_dock_pos("D-810", "IDA View-A", idaapi.DP_TAB)

    def show_windows(self):
        logger.debug("Calling show_windows")
        if self.d810_config_form is None:
            raise RuntimeError("D810ConfigForm_t is None")
        self.d810_config_form.Show()

    def term(self):
        logger.debug("Calling term")
        if self.d810_config_form is not None:
            self.d810_config_form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.d810_config_form = None
        if hasattr(self, "context_menu") and self.context_menu is not None:
            self.context_menu.uninstall()
            self.context_menu = None
