# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
import pathlib

import ida_kernwin
import idaapi

from d810.core import typing
from d810.qt_shim import QFrame, QGroupBox, QMenu, QtCore, QtGui, QToolButton, QtWidgets

if typing.TYPE_CHECKING:
    from d810.manager import D810State

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.logging import LoggerConfigurator, getLogger
from d810.ui.rule_detail import RuleDetailPanel
from d810.ui.rule_tree import RuleTreeWidget
from d810.ui.testbed import TestRunnerForm

logger = getLogger("D810.ui")


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
        self.setWindowTitle(f"Logging for {module_prefix}…")
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

        self._set_all_btn = QtWidgets.QPushButton("Set All ▼")
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
            QtWidgets.QFileDialog.ShowDirsOnly
            | QtWidgets.QFileDialog.DontResolveSymlinks,
        )
        if log_dir != "":
            self.log_dir = log_dir
            self.log_dir_changed = True
            self.lbl_log_dir.setText(self.log_dir)

    def save_config(self):
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
        self.state.d810_config.save()
        self.accept()


class D810ConfigForm_t(ida_kernwin.PluginForm):
    def __init__(self, state: "D810State"):
        super().__init__()
        self.state = state
        self.shown = False
        self.created = False
        self.parent = None
        self.test_runner: TestRunnerForm | None = None

        # Edit state machine attributes
        self._edit_mode: str | None = None  # "new", "duplicate", or "edit"
        self._edit_path: pathlib.Path | None = None
        self._edit_old_conf: ProjectConfiguration | None = None

        # Initialize all widget attributes to None (defensive pattern)
        # These are created in OnCreate() but may be accessed before OnCreate() runs
        self._project_group = None
        self._status_indicator = None
        self.curlabel = None
        self.cfg_select = None
        self.btn_new_cfg = None
        self.btn_duplicate_cfg = None
        self.btn_edit_cfg = None
        self.btn_delele_cfg = None
        self.cfg_description = None
        self._rules_group = None
        self._rules_content = None
        self._edit_header = None
        self._edit_name_input = None
        self._edit_desc_input = None
        self._splitter = None
        self._rule_tree = None
        self._rule_detail = None
        self._rule_configs = None
        self._btn_save_rules = None
        self._btn_cancel_rules = None
        self._engine_group = None
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
                self.cfg_select.currentIndexChanged.disconnect()

            if hasattr(self, "_rule_tree") and self._rule_tree is not None:
                self._rule_tree.rule_selected.disconnect()
                self._rule_tree.rule_toggled.disconnect()

            if hasattr(self, "_rule_detail") and self._rule_detail is not None:
                self._rule_detail.config_changed.disconnect()

            # Disconnect all button signals
            for btn_attr in [
                "btn_new_cfg",
                "btn_duplicate_cfg",
                "btn_edit_cfg",
                "btn_delele_cfg",
                "btn_start",
                "btn_stop",
                "btn_config",
                "btn_logger_cfg",
                "btn_start_profiling",
                "btn_test_runner",
                "_btn_save_rules",
                "_btn_cancel_rules",
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
        self._rule_tree = None
        self._rule_detail = None
        self.cfg_select = None

        if self.test_runner is not None:
            self.test_runner.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            self.test_runner = None

    def Show(self):
        logger.debug("Calling Show")
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self,
            "D-810 Configuration",
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

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        main_layout = QtWidgets.QVBoxLayout(self.parent)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(6)

        # =====================================================================
        # Project Group (always visible, compact)
        # =====================================================================
        self._project_group = QGroupBox("Project", self.parent)
        main_layout.addWidget(self._project_group)

        # Use VBoxLayout to stack config row and description
        project_vbox = QtWidgets.QVBoxLayout(self._project_group)

        # Config row with status indicator
        config_row = QtWidgets.QHBoxLayout()
        project_vbox.addLayout(config_row)

        # Status indicator (colored circle)
        self._status_indicator = QtWidgets.QLabel()
        self._status_indicator.setTextFormat(QtCore.Qt.RichText)
        self._status_indicator.setText(
            '<span style="color: #D32F2F; font-size: 20px;">●</span>'
        )
        self._status_indicator.setToolTip("D810 is stopped")
        config_row.addWidget(self._status_indicator)

        # Config selector
        self.curlabel = QtWidgets.QLabel("Config:")
        config_row.addWidget(self.curlabel)

        self.cfg_select = QtWidgets.QComboBox(self.parent)
        config_row.addWidget(self.cfg_select, stretch=1)

        # Project buttons (icon-only toolbuttons)
        self.btn_new_cfg = QToolButton()
        self.btn_new_cfg.setText("+")
        self.btn_new_cfg.setToolTip("Create new configuration")
        self.btn_new_cfg.setFixedSize(32, 32)
        font = self.btn_new_cfg.font()
        font.setPointSize(16)
        self.btn_new_cfg.setFont(font)
        self.btn_new_cfg.clicked.connect(self._create_config)
        config_row.addWidget(self.btn_new_cfg)

        self.btn_duplicate_cfg = QToolButton()
        self.btn_duplicate_cfg.setText("⧉")
        self.btn_duplicate_cfg.setToolTip("Duplicate current configuration")
        self.btn_duplicate_cfg.setFixedSize(32, 32)
        font = self.btn_duplicate_cfg.font()
        font.setPointSize(16)
        self.btn_duplicate_cfg.setFont(font)
        self.btn_duplicate_cfg.clicked.connect(self._duplicate_config)
        config_row.addWidget(self.btn_duplicate_cfg)

        self.btn_edit_cfg = QToolButton()
        self.btn_edit_cfg.setText("✎")
        self.btn_edit_cfg.setToolTip("Edit current configuration")
        self.btn_edit_cfg.setFixedSize(32, 32)
        font = self.btn_edit_cfg.font()
        font.setPointSize(16)
        self.btn_edit_cfg.setFont(font)
        self.btn_edit_cfg.clicked.connect(self._edit_config)
        config_row.addWidget(self.btn_edit_cfg)

        self.btn_delele_cfg = QToolButton()
        self.btn_delele_cfg.setText("🗑")
        self.btn_delele_cfg.setToolTip("Delete current configuration")
        self.btn_delele_cfg.setFixedSize(32, 32)
        font = self.btn_delele_cfg.font()
        font.setPointSize(16)
        self.btn_delele_cfg.setFont(font)
        self.btn_delele_cfg.clicked.connect(self._delete_config)
        config_row.addWidget(self.btn_delele_cfg)

        # Description text box (read-only, scrollable, below config row)
        self.cfg_description = QtWidgets.QTextEdit()
        self.cfg_description.setReadOnly(True)
        self.cfg_description.setStyleSheet(
            "QTextEdit { background-color: palette(window); color: palette(text); }"
        )
        self.cfg_description.setFixedHeight(60)
        self.cfg_description.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.cfg_description.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.cfg_description.setWordWrapMode(QtGui.QTextOption.WordWrap)
        self.cfg_description.setPlainText("No description")
        project_vbox.addWidget(self.cfg_description)

        # =====================================================================
        # Horizontal divider between Project and Rules
        # =====================================================================
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(divider)

        # =====================================================================
        # Rules Group (always visible, read-only by default)
        # =====================================================================
        self._rules_group = QGroupBox("Rules", self.parent)
        main_layout.addWidget(self._rules_group, stretch=1)

        rules_outer_layout = QtWidgets.QVBoxLayout(self._rules_group)

        # _rules_content is now always visible
        self._rules_content = QtWidgets.QWidget()
        rules_outer_layout.addWidget(self._rules_content)

        rules_content_layout = QtWidgets.QVBoxLayout(self._rules_content)
        rules_content_layout.setContentsMargins(0, 0, 0, 0)
        rules_content_layout.setSpacing(6)

        # Edit header (name + description) — shown only for new/duplicate
        self._edit_header = QtWidgets.QWidget()
        rules_content_layout.addWidget(self._edit_header)

        edit_header_layout = QtWidgets.QHBoxLayout(self._edit_header)
        edit_header_layout.setContentsMargins(0, 0, 0, 0)

        lbl_name = QtWidgets.QLabel("Name:")
        edit_header_layout.addWidget(lbl_name)
        self._edit_name_input = QtWidgets.QLineEdit()
        edit_header_layout.addWidget(self._edit_name_input)

        lbl_desc = QtWidgets.QLabel("Desc:")
        edit_header_layout.addWidget(lbl_desc)
        self._edit_desc_input = QtWidgets.QLineEdit()
        edit_header_layout.addWidget(self._edit_desc_input)

        self._edit_header.setVisible(False)  # Hidden until new/duplicate

        # Splitter: RuleTreeWidget + RuleDetailPanel
        self._splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal, self._rules_content)
        rules_content_layout.addWidget(self._splitter, stretch=1)

        self._rule_tree = RuleTreeWidget(self._splitter)
        self._splitter.addWidget(self._rule_tree)

        self._rule_detail = RuleDetailPanel(self._splitter)
        self._splitter.addWidget(self._rule_detail)

        self._splitter.setSizes([450, 750])

        # Wire signals
        self._rule_tree.rule_selected.connect(self._on_rule_selected)
        self._rule_tree.rule_toggled.connect(self._on_rule_toggled)
        self._rule_detail.config_changed.connect(self._on_config_changed)

        # Populate tree with all known rules (initially in read-only mode)
        all_rules = list(self.state.known_ins_rules) + list(self.state.known_blk_rules)
        self._rule_tree.set_rules(all_rules)
        self._rule_tree.set_read_only(True)
        self._rule_detail.set_read_only(True)

        # State for storing per-rule config overrides during editing
        self._rule_configs: dict[str, dict] = {}

        # Save/Cancel buttons (right-aligned, hidden initially)
        button_layout = QtWidgets.QHBoxLayout()
        rules_content_layout.addLayout(button_layout)
        button_layout.addStretch()

        self._btn_save_rules = QtWidgets.QPushButton("Save")
        self._btn_save_rules.clicked.connect(self._save_rules)
        self._btn_save_rules.setVisible(False)
        button_layout.addWidget(self._btn_save_rules)

        self._btn_cancel_rules = QtWidgets.QPushButton("Cancel")
        self._btn_cancel_rules.clicked.connect(self._cancel_rules)
        self._btn_cancel_rules.setVisible(False)
        button_layout.addWidget(self._btn_cancel_rules)

        # =====================================================================
        # Engine Group (always visible, compact)
        # =====================================================================
        self._engine_group = QGroupBox("Engine", self.parent)
        main_layout.addWidget(self._engine_group)

        engine_layout = QtWidgets.QHBoxLayout(self._engine_group)

        self.btn_start = QtWidgets.QPushButton("Start")
        self.btn_start.clicked.connect(self._start_d810)
        engine_layout.addWidget(self.btn_start)

        self.btn_stop = QtWidgets.QPushButton("Stop")
        self.btn_stop.clicked.connect(self._stop_d810)
        engine_layout.addWidget(self.btn_stop)

        self.btn_config = QtWidgets.QPushButton("Config")
        self.btn_config.clicked.connect(self._configure_plugin)
        engine_layout.addWidget(self.btn_config)

        self.btn_logger_cfg = QtWidgets.QPushButton("Loggers")
        self.btn_logger_cfg.setToolTip("Adjust log-levels at runtime")
        self.btn_logger_cfg.clicked.connect(self._configure_logging)
        engine_layout.addWidget(self.btn_logger_cfg)

        self.btn_start_profiling = QtWidgets.QPushButton("Profile")
        self.btn_start_profiling.setToolTip(
            "Toggle profiling: start to capture, stop to save report"
        )
        self.btn_start_profiling.clicked.connect(self._toggle_profiling)
        engine_layout.addWidget(self.btn_start_profiling)

        if TestRunnerForm is not None:
            self.btn_test_runner = QtWidgets.QPushButton("TestRunner")
            self.btn_test_runner.clicked.connect(self._show_test_runner)
            engine_layout.addWidget(self.btn_test_runner)

        # Status is now shown via the circle indicator in the Project group
        self._update_status(loaded=False)

        # =====================================================================
        # Final initialization
        # =====================================================================
        self.update_cfg_select()
        self.cfg_select.setCurrentIndex(self.state.current_project_index)
        self.cfg_select.currentIndexChanged.connect(self._load_config)

        # Load the current config to populate the Rules tree immediately
        self._load_config(self.state.current_project_index)

    def _update_status(self, loaded: bool) -> None:
        """Update the status indicator circle."""
        if self._status_indicator is None:
            logger.debug("Cannot update status indicator: widget not created yet")
            return
        if loaded:
            self._status_indicator.setText(
                '<span style="color: #4CAF50; font-size: 20px;">●</span>'
            )
            self._status_indicator.setToolTip("D810 is running")
        else:
            self._status_indicator.setText(
                '<span style="color: #D32F2F; font-size: 20px;">●</span>'
            )
            self._status_indicator.setToolTip("D810 is stopped")

    def _on_rule_selected(self, rule) -> None:
        """Show the selected rule's detail panel."""
        if rule is not None:
            # Inject any stored config overrides into the rule's config dict
            # so the detail panel shows current values.
            stored = self._rule_configs.get(rule.name)
            if stored:
                rule.config.update(stored)
        self._rule_detail.set_rule(rule)

    def _on_rule_toggled(self, rule, is_enabled: bool) -> None:
        """Track rule enable/disable state (already handled by the tree)."""
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Rule toggled: %s -> %s", rule.name, is_enabled)

    def _on_config_changed(self, param_name: str, value) -> None:
        """Store config changes for the currently-selected rule."""
        rule = self._rule_detail._current_rule
        if rule is None:
            return
        cfg = self._rule_configs.setdefault(rule.name, {})
        cfg[param_name] = value
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Config stored: %s.%s = %s", rule.name, param_name, value)

    def update_cfg_select(self):
        logger.debug("Calling update_cfg_select")
        tmp = self.state.current_project_index
        self.cfg_select.clear()
        # Display basename for readability
        self.cfg_select.addItems(self.state.project_manager.project_names())
        self.cfg_select.setCurrentIndex(tmp)

    # =========================================================================
    # Edit state machine
    # =========================================================================

    def _enter_edit_mode(
        self,
        mode: str,
        description: str,
        ins_rules: list[RuleConfiguration],
        blk_rules: list[RuleConfiguration],
        path: pathlib.Path | None,
        old_conf: ProjectConfiguration | None,
    ) -> None:
        """Enter edit mode (new, duplicate, or edit).

        Args:
            mode: One of "new", "duplicate", or "edit"
            description: Project description
            ins_rules: Instruction-level rules
            blk_rules: Block-level rules
            path: Path to save (None for new/duplicate)
            old_conf: Old configuration (for edit mode)
        """
        logger.debug("Entering edit mode: %s", mode)

        self._edit_mode = mode
        self._edit_path = path
        self._edit_old_conf = old_conf

        # Build enabled set and per-rule config dict from RuleConfiguration lists
        enabled_names: set[str] = set()
        self._rule_configs.clear()

        for rc in ins_rules:
            if rc.is_activated:
                enabled_names.add(rc.name)
            if rc.config:
                self._rule_configs[rc.name] = dict(rc.config)

        for rc in blk_rules:
            if rc.is_activated:
                enabled_names.add(rc.name)
            if rc.config:
                self._rule_configs[rc.name] = dict(rc.config)

        # Update tree to show enabled rules
        self._rule_tree.set_enabled_rules(enabled_names)

        # Make tree and detail panel editable
        self._rule_tree.set_read_only(False)
        self._rule_detail.set_read_only(False)

        # Show edit header only for new/duplicate
        if mode in ("new", "duplicate"):
            self._edit_header.setVisible(True)
            self._edit_name_input.setText("")
            self._edit_desc_input.setText(description)
        else:
            self._edit_header.setVisible(False)

        # Update title and show Save/Cancel buttons
        self._rules_group.setTitle("Rules (editing)")
        self._btn_save_rules.setVisible(True)
        self._btn_cancel_rules.setVisible(True)

        # Disable Project and Engine groups
        self._project_group.setEnabled(False)
        self._engine_group.setEnabled(False)

    def _exit_edit_mode(self) -> None:
        """Exit edit mode and return to view mode."""
        logger.debug("Exiting edit mode")

        # Update title and hide Save/Cancel buttons
        self._rules_group.setTitle("Rules")
        self._btn_save_rules.setVisible(False)
        self._btn_cancel_rules.setVisible(False)

        # Hide edit header
        self._edit_header.setVisible(False)

        # Make tree and detail panel read-only
        self._rule_tree.set_read_only(True)
        self._rule_detail.set_read_only(True)

        # Re-enable Project and Engine groups
        self._project_group.setEnabled(True)
        self._engine_group.setEnabled(True)

        # Clear edit state
        self._edit_mode = None
        self._edit_path = None
        self._edit_old_conf = None
        self._rule_configs.clear()

    def _save_rules(self) -> None:
        """Save the current rule configuration."""
        logger.debug("Saving rules (mode: %s)", self._edit_mode)

        # Determine save path
        if self._edit_mode in ("new", "duplicate"):
            # Open file dialog
            fname, _ = QtWidgets.QFileDialog.getSaveFileName(
                self.parent,
                "Save configuration",
                str(self.state.d810_config.config_dir),
                "Project configuration (*.json)",
            )
            if not fname:
                return  # User cancelled
            save_path = pathlib.Path(fname)
            description = self._edit_desc_input.text()
        elif self._edit_mode == "edit":
            # Save to user cfg dir (same as _resolve_config_path user path)
            save_path = self.state.d810_config.config_dir / self._edit_path.name
            description = self.state.current_project.description
        else:
            logger.error("Invalid edit mode: %s", self._edit_mode)
            return

        # Build RuleConfiguration lists from tree state
        enabled = self._rule_tree.get_enabled_rule_names()
        ins_rules = []
        for rule in self.state.known_ins_rules:
            if rule.name in enabled:
                ins_rules.append(
                    RuleConfiguration(
                        name=rule.name,
                        is_activated=True,
                        config=self._rule_configs.get(rule.name, {}),
                    )
                )

        blk_rules = []
        for rule in self.state.known_blk_rules:
            if rule.name in enabled:
                blk_rules.append(
                    RuleConfiguration(
                        name=rule.name,
                        is_activated=True,
                        config=self._rule_configs.get(rule.name, {}),
                    )
                )

        # Create and save ProjectConfiguration
        new_config = ProjectConfiguration(
            path=save_path,
            description=description,
            ins_rules=ins_rules,
            blk_rules=blk_rules,
        )
        new_config.save()

        # Update state
        if self._edit_mode in ("new", "duplicate"):
            self.state.add_project(new_config)
        else:  # edit
            self.state.update_project(self._edit_old_conf, new_config)

        # Update UI
        self.update_cfg_select()

        # Find the index of the newly saved config
        for i, proj in enumerate(self.state.project_manager.projects()):
            if proj.path == save_path:
                self.cfg_select.setCurrentIndex(i)
                break

        # Exit edit mode
        self._exit_edit_mode()

    def _cancel_rules(self) -> None:
        """Cancel editing and return to view mode."""
        logger.debug("Cancelling rule edit")
        self._exit_edit_mode()

    def _create_config(self):
        logger.debug("Calling _create_config")
        self._enter_edit_mode("new", "", [], [], None, None)

    def _duplicate_config(self):
        logger.debug("Calling _duplicate_config")
        cur_cfg = self.state.current_project
        self._enter_edit_mode(
            "duplicate",
            "Duplicate of " + cur_cfg.description,
            cur_cfg.ins_rules,
            cur_cfg.blk_rules,
            None,
            None,
        )

    def _edit_config(self):
        logger.debug("Calling _edit_config")
        cur_cfg = self.state.current_project
        self._enter_edit_mode(
            "edit",
            cur_cfg.description,
            cur_cfg.ins_rules,
            cur_cfg.blk_rules,
            cur_cfg.path,
            cur_cfg,
        )

    # callback when the "Delete" button is clicked
    def _delete_config(self):
        logger.debug("Calling _delete_config")
        self.state.project_manager.delete(self.state.current_project)
        self.update_cfg_select()

    # Called when the edit combo is changed
    def _load_config(self, index: int):
        if logger.debug_on:
            projects = self.state.project_manager.projects()
            logger.debug(
                "Calling _load_config with index %s (%s), current project index %s (%s)",
                index,
                projects[index].path.name,
                self.state.current_project_index,
                projects[self.state.current_project_index].path.name,
            )
        project = self.state.load_project(index)
        self.cfg_description.setPlainText(project.description)

        # Populate rules tree with the current config's rules (read-only mode)
        enabled_names: set[str] = set()
        for rc in project.ins_rules:
            if rc.is_activated:
                enabled_names.add(rc.name)
        for rc in project.blk_rules:
            if rc.is_activated:
                enabled_names.add(rc.name)

        self._rule_tree.set_enabled_rules(enabled_names)
        return

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
