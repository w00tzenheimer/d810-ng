"""Deobfuscation statistics panel as a dockable IDA PluginForm.

Provides a Qt-based UI for viewing d810-ng optimization statistics with
filter bar and action buttons for rule management and CSV export.

Follows the CTO function lister lifecycle pattern:
- Widgets created in __init__ BEFORE Show()
- OnCreate attaches layout only
- show() calls display_widget AFTER Show()
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


# Fallback for WOPN_NOT_CLOSED_BY_ESC if not available (CTO pattern)
if IDA_AVAILABLE:
    if not hasattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC"):
        WOPN_NOT_CLOSED_BY_ESC = 0x100
    else:
        WOPN_NOT_CLOSED_BY_ESC = ida_kernwin.WOPN_NOT_CLOSED_BY_ESC  # type: ignore[attr-defined]


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtGui, QtWidgets


class StatsTreeWidget(QtWidgets.QTreeView):
    """Stats tree view widget with CTO-style filter bar (pfilter pattern)."""

    def __init__(self) -> None:
        """Initialize tree view, model, proxy, and filter bar."""
        QtWidgets.QTreeView.__init__(self)

        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(False)  # enabled after populate

        # Generate source model (CTO pattern)
        self.model = QtGui.QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Category", "Name", "Count"])

        # Set proxy model for filter (CTO pattern)
        self.proxy_model = QtCore.QSortFilterProxyModel()
        self.proxy_model.setRecursiveFilteringEnabled(True)
        self.proxy_model.setFilterKeyColumn(-1)  # search all columns

        # Connect tree view with source model through proxy model (CTO pattern)
        self.setModel(self.proxy_model)
        self.proxy_model.setSourceModel(self.model)

        # Set selection model (CTO pattern)
        self.sel_model = QtCore.QItemSelectionModel(self.proxy_model)
        self.setSelectionModel(self.sel_model)

        # --------------------------------------
        # Create line edit widget for filter (CTO pfilter pattern)
        # --------------------------------------
        self.filter = QtWidgets.QLineEdit()
        self.filter.setToolTip("Filter by keyword")

        # Create check boxes (CTO pattern)
        self.regex_box = QtWidgets.QCheckBox("RegEx")
        self.regex_box.setToolTip("Enable regex")
        self.cs_box = QtWidgets.QCheckBox("CS")
        self.cs_box.setToolTip("Case sensitive")

        # [X] button (CTO pattern)
        self.clear_btn = QtWidgets.QPushButton("X")
        self.clear_btn.setContentsMargins(0, 0, 0, 0)
        self.clear_btn.setFixedWidth(25)
        self.clear_btn.setToolTip("Clear filter")

        # [▼] menu button (CTO pattern)
        self.menu_btn = QtWidgets.QPushButton("")
        self.menu_btn.setContentsMargins(0, 0, 0, 0)
        self.menu_btn.setFixedWidth(20)
        self.menu_btn.setToolTip("Actions")

        # [+] button for saving rules (d810-specific)
        self.add_btn = QtWidgets.QPushButton("+")
        self.add_btn.setContentsMargins(0, 0, 0, 0)
        self.add_btn.setFixedWidth(25)
        self.add_btn.setToolTip("Save fired rules for function")

        # Create parent widget for filter bar (CTO pfilter pattern EXACTLY)
        self.pfilter = QtWidgets.QWidget()
        filter_layout = QtWidgets.QHBoxLayout(self.pfilter)
        filter_layout.setContentsMargins(0, 0, 0, 0)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(0)

        filter_layout.addLayout(btn_layout)
        filter_layout.addWidget(self.filter)
        filter_layout.addWidget(self.regex_box)
        filter_layout.addWidget(self.cs_box)

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.menu_btn)

        # Set hooks for filter changes (CTO pattern)
        self.filter.textChanged.connect(self._on_filter_text_changed)
        self.regex_box.stateChanged.connect(self._on_filter_changed)
        self.cs_box.stateChanged.connect(self._on_filter_changed)
        self.clear_btn.pressed.connect(self.clear_filter)

        # Appearance tweaks (d810-specific: flat list)
        self.setRootIsDecorated(False)  # flat list, no expand arrows
        self.setUniformRowHeights(True)  # performance
        self.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

    def clear_filter(self) -> None:
        """Clear the filter text (CTO pattern)."""
        self.filter.clear()

    def _on_filter_text_changed(self, text: str) -> None:
        """Handle filter text change (triggers filter update)."""
        self._on_filter_changed()

    def _on_filter_changed(self) -> None:
        """Apply filter to proxy model (CTO pattern with Qt5/Qt6 compatibility)."""
        text = self.filter.text()

        if self.regex_box.isChecked():
            # Try Qt6 first, fall back to Qt5
            try:
                # Qt6 path
                regex = QtCore.QRegularExpression(text)
                if not self.cs_box.isChecked():
                    regex.setPatternOptions(
                        QtCore.QRegularExpression.PatternOption.CaseInsensitiveOption
                    )
                self.proxy_model.setFilterRegularExpression(regex)
            except AttributeError:
                # Qt5 path
                import re as _re

                syntax = QtCore.QRegExp.PatternSyntax.RegExp
                cs = (
                    QtCore.Qt.CaseSensitivity.CaseSensitive
                    if self.cs_box.isChecked()
                    else QtCore.Qt.CaseSensitivity.CaseInsensitive
                )
                self.proxy_model.setFilterRegExp(QtCore.QRegExp(text, cs, syntax))
        else:
            cs = (
                QtCore.Qt.CaseSensitivity.CaseSensitive
                if self.cs_box.isChecked()
                else QtCore.Qt.CaseSensitivity.CaseInsensitive
            )
            try:
                self.proxy_model.setFilterCaseSensitivity(cs)
                self.proxy_model.setFilterFixedString(text)
            except AttributeError:
                self.proxy_model.setFilterFixedString(text)


class DeobfuscationStatsPanel(ida_kernwin.PluginForm):
    """Dockable panel for d810-ng deobfuscation statistics (CTO pattern).

    Features:
    - Qt table with sortable columns showing stats by category
    - Filter bar with regex/case-sensitive options (CTO pfilter)
    - [+] button to enable/disable rules per function
    - [▼] menu for refresh and CSV export
    - Persistent docking (stays open between invocations)

    Lifecycle (CTO pattern):
    - Widgets created in __init__ BEFORE Show()
    - OnCreate attaches layout only
    - show() calls display_widget AFTER Show()
    """

    TITLE = "d810-ng Statistics"

    def __init__(self, state: typing.Any):
        """Initialize the stats panel.

        Args:
            state: D810State instance
        """
        ida_kernwin.PluginForm.__init__(self)
        self._state = state
        self._stats: dict[str, typing.Any] = {}
        self._func_ea: int | None = None
        self._func_name: str | None = None
        self._closed = False

        # Create tree BEFORE Show (CTO pattern)
        self.tree = StatsTreeWidget()
        self.model = self.tree.model
        self.proxy_model = self.tree.proxy_model

        # Menu for [▼] button
        self.filter_menu = QtWidgets.QMenu("")
        refresh_action = self.filter_menu.addAction("Refresh")
        refresh_action.triggered.connect(self._refresh_data)
        export_action = self.filter_menu.addAction("Export CSV")
        export_action.triggered.connect(self._export_csv)
        self.tree.menu_btn.setMenu(self.filter_menu)

        # Menu for [+] button
        self.add_menu = QtWidgets.QMenu("")
        self.tree.add_btn.setMenu(self.add_menu)
        self.add_menu.aboutToShow.connect(self._rebuild_add_menu)

    def OnCreate(self, form: typing.Any) -> None:
        """Called when the plugin form is created (CTO pattern).

        Args:
            form: IDA form handle
        """
        # Get parent widget (CTO pattern)
        self.parent = self.FormToPyQtWidget(form)

        self.create_tree()

    def OnClose(self, form: typing.Any) -> None:
        """Called when IDA destroys the form. Clean up to prevent shutdown crash.

        Args:
            form: IDA form handle
        """
        self._closed = True

        # Disconnect all signals to prevent PySide6 crash during Python finalization
        try:
            if self.tree is not None:
                self.tree.filter.textChanged.disconnect()
                self.tree.regex_box.stateChanged.disconnect()
                self.tree.cs_box.stateChanged.disconnect()
                self.tree.clear_btn.pressed.disconnect()
                if hasattr(self, 'filter_menu'):
                    pass  # QMenu signals auto-disconnect when parent is destroyed
                if hasattr(self, 'add_menu'):
                    self.add_menu.aboutToShow.disconnect()
        except (RuntimeError, TypeError):
            pass  # Already disconnected or C++ object already deleted

        # Clear references to prevent dangling C++ references
        self.tree = None
        self.model = None
        self.proxy_model = None
        self.parent = None

    def create_tree(self) -> None:
        """Build the tree layout and populate data (CTO pattern)."""
        # Build the stats table
        self.tree.setSortingEnabled(False)
        self._refresh_data()

        # Adjust header length (CTO pattern)
        self.tree.header().setMinimumSectionSize(10)
        try:
            rmode = self.tree.header().Interactive
        except AttributeError:
            rmode = self.tree.header().ResizeMode.Interactive
        self.tree.header().setSectionResizeMode(0, rmode)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().resizeSection(0, 75)  # Category

        # Name column stretches (CTO pattern)
        try:
            smode = self.tree.header().Stretch
        except AttributeError:
            smode = self.tree.header().ResizeMode.Stretch
        self.tree.header().setSectionResizeMode(1, smode)

        # Right-click context menu
        self.tree.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._build_context_menu)

        # Create layout (CTO pattern EXACTLY)
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(2, 0, 0, 0)
        layout.addWidget(self.tree)
        layout.addWidget(self.tree.pfilter)

        # Populate PluginForm (CTO pattern)
        self.parent.setLayout(layout)

        # Sort after layout (CTO pattern)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, QtCore.Qt.SortOrder.AscendingOrder)

        self.tree.setFocus()

    def Show(self) -> bool:
        """Show the form (CTO pattern).

        Returns:
            True if successful, False otherwise
        """
        return ida_kernwin.PluginForm.Show(
            self, self.TITLE, options=ida_kernwin.PluginForm.WOPN_PERSIST
        )

    def show(self) -> bool:
        """Show and dock the panel (CTO pattern).

        Returns:
            True if successful, False otherwise
        """
        r = self.Show()
        if r:
            # CTO pattern: display_widget AFTER Show
            ida_kernwin.display_widget(self.GetWidget(), WOPN_NOT_CLOSED_BY_ESC, None)
            ida_kernwin.set_dock_pos(self.TITLE, "IDA View-A", ida_kernwin.DP_TAB)

        # Resize columns after display (CTO pattern — only works after widget visible)
        for i in range(self.model.columnCount()):
            self.tree.resizeColumnToContents(i)

        self.tree.setFocus()
        return r

    def set_function(self, func_ea: int | None, func_name: str | None) -> None:
        """Update the function context.

        Args:
            func_ea: Function entry address
            func_name: Function name
        """
        self._func_ea = func_ea
        self._func_name = func_name

    def _refresh_data(self) -> None:
        """Refresh the statistics table."""
        from d810.ui.actions_logic import get_deobfuscation_stats, stats_to_table_rows

        # Get fresh stats
        if hasattr(self._state, "manager") and self._state.manager is not None:
            self._stats = get_deobfuscation_stats(self._state.manager)
        else:
            self._stats = {}

        # Convert to table rows
        rows = stats_to_table_rows(self._stats)

        # Update table
        self._populate_table(rows)

    def _populate_table(self, rows: list[tuple[str, str, str]]) -> None:
        """Populate the table with data rows.

        Args:
            rows: List of (category, name, count_str) tuples
        """
        self.model.removeRows(0, self.model.rowCount())

        for category, name, count_str in rows:
            category_item = QtGui.QStandardItem(category)
            name_item = QtGui.QStandardItem(name)
            count_item = QtGui.QStandardItem(count_str)

            # Right-align count column for numeric readability
            count_item.setTextAlignment(
                QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter
            )

            items = [category_item, name_item, count_item]

            for item in items:
                item.setEditable(False)

            self.model.appendRow(items)

    def _rebuild_add_menu(self) -> None:
        """Rebuild the [+] button context menu."""
        self.add_menu.clear()

        # No function selected
        if self._func_ea is None:
            action = self.add_menu.addAction("(no function selected)")
            action.setEnabled(False)
            return

        from d810.ui.stats_logic import get_fired_rule_names

        # Get fired rules from stats
        fired_rule_names = get_fired_rule_names(self._stats)

        # Check if any rules fired
        if not fired_rule_names:
            action = self.add_menu.addAction("(no rules fired)")
            action.setEnabled(False)
            return

        # Add "Save for function" option
        action = self.add_menu.addAction("Save for function")
        action.triggered.connect(self._on_save_for_function)

    def _on_save_for_function(self) -> None:
        """Handle save fired rules for function action."""
        if self._func_ea is None:
            return

        from d810.ui.stats_logic import get_fired_rule_names, save_fired_rules_for_function

        # Get fired rules from stats
        fired_rule_names = get_fired_rule_names(self._stats)

        if not fired_rule_names:
            ida_kernwin.msg("d810-ng: No fired rules to save\n")
            return

        # Create function rule config with fired rules
        func_rule_config = save_fired_rules_for_function(
            func_ea=self._func_ea,
            fired_rule_names=fired_rule_names,
            func_name=self._func_name or f"sub_{self._func_ea:X}",
        )

        # Persist to storage
        storage = None
        if hasattr(self._state, "manager") and hasattr(self._state.manager, "storage"):
            storage = self._state.manager.storage
            if storage is not None:
                storage.set_function_rules(
                    function_addr=self._func_ea,
                    enabled_rules=func_rule_config.enabled_rules,
                    disabled_rules=func_rule_config.disabled_rules,
                    notes=func_rule_config.notes,
                )

        # Show confirmation
        func_name = self._func_name or f"sub_{self._func_ea:X}"
        ida_kernwin.msg(f"d810-ng: Saved {len(fired_rule_names)} rules for {func_name}\n")

    def _export_csv(self) -> None:
        """Export statistics to CSV file."""
        from d810.ui.actions_logic import stats_to_csv

        # Show file dialog
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.parent,
            "Export Statistics to CSV",
            "",
            "CSV Files (*.csv);;All Files (*)",
        )

        if not file_path:
            return

        # Generate CSV
        csv_content = stats_to_csv(
            self._stats,
            func_ea=self._func_ea,
            func_name=self._func_name,
        )

        # Write to file
        try:
            with open(file_path, "w") as f:
                f.write(csv_content)
            ida_kernwin.msg(f"d810-ng: Exported statistics to {file_path}\n")
        except Exception as e:
            ida_kernwin.warning(f"Failed to export CSV: {e}")

    def _build_context_menu(self, pos: typing.Any) -> None:
        """Build right-click context menu (stub for future expansion)."""
        pass

    def __del__(self):
        """Safety net for garbage collection."""
        self._closed = True


# Stub classes when IDA is not available (for unit test imports)
if not IDA_AVAILABLE:

    class StatsTreeWidget:  # type: ignore[no-redef]
        """Stub tree widget when IDA is not available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any):
            raise ImportError("StatsTreeWidget requires IDA Pro")

    class DeobfuscationStatsPanel:  # type: ignore[no-redef]
        """Stub panel when IDA is not available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any):
            raise ImportError("DeobfuscationStatsPanel requires IDA Pro")
