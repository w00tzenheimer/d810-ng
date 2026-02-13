# -*- coding: utf-8 -*-
"""Tree-based rule browser widget for D-810.

Groups optimization rules by their CATEGORY class attribute and displays
them in a QTreeWidget with inline checkboxes for enable/disable. Supports
text-based filtering and emits signals when the user selects a rule.
"""
from __future__ import annotations

import logging
import typing

from d810.qt_shim import QtCore, QtWidgets, qt_flag_or, QColor, QBrush

if typing.TYPE_CHECKING:
    from d810.optimizers.microcode.handler import OptimizationRule

logger = logging.getLogger("D810.ui.rule_tree")

# Qt role used to store the rule object reference on tree items.
try:
    RULE_DATA_ROLE: int = int(QtCore.Qt.UserRole) + 1
except (TypeError, ValueError):
    RULE_DATA_ROLE: int = 0x0100 + 1  # fallback for non-GUI stubs

# Color constants for rule states
COLOR_ENABLED = QColor(76, 175, 80)  # Material Green 500
COLOR_DISABLED = QColor(158, 158, 158)  # Material Gray


class RuleTreeWidget(QtWidgets.QWidget):
    """A filterable tree that groups rules by CATEGORY.

    Signals
    -------
    rule_selected(object)
        Emitted when the user clicks a rule item.  The payload is the
        :class:`OptimizationRule` instance (or *None* when a category
        header is selected).
    rule_toggled(object, bool)
        Emitted when a rule's checkbox is toggled.  Payload is
        ``(rule, is_enabled)``.
    """

    # Signals ----------------------------------------------------------------
    rule_selected = QtCore.pyqtSignal(object)
    rule_toggled = QtCore.pyqtSignal(object, bool)

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._rules: list[OptimizationRule] = []
        self._enabled_rules: set[str] = set()  # names of enabled rules
        self._read_only: bool = False

        # --- Layout -----------------------------------------------------------
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Filter bar
        self._filter_edit = QtWidgets.QLineEdit(self)
        self._filter_edit.setPlaceholderText("Filter rules...")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self._filter_edit)

        # Legend strip
        legend_widget = QtWidgets.QWidget(self)
        legend_layout = QtWidgets.QHBoxLayout(legend_widget)
        legend_layout.setContentsMargins(4, 2, 4, 2)
        legend_layout.setSpacing(8)

        # Enabled legend item
        enabled_label = QtWidgets.QLabel(
            "<span style='color:#4CAF50'>●</span> Enabled", legend_widget
        )
        enabled_label.setStyleSheet("font-size: 10px")
        legend_layout.addWidget(enabled_label)

        # Disabled legend item
        disabled_label = QtWidgets.QLabel(
            "<span style='color:#9E9E9E'>●</span> Disabled", legend_widget
        )
        disabled_label.setStyleSheet("font-size: 10px")
        legend_layout.addWidget(disabled_label)

        # Configurable legend item
        configurable_label = QtWidgets.QLabel(
            "⚙ Configurable", legend_widget
        )
        configurable_label.setStyleSheet("font-size: 10px")
        legend_layout.addWidget(configurable_label)

        legend_layout.addStretch(1)
        layout.addWidget(legend_widget)

        # Tree widget
        self._tree = QtWidgets.QTreeWidget(self)
        self._tree.setColumnCount(1)
        self._tree.setHeaderLabels(["Rules"])
        self._tree.setRootIsDecorated(True)
        self._tree.setExpandsOnDoubleClick(True)
        self._tree.setSelectionMode(QtWidgets.QTreeWidget.SingleSelection)
        self._tree.itemClicked.connect(self._on_item_clicked)
        self._tree.currentItemChanged.connect(self._on_current_item_changed)
        self._tree.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._tree)

        # Enable custom context menu
        self._tree.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

    # --- Public API ---------------------------------------------------------

    def set_rules(
        self,
        rules: list[OptimizationRule],
        enabled_names: set[str] | None = None,
    ) -> None:
        """Populate the tree with *rules*, grouped by CATEGORY.

        Parameters
        ----------
        rules:
            Full list of known rule instances.
        enabled_names:
            Set of rule *names* that should appear as checked.
        """
        self._rules = list(rules)
        self._enabled_rules = set(enabled_names) if enabled_names else set()
        self._rebuild_tree()

    def set_enabled_rules(self, enabled_names: set[str]) -> None:
        """Update which rules are checked without a full rebuild."""
        self._enabled_rules = set(enabled_names)
        self._rebuild_tree()

    def get_enabled_rule_names(self) -> set[str]:
        """Return the set of currently-checked rule names."""
        return set(self._enabled_rules)

    def set_read_only(self, read_only: bool) -> None:
        """Set read-only mode.

        When enabled, rule checkboxes are hidden (items remain selectable).
        The filter bar remains functional regardless of read-only state.

        Parameters
        ----------
        read_only:
            If True, disable checkboxes on all rule items.
        """
        self._read_only = read_only
        self._rebuild_tree()

    # --- Internal -----------------------------------------------------------

    def _rebuild_tree(self) -> None:
        """(Re)build the tree, grouping rules by optimizer type then CATEGORY."""
        self._tree.blockSignals(True)
        self._tree.clear()

        # Group rules by optimizer type, then by category
        optimizer_groups = self._group_by_optimizer_type(self._rules)
        filter_text = self._filter_edit.text().strip().lower()

        for opt_type_name in ["Instruction Optimizers", "Block Optimizers", "Ctree Optimizers"]:
            rules_in_type = optimizer_groups.get(opt_type_name, [])
            if not rules_in_type:
                continue

            # Group by category within this optimizer type
            categories: dict[str, list[OptimizationRule]] = {}
            for rule in rules_in_type:
                cat = getattr(rule, "CATEGORY", "General")
                categories.setdefault(cat, []).append(rule)

            # Pre-filter rules
            if filter_text:
                visible_rules_all = [
                    r for r in rules_in_type
                    if filter_text in r.name.lower()
                ]
            else:
                visible_rules_all = rules_in_type

            if not visible_rules_all and filter_text:
                continue  # skip empty optimizer type when filtering

            # Top-level item: optimizer type
            type_item = QtWidgets.QTreeWidgetItem()
            self._tree.addTopLevelItem(type_item)

            # Count enabled rules in this optimizer type
            enabled_count = sum(
                1 for r in rules_in_type if r.name in self._enabled_rules
            )
            total_count = len(rules_in_type)
            type_item.setText(
                0,
                f"{opt_type_name} ({enabled_count}/{total_count} enabled)",
            )

            # Bold font for optimizer type headers
            font = type_item.font(0)
            font.setBold(True)
            font.setPointSize(font.pointSize() + 1)
            type_item.setFont(0, font)

            # Disable checkbox on optimizer type items
            type_item.setFlags(
                qt_flag_or(QtCore.Qt.ItemIsEnabled, QtCore.Qt.ItemIsSelectable)
            )

            # Second level: categories within optimizer type
            for cat_name in sorted(categories):
                rules_in_cat = categories[cat_name]

                # Pre-filter rules for this category
                if filter_text:
                    visible_rules = [
                        r for r in rules_in_cat
                        if filter_text in r.name.lower()
                    ]
                else:
                    visible_rules = rules_in_cat

                if not visible_rules and filter_text:
                    continue  # skip empty categories when filtering

                cat_item = QtWidgets.QTreeWidgetItem(type_item)

                # Count enabled rules in this category
                cat_enabled_count = sum(
                    1 for r in rules_in_cat if r.name in self._enabled_rules
                )
                cat_total_count = len(rules_in_cat)
                cat_item.setText(
                    0,
                    f"{cat_name} ({cat_enabled_count}/{cat_total_count})",
                )

                # Bold font for category headers
                cat_font = cat_item.font(0)
                cat_font.setBold(True)
                cat_item.setFont(0, cat_font)

                # Color category header based on enabled rules
                if cat_enabled_count == cat_total_count and cat_total_count > 0:
                    # All rules enabled: green
                    cat_item.setForeground(0, QBrush(COLOR_ENABLED))
                elif cat_enabled_count == 0:
                    # No rules enabled: gray
                    cat_item.setForeground(0, QBrush(COLOR_DISABLED))
                # Else: some rules enabled - use default color (no override)

                # Disable checkbox on category items
                cat_item.setFlags(
                    qt_flag_or(QtCore.Qt.ItemIsEnabled, QtCore.Qt.ItemIsSelectable)
                )

                # Third level: individual rules
                for rule in visible_rules:
                    rule_item = QtWidgets.QTreeWidgetItem(cat_item)
                    has_extra_config = self._has_extended_schema(rule)
                    has_warning = any(
                        keyword in rule.description.upper()
                        for keyword in ["WARNING:", "CAUTION:", "DANGER:"]
                    )
                    display_name = rule.name
                    # Prepend warning icon if description contains warning
                    if has_warning:
                        display_name = f"\u26a0 {display_name}"
                    # Prepend gear icon for configurable rules
                    if has_extra_config:
                        display_name = f"\u2699 {display_name}"
                    rule_item.setText(0, display_name)
                    rule_item.setToolTip(0, rule.description)
                    rule_item.setData(0, RULE_DATA_ROLE, rule)

                    # Set color based on enabled state
                    is_enabled = rule.name in self._enabled_rules
                    rule_color = COLOR_ENABLED if is_enabled else COLOR_DISABLED
                    rule_item.setForeground(0, QBrush(rule_color))

                    # Checkbox - conditionally include based on read-only state
                    if self._read_only:
                        rule_item.setFlags(
                            qt_flag_or(QtCore.Qt.ItemIsEnabled, QtCore.Qt.ItemIsSelectable)
                        )
                    else:
                        rule_item.setFlags(
                            qt_flag_or(QtCore.Qt.ItemIsEnabled, QtCore.Qt.ItemIsSelectable, QtCore.Qt.ItemIsUserCheckable)
                        )
                        if rule.name in self._enabled_rules:
                            rule_item.setCheckState(0, QtCore.Qt.Checked)
                        else:
                            rule_item.setCheckState(0, QtCore.Qt.Unchecked)

                cat_item.setExpanded(True)

            type_item.setExpanded(True)

        self._tree.blockSignals(False)

    @staticmethod
    def _group_by_optimizer_type(rules: list[OptimizationRule]) -> dict[str, list[OptimizationRule]]:
        """Group rules by their optimizer type based on class hierarchy."""
        groups: dict[str, list[OptimizationRule]] = {
            "Instruction Optimizers": [],
            "Block Optimizers": [],
            "Ctree Optimizers": [],
        }

        for rule in rules:
            # Check class hierarchy by name to avoid IDA imports
            rule_class_names = {cls.__name__ for cls in type(rule).__mro__}

            if "InstructionOptimizationRule" in rule_class_names:
                groups["Instruction Optimizers"].append(rule)
            elif "FlowOptimizationRule" in rule_class_names:
                groups["Block Optimizers"].append(rule)
            elif "CtreeOptimizationRule" in rule_class_names:
                groups["Ctree Optimizers"].append(rule)
            else:
                # Fallback: classify as instruction optimizer if not clearly flow/ctree
                groups["Instruction Optimizers"].append(rule)

        return groups

    @staticmethod
    def _has_extended_schema(rule: OptimizationRule) -> bool:
        """Return True if *rule* defines CONFIG_SCHEMA params beyond the base."""
        from d810.optimizers.microcode.handler import OptimizationRule as BaseRule

        base_names = {p.name for p in BaseRule.CONFIG_SCHEMA}
        rule_names = {p.name for p in getattr(rule, "CONFIG_SCHEMA", ())}
        return bool(rule_names - base_names)

    def _apply_filter(self, _text: str) -> None:
        self._rebuild_tree()

    # --- Slots ---------------------------------------------------------------

    def _on_item_clicked(
        self, item: QtWidgets.QTreeWidgetItem, _column: int
    ) -> None:
        rule = item.data(0, RULE_DATA_ROLE)
        self.rule_selected.emit(rule)

    def _on_current_item_changed(
        self, current: QtWidgets.QTreeWidgetItem | None, _previous: QtWidgets.QTreeWidgetItem | None
    ) -> None:
        """Slot for currentItemChanged signal (keyboard + mouse navigation)."""
        if current is not None:
            rule = current.data(0, RULE_DATA_ROLE)
            self.rule_selected.emit(rule)

    def _on_item_changed(
        self, item: QtWidgets.QTreeWidgetItem, _column: int
    ) -> None:
        rule = item.data(0, RULE_DATA_ROLE)
        if rule is None:
            return  # category or optimizer type header
        is_checked = item.checkState(0) == QtCore.Qt.Checked
        if is_checked:
            self._enabled_rules.add(rule.name)
        else:
            self._enabled_rules.discard(rule.name)

        # Update item color based on new state
        rule_color = COLOR_ENABLED if is_checked else COLOR_DISABLED
        item.setForeground(0, QBrush(rule_color))

        # Update parent category label counts (if exists)
        category_parent = item.parent()
        if category_parent is not None:
            cat_text = category_parent.text(0)
            # Extract category name (before the parenthesized count)
            cat_name = cat_text.rsplit("(", 1)[0].strip()
            # Recount rules in this category
            cat_enabled = 0
            cat_total = 0
            for i in range(category_parent.childCount()):
                child = category_parent.child(i)
                cat_total += 1
                if child.checkState(0) == QtCore.Qt.Checked:
                    cat_enabled += 1
            category_parent.setText(0, f"{cat_name} ({cat_enabled}/{cat_total})")

            # Update category header color
            if cat_enabled == cat_total and cat_total > 0:
                # All rules enabled: green
                category_parent.setForeground(0, QBrush(COLOR_ENABLED))
            elif cat_enabled == 0:
                # No rules enabled: gray
                category_parent.setForeground(0, QBrush(COLOR_DISABLED))
            else:
                # Some rules enabled: reset to default (no color override)
                category_parent.setData(0, QtCore.Qt.ForegroundRole, None)

            # Update grandparent optimizer type label counts (if exists)
            optimizer_parent = category_parent.parent()
            if optimizer_parent is not None:
                opt_text = optimizer_parent.text(0)
                # Extract optimizer type name (before the parenthesized count)
                opt_name = opt_text.rsplit("(", 1)[0].strip()
                # Recount all rules in this optimizer type (across all categories)
                opt_enabled = 0
                opt_total = 0
                for i in range(optimizer_parent.childCount()):
                    cat_item = optimizer_parent.child(i)
                    for j in range(cat_item.childCount()):
                        rule_item = cat_item.child(j)
                        opt_total += 1
                        if rule_item.checkState(0) == QtCore.Qt.Checked:
                            opt_enabled += 1
                optimizer_parent.setText(0, f"{opt_name} ({opt_enabled}/{opt_total} enabled)")

        self.rule_toggled.emit(rule, is_checked)

    def _on_context_menu(self, pos: QtCore.QPoint) -> None:
        """Show context menu for category items with Select All/Deselect All."""
        if self._read_only:
            return  # No context menu in read-only mode

        item = self._tree.itemAt(pos)
        if item is None:
            return

        # Check if this is a category/optimizer item (has children but no rule data)
        is_category = (
            item.childCount() > 0 and
            item.data(0, RULE_DATA_ROLE) is None
        )

        if not is_category:
            return  # Only show menu for category/optimizer items

        # Create context menu
        menu = QtWidgets.QMenu(self._tree)

        select_all_action = menu.addAction("Select All")
        select_all_action.triggered.connect(
            lambda: self._set_category_check_state(item, QtCore.Qt.CheckState.Checked)
        )

        deselect_all_action = menu.addAction("Deselect All")
        deselect_all_action.triggered.connect(
            lambda: self._set_category_check_state(item, QtCore.Qt.CheckState.Unchecked)
        )

        # Show menu at global position
        menu.exec_(self._tree.viewport().mapToGlobal(pos))

    def _set_category_check_state(
        self,
        parent_item: QtWidgets.QTreeWidgetItem,
        state: QtCore.Qt.CheckState,
    ) -> None:
        """Recursively set check state for all rule items under a category.

        Parameters
        ----------
        parent_item:
            The category or optimizer item.
        state:
            The check state to apply (Checked or Unchecked).
        """
        for i in range(parent_item.childCount()):
            child = parent_item.child(i)

            # If this child has RULE_DATA_ROLE, it's a rule leaf item
            if child.data(0, RULE_DATA_ROLE) is not None:
                child.setCheckState(0, state)
            # If this child has children, it's a subcategory - recurse
            elif child.childCount() > 0:
                self._set_category_check_state(child, state)
