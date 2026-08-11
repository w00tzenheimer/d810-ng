"""Fixed Qt renderer for pass-owned config-v2 rule catalogs.

Rule registration owns all descriptions, family memberships, and safety
metadata.  This widget renders that closed contract; it never derives a group
from a name or executes a rule to discover its properties.
"""

from __future__ import annotations

from d810.core import typing
from d810.ui.config_v2_editing_logic import (
    ConfigV2RuleCatalogView,
    ConfigV2RuleView,
)
from d810.ui.qt_layout_policy import configure_overflow_menu_button
from d810.ui.workbench_structured_details_logic import DetailField, DetailSection

try:
    from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets, qt_flag_or
except ImportError:  # Narrow fake-Qt test adapters may omit this feature flag.
    from d810.qt_shim import QtCore, QtWidgets, qt_flag_or

    QT_GRAPHICS_AVAILABLE = False


def _user_role() -> typing.Any:
    try:
        return QtCore.Qt.ItemDataRole.UserRole
    except AttributeError:
        return QtCore.Qt.UserRole


def _checkable_flag() -> typing.Any:
    try:
        return QtCore.Qt.ItemFlag.ItemIsUserCheckable
    except AttributeError:
        return QtCore.Qt.ItemIsUserCheckable


def _checked_state() -> typing.Any:
    try:
        return QtCore.Qt.CheckState.Checked
    except AttributeError:
        return QtCore.Qt.Checked


def _unchecked_state() -> typing.Any:
    try:
        return QtCore.Qt.CheckState.Unchecked
    except AttributeError:
        return QtCore.Qt.Unchecked


def _partial_state() -> typing.Any:
    try:
        return QtCore.Qt.CheckState.PartiallyChecked
    except AttributeError:
        return QtCore.Qt.PartiallyChecked


def _custom_context_menu_policy() -> typing.Any:
    try:
        return QtCore.Qt.ContextMenuPolicy.CustomContextMenu
    except AttributeError:
        return QtCore.Qt.CustomContextMenu


def _scrollbar_as_needed() -> typing.Any:
    try:
        return QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded
    except AttributeError:
        return QtCore.Qt.ScrollBarAsNeeded


def _exec_menu(menu: typing.Any, position: typing.Any) -> typing.Any:
    execute = getattr(menu, "exec", None)
    if execute is None:
        execute = menu.exec_
    return execute(position)


def _check_state(name: str) -> typing.Any:
    if name == "checked":
        return _checked_state()
    if name == "partial":
        return _partial_state()
    return _unchecked_state()


def _display_status(value: str) -> str:
    return value.replace("_", " ").capitalize()


if QT_GRAPHICS_AVAILABLE:
    from d810.ui.workbench_structured_details import StructuredDetailsView

    class ConfigV2RuleCatalogWidget(QtWidgets.QWidget):
        """Filterable fixed tree of explicit rule family/subfamily metadata."""

        def __init__(
            self,
            *,
            on_query_changed: typing.Callable[[str], None],
            on_selection_changed: typing.Callable[[str, bool], None],
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._on_query_changed = on_query_changed
            self._on_selection_changed = on_selection_changed
            self._rendering = False
            self._catalog: ConfigV2RuleCatalogView | None = None
            self._by_target: dict[str, ConfigV2RuleView] = {}
            self._group_labels: dict[str, str] = {}

            self.query = QtWidgets.QLineEdit(self)
            self.query.setPlaceholderText(
                "Filter rules, families, verification, advisory, or experimental status..."
            )
            self.tree = QtWidgets.QTreeWidget(self)
            self.tree.setColumnCount(2)
            self.tree.setHeaderLabels(["Rule family", "Selection"])
            self.tree.setAlternatingRowColors(True)
            self.tree.setExpandsOnDoubleClick(True)
            self.tree.setContextMenuPolicy(_custom_context_menu_policy())
            self.tree.setVerticalScrollBarPolicy(_scrollbar_as_needed())
            try:
                self.tree.header().setStretchLastSection(False)
                self.tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
            except AttributeError:
                pass

            self.select_visible_button = QtWidgets.QPushButton("Select visible", self)
            self.clear_visible_button = QtWidgets.QPushButton("Clear visible", self)
            self.overflow_button = QtWidgets.QToolButton(self)
            configure_overflow_menu_button(self.overflow_button)
            self.overflow_button.setText("...")
            self.overflow_menu = QtWidgets.QMenu(self.overflow_button)
            self.overflow_menu.addAction("Select every rule", self._select_all)
            self.overflow_menu.addAction("Clear every rule", self._clear_all)
            self.overflow_button.setMenu(self.overflow_menu)
            try:
                self.overflow_button.setPopupMode(
                    QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup
                )
            except AttributeError:
                self.overflow_button.setPopupMode(QtWidgets.QToolButton.InstantPopup)

            self.details = StructuredDetailsView(self)
            self.details.setVerticalScrollBarPolicy(_scrollbar_as_needed())
            self.splitter = QtWidgets.QSplitter(self)
            try:
                self.splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                self.splitter.setOrientation(QtCore.Qt.Horizontal)
            left = QtWidgets.QWidget(self.splitter)
            left_layout = QtWidgets.QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.setSpacing(4)
            left_layout.addWidget(self.query)
            left_layout.addWidget(self.tree, stretch=1)
            controls = QtWidgets.QHBoxLayout()
            controls.addWidget(self.select_visible_button)
            controls.addWidget(self.clear_visible_button)
            controls.addStretch(1)
            controls.addWidget(self.overflow_button)
            left_layout.addLayout(controls)
            self.splitter.addWidget(left)
            self.splitter.addWidget(self.details)
            self.splitter.setChildrenCollapsible(False)
            self.splitter.setStretchFactor(0, 3)
            self.splitter.setStretchFactor(1, 2)

            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.splitter)

            self.query.textChanged.connect(self._query_changed)
            self.tree.itemChanged.connect(self._item_changed)
            self.tree.currentItemChanged.connect(self._current_item_changed)
            self.tree.customContextMenuRequested.connect(self._show_group_context_menu)
            self.select_visible_button.clicked.connect(self._select_visible)
            self.clear_visible_button.clicked.connect(self._clear_visible)
            self._render_empty()

        def set_catalog(self, catalog: ConfigV2RuleCatalogView | None) -> None:
            """Render a typed catalog without changing its selection."""
            self._catalog = catalog
            self._rendering = True
            try:
                self.tree.clear()
                self._by_target.clear()
                self._group_labels.clear()
                self.query.setText(catalog.query if catalog is not None else "")
                if catalog is None:
                    self._render_empty()
                    return
                for family in catalog.families:
                    family_item = self._item(
                        f"{family.label} ({family.selected_count}/{family.visible_count})",
                        family.target_id,
                        family.check_state,
                    )
                    self._group_labels[family.target_id] = family.label
                    self.tree.addTopLevelItem(family_item)
                    for subfamily in family.subfamilies:
                        subfamily_item = self._item(
                            f"{subfamily.label} ({subfamily.selected_count}/{subfamily.visible_count})",
                            subfamily.target_id,
                            subfamily.check_state,
                        )
                        self._group_labels[subfamily.target_id] = subfamily.label
                        family_item.addChild(subfamily_item)
                        for rule in subfamily.rules:
                            label = rule.label
                            if rule.experimental:
                                label += " [Experimental]"
                            elif rule.advisory != "none":
                                label += f" [{_display_status(rule.advisory)}]"
                            leaf = self._item(
                                label,
                                rule.rule_id,
                                "checked" if rule.selected else "unchecked",
                            )
                            subfamily_item.addChild(leaf)
                            self._by_target[rule.rule_id] = rule
                self.tree.expandAll()
                self._render_empty()
            finally:
                self._rendering = False

        def current_catalog(self) -> ConfigV2RuleCatalogView | None:
            return self._catalog

        def _item(
            self,
            label: str,
            target_id: str,
            check_state: str,
        ) -> typing.Any:
            item = QtWidgets.QTreeWidgetItem([label, _display_status(check_state)])
            item.setFlags(qt_flag_or(item.flags(), _checkable_flag()))
            item.setData(0, _user_role(), target_id)
            item.setCheckState(0, _check_state(check_state))
            return item

        def _query_changed(self, text: str) -> None:
            if not self._rendering:
                self._on_query_changed(str(text))

        def _item_changed(self, item: typing.Any, column: int) -> None:
            if self._rendering or column != 0:
                return
            target_id = item.data(0, _user_role())
            if isinstance(target_id, str):
                self._on_selection_changed(
                    target_id,
                    item.checkState(0) == _checked_state(),
                )

        def _current_item_changed(self, item: typing.Any, previous: typing.Any) -> None:
            del previous
            target_id = item.data(0, _user_role()) if item is not None else None
            rule = self._by_target.get(target_id)
            if rule is None:
                self._render_empty()
                return
            self.details.set_sections(self._details_for(rule))

        def _show_group_context_menu(self, position: typing.Any) -> None:
            item = self.tree.itemAt(position)
            if item is None:
                return
            target_id = item.data(0, _user_role())
            if not isinstance(target_id, str):
                return
            if not target_id.startswith(("family:", "subfamily:")):
                return
            group_label = self._group_labels.get(target_id)
            if group_label is None:
                return
            menu = QtWidgets.QMenu(self.tree)
            select_action = menu.addAction(f"Select all in {group_label}")
            clear_action = menu.addAction(f"Clear all in {group_label}")
            selected_action = _exec_menu(
                menu,
                self.tree.viewport().mapToGlobal(position),
            )
            if selected_action is select_action:
                self._on_selection_changed(target_id, True)
            elif selected_action is clear_action:
                self._on_selection_changed(target_id, False)

        def _details_for(
            self, rule: ConfigV2RuleView
        ) -> tuple[DetailSection, ...]:
            fields = [
                DetailField("Rule", f"{rule.label} ({rule.rule_id})"),
                DetailField("Description", rule.description),
                DetailField("Reference", rule.reference or "None"),
                DetailField("Maturities", ", ".join(rule.maturities)),
                DetailField(
                    "Verification",
                    f"{_display_status(rule.verification)}: {rule.verification_reason}",
                ),
            ]
            if rule.experimental:
                fields.append(
                    DetailField("Experimental", rule.experimental_reason)
                )
            if rule.advisory != "none":
                fields.append(
                    DetailField(
                        "Advisory",
                        f"{_display_status(rule.advisory)}: {rule.advisory_reason}",
                    )
                )
            if rule.cost != "unknown":
                fields.append(
                    DetailField(
                        "Cost",
                        f"{_display_status(rule.cost)}: {rule.cost_detail}",
                    )
                )
            return (DetailSection("rule", "Rule metadata", tuple(fields)),)

        def _render_empty(self) -> None:
            if self._catalog is None:
                message = "This pass has no individually selectable rules."
            elif not self._catalog.visible_rule_ids:
                message = "No rules match the current filter."
            else:
                message = "Select a rule to inspect its metadata and safety guidance."
            self.details.set_sections(
                (DetailSection("selection", "Rule metadata", (DetailField("Selection", message),)),)
            )

        def _emit_scope(self, target_id: str, selected: bool) -> None:
            if self._catalog is not None:
                self._on_selection_changed(target_id, selected)

        def _select_visible(self, checked: bool = False) -> None:
            del checked
            if self._catalog is not None:
                self._on_selection_changed("visible", True)

        def _clear_visible(self, checked: bool = False) -> None:
            del checked
            if self._catalog is not None:
                self._on_selection_changed("visible", False)

        def _select_all(self, checked: bool = False) -> None:
            del checked
            self._emit_scope("all", True)

        def _clear_all(self, checked: bool = False) -> None:
            del checked
            self._emit_scope("all", False)


else:

    class ConfigV2RuleCatalogWidget:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ConfigV2RuleCatalogWidget requires IDA Pro Qt")


__all__ = ["ConfigV2RuleCatalogWidget"]
