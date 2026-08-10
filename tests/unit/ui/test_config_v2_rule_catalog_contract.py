"""Source contracts for the fixed Qt config-v2 rule catalog."""

from __future__ import annotations

import ast
from pathlib import Path


RULE_CATALOG = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_rule_catalog.py"
)


def test_rule_catalog_uses_typed_grouping_and_operator_visible_metadata() -> None:
    source = RULE_CATALOG.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(RULE_CATALOG))
    classes = {
        item.name
        for item in ast.walk(tree)
        if isinstance(item, ast.ClassDef)
    }

    assert "ConfigV2RuleCatalogWidget" in classes
    assert "ConfigV2RuleCatalogView" in source
    assert "ConfigV2RuleView" in source
    assert "Select every rule" in source
    assert "Clear every rule" in source
    assert "Experimental" in source
    assert "Verification" in source
    assert "Cost" in source


def test_rule_catalog_routes_group_actions_and_keeps_both_panes_scrollable() -> None:
    source = RULE_CATALOG.read_text(encoding="utf-8")

    assert "customContextMenuRequested.connect(self._show_group_context_menu)" in source
    assert "item = self.tree.itemAt(position)" in source
    assert "target_id = item.data(0, _user_role())" in source
    assert 'target_id.startswith(("family:", "subfamily:"))' in source
    assert 'menu.addAction(f"Select all in {group_label}")' in source
    assert 'menu.addAction(f"Clear all in {group_label}")' in source
    assert "self._on_selection_changed(target_id, True)" in source
    assert "self._on_selection_changed(target_id, False)" in source
    assert 'self._on_selection_changed("visible", True)' in source
    assert 'self._on_selection_changed("visible", False)' in source
    assert "set_pass_options" not in source

    assert "left_layout.addWidget(self.tree, stretch=1)" in source
    assert "self.splitter.addWidget(left)" in source
    assert "self.splitter.addWidget(self.details)" in source
    assert "self.tree.setVerticalScrollBarPolicy(_scrollbar_as_needed())" in source
    assert "self.details.setVerticalScrollBarPolicy(_scrollbar_as_needed())" in source
    assert "self.splitter.setChildrenCollapsible(False)" in source
    assert "self.splitter.setStretchFactor(0, 3)" in source
    assert "self.splitter.setStretchFactor(1, 2)" in source
