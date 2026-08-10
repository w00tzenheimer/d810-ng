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
