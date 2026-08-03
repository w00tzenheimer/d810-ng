from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RULE_TREE = ROOT / "src" / "d810" / "ui" / "rule_tree.py"
FUNCTION_RULES = ROOT / "src" / "d810" / "ui" / "actions" / "function_rules.py"


def _source() -> str:
    return RULE_TREE.read_text(encoding="utf-8")


def test_rule_tree_declares_opt_in_context_intent_signal_and_constructor_flag() -> None:
    source = _source()
    tree = ast.parse(source, filename=str(RULE_TREE))

    assert "context_action_requested" in source
    assert "context_actions_enabled" in source
    assert "set_context_actions_enabled" in source
    assert "RuleTreeContextRequest" in source
    assert "context_action_for" in source
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setContextMenuPolicy"
        for node in ast.walk(tree)
    )


def test_rule_tree_contains_state_aware_context_labels() -> None:
    source = _source()

    assert "action.label" in source

    logic_source = (
        ROOT / "src" / "d810" / "ui" / "rule_tree_logic.py"
    ).read_text(encoding="utf-8")
    for label in ("Enable", "Disable", "Enable All", "Disable All"):
        assert f'"{label}"' in logic_source


def test_context_menu_keeps_legacy_select_all_path_for_non_opt_in_callers() -> None:
    source = _source()

    assert "Select All" in source
    assert "Deselect All" in source
    assert "if self._context_actions_enabled" in source
    assert "if self._read_only" in source


def test_function_rule_dialog_does_not_opt_into_global_context_intents() -> None:
    source = FUNCTION_RULES.read_text(encoding="utf-8")

    assert "context_actions_enabled=True" not in source
    assert "RuleTreeWidget(self)" in source
