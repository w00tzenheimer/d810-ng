from __future__ import annotations

from types import SimpleNamespace

from d810.core.persistence import FunctionRuleConfig
from d810.ui.actions.function_rules import (
    _build_override_sets,
    _collect_available_rules,
    _format_tags_csv,
    _parse_tags_csv,
    _resolve_initial_enabled_rule_names,
)


class _Rule:
    def __init__(self, name: str):
        self.name = name


def test_collect_available_rules_prefers_current_and_dedups():
    state = SimpleNamespace(
        current_ins_rules=[_Rule("A"), _Rule("B")],
        current_blk_rules=[_Rule("B"), _Rule("C")],
        known_ins_rules=[_Rule("X")],
        known_blk_rules=[_Rule("Y")],
    )

    collected = _collect_available_rules(state)
    assert [rule.name for rule in collected] == ["A", "B", "C"]


def test_collect_available_rules_falls_back_to_known():
    state = SimpleNamespace(
        current_ins_rules=[],
        current_blk_rules=[],
        known_ins_rules=[_Rule("I1")],
        known_blk_rules=[_Rule("F1")],
    )
    collected = _collect_available_rules(state)
    assert [rule.name for rule in collected] == ["I1", "F1"]


def test_resolve_initial_enabled_rule_names_without_override():
    all_names = {"A", "B", "C"}
    assert _resolve_initial_enabled_rule_names(all_names, None) == all_names


def test_resolve_initial_enabled_rule_names_with_whitelist_override():
    all_names = {"A", "B", "C"}
    override = FunctionRuleConfig(
        function_addr=0x401000,
        enabled_rules={"A", "C"},
        disabled_rules={"C"},
        notes="test",
    )
    assert _resolve_initial_enabled_rule_names(all_names, override) == {"A"}


def test_build_override_sets_all_enabled_is_no_override():
    enabled, disabled = _build_override_sets({"A", "B"}, {"A", "B"})
    assert enabled == set()
    assert disabled == set()


def test_build_override_sets_prefers_smaller_representation():
    # Small disable set -> blacklist representation
    enabled, disabled = _build_override_sets({"A", "B", "C"}, {"A", "B"})
    assert enabled == set()
    assert disabled == {"C"}

    # Small enable set -> whitelist representation
    enabled, disabled = _build_override_sets({"A", "B", "C"}, {"A"})
    assert enabled == {"A"}
    assert disabled == set()


def test_parse_tags_csv_and_format_roundtrip():
    parsed = _parse_tags_csv(" flattened,opaque_pred,, dispatcher ")
    assert parsed == {"flattened", "opaque_pred", "dispatcher"}
    assert _format_tags_csv(parsed) == "dispatcher, flattened, opaque_pred"
