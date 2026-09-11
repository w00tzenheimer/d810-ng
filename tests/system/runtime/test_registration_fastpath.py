"""Native runtime coverage for uncached legacy pattern lookup semantics."""

import ida_hexrays

from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternStorage,
    pattern_search_logger,
)


def _binary(opcode, left=None, right=None):
    return AstNode(
        opcode,
        left if left is not None else AstLeaf("left"),
        right if right is not None else AstLeaf("right"),
    )


def _constant(name, value):
    return AstConstant(name, expected_value=value, expected_size=4)


def _rules(storage, subject):
    return [entry.rule for entry in storage.get_matching_rule_pattern_info(subject)]


def test_lookup_does_not_render_subject_when_debug_logging_is_disabled(monkeypatch):
    storage = PatternStorage()
    subject = _binary(
        ida_hexrays.m_add,
        _constant("one", 1),
        _constant("two", 2),
    )
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add")

    monkeypatch.setattr(pattern_search_logger, "debug_on", False)

    def fail_if_rendered():
        raise AssertionError("matching must not call AstBase.get_pattern()")

    monkeypatch.setattr(subject, "get_pattern", fail_if_rendered)

    assert _rules(storage, subject) == ["add"]


def test_signature_generation_branch_preserves_literal_registration_order():
    storage = PatternStorage()
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add-first")
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add-second")
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_sub), "sub")
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_xor), "xor")

    subject = _binary(ida_hexrays.m_add, _constant("one", 1), _constant("two", 2))

    # One concrete root has two generated variants, fewer than the three
    # registered roots, so lookup takes the signature-generation branch.
    assert _rules(storage, subject) == ["add-first", "add-second"]


def test_linear_scan_branch_matches_constant_subjects_to_leaf_wildcards_in_order():
    storage = PatternStorage()
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "leaf-wildcard")
    storage.add_pattern_for_rule(
        _binary(ida_hexrays.m_add, _constant("left", 7), AstLeaf("right")),
        "constant-left",
    )

    subject = _binary(ida_hexrays.m_add, _constant("one", 1), _constant("two", 2))

    # Four generated depth-two variants are not fewer than the two stored
    # signatures, so lookup takes the linear compatibility-scan branch.
    assert _rules(storage, subject) == ["leaf-wildcard", "constant-left"]


def test_duplicate_registrations_remain_duplicate_candidate_occurrences():
    storage = PatternStorage()
    registered = _binary(ida_hexrays.m_add)
    storage.add_pattern_for_rule(registered, "duplicate")
    storage.add_pattern_for_rule(registered, "duplicate")

    assert _rules(storage, _binary(ida_hexrays.m_add)) == [
        "duplicate",
        "duplicate",
    ]


def test_registration_after_lookup_is_visible_on_the_next_lookup():
    storage = PatternStorage()
    subject = _binary(ida_hexrays.m_add)
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_sub), "sub")

    assert _rules(storage, subject) == []

    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add")

    assert _rules(storage, subject) == ["add"]


def test_mutating_a_supported_subject_opcode_changes_the_next_lookup():
    storage = PatternStorage()
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add")
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_sub), "sub")
    subject = _binary(ida_hexrays.m_add)

    assert _rules(storage, subject) == ["add"]

    subject.opcode = ida_hexrays.m_sub

    assert _rules(storage, subject) == ["sub"]


def test_mutating_a_returned_candidate_list_does_not_change_later_results():
    storage = PatternStorage()
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_add), "add")
    subject = _binary(ida_hexrays.m_add)

    first = storage.get_matching_rule_pattern_info(subject)
    first.clear()

    assert _rules(storage, subject) == ["add"]


def test_repeated_misses_return_independent_empty_lists():
    storage = PatternStorage()
    storage.add_pattern_for_rule(_binary(ida_hexrays.m_sub), "sub")
    subject = _binary(ida_hexrays.m_add)

    first = storage.get_matching_rule_pattern_info(subject)
    second = storage.get_matching_rule_pattern_info(subject)

    assert first == []
    assert second == []
    assert first is not second
