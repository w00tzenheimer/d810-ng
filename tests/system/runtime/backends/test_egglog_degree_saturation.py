from __future__ import annotations

from functools import lru_cache

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    CERTIFICATE_WIDTHS,
    compiled_rules_for_families,
)
from d810.backends.mba.egglog_saturation import (  # noqa: E402
    EgglogExtractionBudget,
    ExtractionSkipReason,
    extract_bounded_candidate,
)
from d810.hexrays.expr.p_ast import AstConstant, AstLeaf, AstNode  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)


@lru_cache(maxsize=1)
def _rules():
    return compiled_rules_for_families(
        ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
    )


def _rule(family: str, source_name: str):
    matches = tuple(
        rule
        for rule in _rules()
        if rule.family == family and rule.source_name == source_name
    )
    assert len(matches) == 1
    return matches[0]


def _leaf(name: str, register: int, size: int = 4) -> AstLeaf:
    leaf = AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4) -> AstConstant:
    wrapped = value & ((1 << (size * 8)) - 1)
    constant = AstConstant(str(value), wrapped, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=wrapped)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4) -> AstNode:
    node = AstNode(opcode, left, right)
    node.dest_size = size
    return node


def _direct_add_candidate(size: int = 4) -> AstNode:
    x, y = _leaf("x", 1, size), _leaf("y", 2, size)
    return _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y, size=size),
        _node(
            ida_hexrays.m_mul,
            _constant(2, size),
            _node(ida_hexrays.m_and, x.clone(), y.clone(), size=size),
            size=size,
        ),
        size=size,
    )


def _degree_two_candidate(size: int = 4) -> AstNode:
    # BnotXor_FactorRule_1 keeps cost equal at degree 1:
    #   (~x) ^ (~y) -> ~((~x) ^ y)
    # Bnot_FactorRule_5 then strictly reduces at degree 2:
    #   ~((~x) ^ y) -> x ^ y
    return _node(
        ida_hexrays.m_xor,
        _node(ida_hexrays.m_bnot, _leaf("x", 1, size), size=size),
        _node(ida_hexrays.m_bnot, _leaf("y", 2, size), size=size),
        size=size,
    )


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_one_catalogue_rewrite_extracts_at_degree_one_and_proves_all_widths(size):
    candidate = _direct_add_candidate(size)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        candidate,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        size,
    )

    assert rule.proof_widths == CERTIFICATE_WIDTHS
    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.skip_reason is None
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_2",
        ("Add_OllvmRule_3",),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        result.replacement_ast,
        width=size * 8,
    )


def test_composed_catalogue_rewrite_needs_degree_two():
    candidate = _degree_two_candidate()
    rules = (
        _rule("bnot", "BnotXor_FactorRule_1"),
        _rule("bnot", "Bnot_FactorRule_5"),
    )
    common = dict(
        saturation_rounds=2,
        time_budget_ms=1000,
        max_eclasses=256,
        max_enodes=512,
    )

    degree_one = extract_bounded_candidate(
        candidate,
        rules,
        EgglogExtractionBudget(max_degree=1, **common),
        4,
    )
    degree_two = extract_bounded_candidate(
        candidate,
        rules,
        EgglogExtractionBudget(max_degree=2, **common),
        4,
    )

    assert degree_one.replacement_ast is None
    assert (
        degree_one.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )
    assert degree_two.replacement_ast is not None
    assert degree_two.receipt.degree == 2
    assert degree_two.selected_provenance == (
        "bnot",
        "Bnot_FactorRule_5",
        (),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        degree_two.replacement_ast,
        width=32,
    )


def test_rule_firing_cap_returns_receipt_not_exception():
    result = extract_bounded_candidate(
        _degree_two_candidate(),
        (
            _rule("bnot", "BnotXor_FactorRule_1"),
            _rule("bnot", "Bnot_FactorRule_5"),
        ),
        EgglogExtractionBudget(
            max_degree=2,
            saturation_rounds=2,
            max_rule_firings=1,
            max_eclasses=256,
            max_enodes=512,
            time_budget_ms=1000,
        ),
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.rule_firings > 1
    assert result.receipt.skip_reason is ExtractionSkipReason.RULE_FIRING_BUDGET


def test_ac_operand_order_uses_no_variant_catalogue_rewrite():
    direct = _direct_add_candidate()
    swapped = _node(ida_hexrays.m_add, direct.right, direct.left)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        swapped,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.rule_firings == 1
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_2",
        ("Add_OllvmRule_3",),
    )


def test_ac_reassociation_uses_no_associativity_rewrite():
    x, y, z = _leaf("x", 1), _leaf("y", 2), _leaf("z", 3)
    candidate = _node(
        ida_hexrays.m_sub,
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(
                ida_hexrays.m_or,
                z,
                _node(ida_hexrays.m_or, y, x),
            ),
        ),
        _node(
            ida_hexrays.m_xor,
            x.clone(),
            _node(ida_hexrays.m_or, z.clone(), y.clone()),
        ),
    )
    rule = _rule("add", "Add_HackersDelightRule_5")

    result = extract_bounded_candidate(
        candidate,
        (rule,),
        EgglogExtractionBudget(max_leaves=3, time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.rule_firings == 1
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_5",
        (),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        result.replacement_ast,
        width=32,
    )


def test_grounded_constant_guard_fires_only_when_constraint_holds():
    rule = _rule("add", "Add_SpecialConstantRule_1")

    def candidate(second_constant: int) -> AstNode:
        x = _leaf("x", 1)
        return _node(
            ida_hexrays.m_add,
            _node(ida_hexrays.m_xor, x, _constant(5)),
            _node(
                ida_hexrays.m_mul,
                _constant(2),
                _node(
                    ida_hexrays.m_and,
                    x.clone(),
                    _constant(second_constant),
                ),
            ),
        )

    valid_candidate = candidate(5)
    valid = extract_bounded_candidate(
        valid_candidate,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )
    invalid = extract_bounded_candidate(
        candidate(6),
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert valid.replacement_ast is not None
    assert valid.receipt.rule_firings == 1
    assert valid.selected_provenance == (
        "add",
        "Add_SpecialConstantRule_1",
        (),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        valid_candidate,
        valid.replacement_ast,
        width=32,
    )
    assert invalid.replacement_ast is None
    assert invalid.receipt.rule_firings == 0
    assert (
        invalid.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )


@pytest.mark.parametrize(
    ("budget", "reason"),
    [
        (EgglogExtractionBudget(max_operator_nodes=1), ExtractionSkipReason.CANDIDATE_BUDGET),
        (
            EgglogExtractionBudget(max_eclasses=1, time_budget_ms=1000),
            ExtractionSkipReason.ECLASS_BUDGET,
        ),
        (
            EgglogExtractionBudget(max_enodes=1, time_budget_ms=1000),
            ExtractionSkipReason.ENODE_BUDGET,
        ),
    ],
)
def test_resource_caps_abort_without_materializing_a_mop(monkeypatch, budget, reason):
    create_mop_calls = []
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda self, ea: create_mop_calls.append((self, ea)),
    )

    result = extract_bounded_candidate(
        _direct_add_candidate(),
        (_rule("add", "Add_HackersDelightRule_2"),),
        budget,
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.skip_reason is reason
    assert create_mop_calls == []


def test_one_schedule_round_cannot_authorize_a_degree_two_chain():
    result = extract_bounded_candidate(
        _degree_two_candidate(),
        (
            _rule("bnot", "BnotXor_FactorRule_1"),
            _rule("bnot", "Bnot_FactorRule_5"),
        ),
        EgglogExtractionBudget(
            max_degree=2,
            saturation_rounds=1,
            max_eclasses=256,
            max_enodes=512,
            time_budget_ms=1000,
        ),
        4,
    )

    assert result.replacement_ast is None
    assert (
        result.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )
