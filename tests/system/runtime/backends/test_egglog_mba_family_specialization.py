from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba import egglog_add_rule_compiler  # noqa: E402
from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    CERTIFICATE_WIDTHS,
    specialize,
)
from d810.hexrays.expr.p_ast import (  # noqa: E402
    AstBase,
    AstConstant,
    AstLeaf,
    AstNode,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.dsl import SymbolicExpressionProtocol  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)


_REGISTER_BY_NAME = {
    "x": 1,
    "y": 2,
    "z": 3,
    "x_0": 1,
    "x_1": 2,
    "x_2": 3,
}


@lru_cache(maxsize=1)
def _compiled_catalogue():
    return egglog_add_rule_compiler.compiled_rules_for_families(
        ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
    )


def _catalogue_rule(family: str, source_name: str):
    matches = [
        rule
        for rule in _compiled_catalogue()
        if rule.family == family
        if rule.source_name == source_name
    ]
    assert len(matches) == 1
    return matches[0]


def _leaf(name: str, register: int | None = None, size: int = 4) -> AstLeaf:
    leaf = AstLeaf(name)
    leaf.mop = MopSnapshot(
        t=ida_hexrays.mop_r,
        size=size,
        reg=register if register is not None else _REGISTER_BY_NAME[name],
    )
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


def _bnot_of(variable_name: str) -> AstNode:
    return _node(ida_hexrays.m_bnot, _leaf(variable_name))


def _candidate_from_pattern(
    expression: SymbolicExpressionProtocol,
    *,
    constant_bindings: Mapping[str, int] | None = None,
    ast_bindings: Mapping[str, AstBase] | None = None,
) -> AstBase:
    constant_bindings = constant_bindings or {}
    ast_bindings = ast_bindings or {}
    leaves: dict[str, AstLeaf] = {}

    def materialize(item: SymbolicExpressionProtocol) -> AstBase:
        if item.operation is None:
            assert item.name is not None
            if bool(getattr(item, "is_pattern_constant", False)):
                value = constant_bindings.get(item.name, item.value)
                assert value is not None, f"missing value for {item.name}"
                return _constant(value)
            bound = ast_bindings.get(item.name)
            if bound is not None:
                return bound.clone()
            leaf = leaves.setdefault(item.name, _leaf(item.name))
            return leaf.clone()

        assert item.left is not None
        opcode = {
            "add": ida_hexrays.m_add,
            "sub": ida_hexrays.m_sub,
            "mul": ida_hexrays.m_mul,
            "and": ida_hexrays.m_and,
            "or": ida_hexrays.m_or,
            "xor": ida_hexrays.m_xor,
            "neg": ida_hexrays.m_neg,
            "bnot": ida_hexrays.m_bnot,
        }[item.operation]
        return _node(
            opcode,
            materialize(item.left),
            materialize(item.right) if item.right is not None else None,
        )

    return materialize(expression)


def _node_count(ast: AstBase | None) -> int:
    if ast is None:
        return 0
    if ast.is_leaf():
        return 1
    return 1 + _node_count(ast.left) + _node_count(ast.right)


def _prove(
    family: str,
    source_name: str,
    *,
    constant_bindings: Mapping[str, int] | None = None,
    ast_bindings: Mapping[str, AstBase] | None = None,
    require_native_proof: bool = True,
):
    rule = _catalogue_rule(family, source_name)
    candidate = _candidate_from_pattern(
        rule.pattern,
        constant_bindings=constant_bindings,
        ast_bindings=ast_bindings,
    )
    assert isinstance(candidate, AstNode)

    specialization = specialize(rule, candidate, destination_size=4, rounds=3)

    assert specialization is not None
    assert specialization.family == family
    assert specialization.rule.proof_widths == CERTIFICATE_WIDTHS
    assert 32 in specialization.rule.proof_widths
    assert _node_count(specialization.replacement_ast) < _node_count(candidate)
    if require_native_proof:
        assert EgglogOptimizer._prove_ast_equivalence(
            candidate,
            specialization.replacement_ast,
            width=32,
        )
    return specialization


@pytest.mark.parametrize(
    ("family", "source_name"),
    [
        ("add", "Add_HackersDelightRule_2"),
        ("and", "And_HackersDelightRule_3"),
        ("bnot", "Bnot_HackersDelightRule_1"),
        ("mul", "Mul_FactorRule_2"),
        ("neg", "Neg_HackersDelightRule_1"),
        ("or", "Or_HackersDelightRule_2"),
        ("sub", "Sub_HackersDelightRule_1"),
        ("xor", "Xor_HackersDelightRule_1"),
    ],
)
def test_each_closed_family_executes_a_strict_exact_width_proven_rewrite(
    family,
    source_name,
):
    _prove(family, source_name)


@pytest.mark.parametrize(
    ("family", "source_name", "constant_bindings", "bnot_bindings"),
    [
        ("add", "Add_SpecialConstantRule_1", {"c_1": 5, "c_2": 5}, {}),
        (
            "add",
            "Add_SpecialConstantRule_2",
            {"c_1": 0x112, "c_2": 0x12},
            {},
        ),
        (
            "add",
            "Add_SpecialConstantRule_3",
            {"c_1": 0xFFFFFFFE, "c_2": 1},
            {},
        ),
        ("xor", "Xor_SpecialConstantRule_2", {"c_minus_2": -2}, {}),
        (
            "or",
            "Or_HackersDelightRule_1",
            {},
            {"bnot_x_1": "x_1"},
        ),
        (
            "xor",
            "Xor_FactorRule_1",
            {},
            {"bnot_x_0": "x_0", "bnot_x_1": "x_1"},
        ),
    ],
)
def test_every_compiled_guard_shape_executes_with_real_bindings(
    family,
    source_name,
    constant_bindings,
    bnot_bindings,
):
    specialization = _prove(
        family,
        source_name,
        constant_bindings=constant_bindings,
        ast_bindings={
            name: _bnot_of(operand) for name, operand in bnot_bindings.items()
        },
    )

    if source_name == "Add_SpecialConstantRule_3":
        assert specialization.replacement_ast.right.value == 0


@pytest.mark.parametrize(
    ("family", "source_name", "aliases", "bnot_bindings"),
    [
        ("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",), {}),
        ("add", "Add_OllvmRule_1", ("Add_OllvmRule_DynamicConst",), {}),
        ("xor", "Xor_HackersDelightRule_5", ("Xor_MbaRule_2",), {}),
        (
            "xor",
            "Xor_FactorRule_1",
            ("Xor_Rule_4",),
            {"bnot_x_0": "x_0", "bnot_x_1": "x_1"},
        ),
    ],
)
def test_every_duplicate_shape_executes_once_with_alias_provenance(
    family,
    source_name,
    aliases,
    bnot_bindings,
):
    specialization = _prove(
        family,
        source_name,
        ast_bindings={
            name: _bnot_of(operand) for name, operand in bnot_bindings.items()
        },
        require_native_proof=False,
    )

    assert specialization.source_names == (source_name, *aliases)


def test_unsupported_root_refuses_specialization_before_egglog_proof(monkeypatch):
    rule = _catalogue_rule("add", "Add_HackersDelightRule_2")
    unsupported = _node(
        ida_hexrays.m_udiv,
        _leaf("x_0"),
        _leaf("x_1"),
    )
    proof_attempts = []

    def record_proof_attempt(specialization):
        proof_attempts.append(specialization)
        return True

    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "_prove_specialization",
        record_proof_attempt,
    )

    assert specialize(rule, unsupported, destination_size=4) is None
    assert proof_attempts == []
