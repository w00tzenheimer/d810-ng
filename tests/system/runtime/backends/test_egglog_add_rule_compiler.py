from __future__ import annotations

from types import SimpleNamespace

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba import egglog_add_rule_compiler  # noqa: E402
from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    compile_add_rule_catalogue,
    specialize,
)
from d810.backends.mba.egglog_saturation import EgglogExtractionReceipt  # noqa: E402
from d810.core.stats import OptimizationStatistics  # noqa: E402
from d810.hexrays.expr.ast import (  # noqa: E402
    AstConstant,
    AstLeaf,
    AstNode,
    AstProxy,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)
from d810.optimizers.microcode.instructions.peephole.handler import (  # noqa: E402
    PeepholeOptimizer,
)


def _catalogue_rule(name: str):
    receipt = compile_add_rule_catalogue().receipt_for(name)
    assert receipt.compiled_rule is not None
    return receipt.compiled_rule


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


def _prove(rule_name: str, candidate: AstNode):
    specialization = specialize(
        _catalogue_rule(rule_name), candidate, destination_size=4
    )
    assert specialization is not None
    return specialization


def test_specialization_api_does_not_expose_caller_owned_graph_registration():
    assert not hasattr(egglog_add_rule_compiler, "register_specialization")


def test_specializes_direct_add_rule_and_proves_the_egglog_equation():
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )

    specialization = _prove("Add_HackersDelightRule_2", candidate)

    assert specialization.replacement_ast.opcode == ida_hexrays.m_add
    assert specialization.source_names == (
        "Add_HackersDelightRule_2",
        "Add_OllvmRule_3",
    )


def test_live_handler_selects_certified_catalogue_rule_with_alias_provenance():
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate_ast = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )

    handler = EgglogOptimizer()
    specialization = handler._select_specialization(
        candidate_ast, destination_size=4
    )

    assert specialization is not None
    assert specialization.rule.source_name == "Add_HackersDelightRule_2"
    assert specialization.rule.aliases == ("Add_OllvmRule_3",)


def test_live_handler_selects_later_certified_specialization_with_lower_cost(
    monkeypatch,
):
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )
    earlier_rule = SimpleNamespace(proof_widths=(32,), source_name="Earlier")
    later_rule = SimpleNamespace(proof_widths=(32,), source_name="Later")
    earlier = SimpleNamespace(
        rule=earlier_rule,
        replacement_ast=_node(
            ida_hexrays.m_add,
            x.clone(),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )
    later = SimpleNamespace(
        rule=later_rule,
        replacement_ast=_node(ida_hexrays.m_add, x.clone(), y.clone()),
    )
    handler = EgglogOptimizer()
    handler._catalogue = SimpleNamespace(compiled_rules=(earlier_rule, later_rule))
    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.egraph.egglog_handler.specialize",
        lambda rule, _ast, **_kwargs: (
            earlier if rule is earlier_rule else later if rule is later_rule else None
        ),
    )
    monkeypatch.setattr(handler, "_prove_ast_equivalence", lambda *_args, **_kwargs: True)

    assert handler._select_specialization(candidate, destination_size=4) is later


def test_live_handler_breaks_equal_cost_selection_ties_by_catalogue_order(monkeypatch):
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )
    earlier_rule = SimpleNamespace(proof_widths=(32,), source_name="Earlier")
    later_rule = SimpleNamespace(proof_widths=(32,), source_name="Later")
    earlier = SimpleNamespace(
        rule=earlier_rule,
        replacement_ast=_node(ida_hexrays.m_add, x.clone(), y.clone()),
    )
    later = SimpleNamespace(
        rule=later_rule,
        replacement_ast=_node(ida_hexrays.m_add, y.clone(), x.clone()),
    )
    handler = EgglogOptimizer()
    handler._catalogue = SimpleNamespace(compiled_rules=(earlier_rule, later_rule))
    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.egraph.egglog_handler.specialize",
        lambda rule, _ast, **_kwargs: (
            earlier if rule is earlier_rule else later if rule is later_rule else None
        ),
    )
    monkeypatch.setattr(handler, "_prove_ast_equivalence", lambda *_args, **_kwargs: True)

    assert handler._select_specialization(candidate, destination_size=4) is earlier


def test_specializes_live_astproxy_without_changing_structural_semantics():
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )
    proxied = AstProxy(candidate)

    specialization = specialize(
        _catalogue_rule("Add_HackersDelightRule_2"),
        proxied,
        destination_size=4,
    )

    assert specialization is not None
    assert specialization.candidate_ast is candidate
    assert specialization.rule.source_name == "Add_HackersDelightRule_2"


def test_live_handler_threads_configured_rounds_into_specialization(monkeypatch):
    x, y = _leaf("x", 1), _leaf("y", 2)
    candidate_ast = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )
    observed_rounds = []
    real_specialize = egglog_add_rule_compiler.specialize

    def observe(rule, ast, *, destination_size, rounds):
        observed_rounds.append(rounds)
        return real_specialize(
            rule, ast, destination_size=destination_size, rounds=rounds
        )

    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.egraph.egglog_handler.specialize",
        observe,
    )
    handler = EgglogOptimizer()
    handler.configure({"rounds": 2})

    assert handler._select_specialization(candidate_ast, destination_size=4)
    assert observed_rounds
    assert set(observed_rounds) == {2}


def test_live_handler_rejects_disabling_mandatory_proof():
    handler = EgglogOptimizer()

    with pytest.raises(ValueError, match="mandatory"):
        handler.configure({"require_proof": False})


def test_central_statistics_records_and_serializes_egglog_provenance(monkeypatch):
    stats = OptimizationStatistics()
    optimizer = PeepholeOptimizer([ida_hexrays.MMAT_GLBOPT2], stats)
    handler = EgglogOptimizer()
    handler.last_rule_provenance = (
        "Add_HackersDelightRule_2",
        "Add_OllvmRule_3",
    )
    handler.last_extraction_receipt = EgglogExtractionReceipt(
        selected_family="add",
        selected_source="Add_HackersDelightRule_2",
        selected_aliases=("Add_OllvmRule_3",),
    )
    class _Instruction:
        opcode = ida_hexrays.m_add
        ea = 0x401000

        @staticmethod
        def _print():
            return "fake instruction"

    monkeypatch.setattr(
        handler, "check_and_replace", lambda _blk, _ins: _Instruction()
    )
    optimizer.add_rule(handler)

    class _Mba:
        maturity = ida_hexrays.MMAT_GLBOPT2

    class _Block:
        mba = _Mba()

    replacement = optimizer.get_optimized_instruction(_Block(), _Instruction())
    assert replacement is not None
    optimizer.record_mutation_accepted()
    execution = stats.get_rule_execution("EgglogOptimizer")

    assert execution is not None
    assert execution.metadata["source_names"] == (
        "Add_HackersDelightRule_2",
        "Add_OllvmRule_3",
    )
    assert execution.metadata["source_name"] == "Add_HackersDelightRule_2"
    assert execution.metadata["aliases"] == ("Add_OllvmRule_3",)
    serialized = stats.to_dict()["rule_executions"]["egglogoptimizer"]
    assert serialized["metadata"]["source_names"] == (
        "Add_HackersDelightRule_2",
        "Add_OllvmRule_3",
    )


def test_rejects_guarded_rule_when_constant_constraint_is_false():
    x = _leaf("x", 1)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, _constant(5)),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), _constant(6)),
        ),
    )

    assert (
        specialize(
            _catalogue_rule("Add_SpecialConstantRule_1"),
            candidate,
            destination_size=4,
        )
        is None
    )


def test_rejects_concrete_constant_with_missing_literal_payload():
    x, y = _leaf("x", 1), _leaf("y", 2)
    missing = AstConstant("missing", expected_value=None, expected_size=4)
    missing.dest_size = 4
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y),
        _node(
            ida_hexrays.m_mul,
            missing,
            _node(ida_hexrays.m_and, x.clone(), y.clone()),
        ),
    )

    assert (
        specialize(
            _catalogue_rule("Add_HackersDelightRule_2"),
            candidate,
            destination_size=4,
        )
        is None
    )


@pytest.mark.parametrize("payload", [None, "not-an-integer"])
def test_rejects_malformed_constant_bound_as_repeated_ordinary_variable(payload):
    malformed = AstConstant("malformed", expected_value=payload, expected_size=4)
    malformed.dest_size = 4
    y = _leaf("y", 2)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, malformed, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, malformed.clone(), y.clone()),
        ),
    )

    assert (
        specialize(
            _catalogue_rule("Add_HackersDelightRule_2"),
            candidate,
            destination_size=4,
        )
        is None
    )


def test_specializes_equal_and_masked_constant_guards():
    x = _leaf("x", 1)
    equal_candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, _constant(5)),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), _constant(5)),
        ),
    )
    masked_candidate = _node(
        ida_hexrays.m_add,
        _node(
            ida_hexrays.m_xor,
            _node(ida_hexrays.m_and, x.clone(), _constant(0xFF)),
            _constant(0x112),
        ),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_and, x.clone(), _constant(0x12)),
        ),
    )

    assert _prove("Add_SpecialConstantRule_1", equal_candidate)
    assert _prove("Add_SpecialConstantRule_2", masked_candidate)


def test_specializes_complement_guard_and_materializes_derived_constant():
    x = _leaf("x", 1)
    candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, _constant(0xFFFFFFFE)),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_or, x.clone(), _constant(1)),
        ),
    )

    specialization = _prove("Add_SpecialConstantRule_3", candidate)

    assert specialization.replacement_ast.right.value == 0


@pytest.mark.parametrize("rule_name", ["Add_OllvmRule_2", "Add_OllvmRule_4"])
def test_specializes_wrapped_negative_two_guard(rule_name: str):
    x, y = _leaf("x", 1), _leaf("y", 2)
    bitwise = ida_hexrays.m_or if rule_name.endswith("2") else ida_hexrays.m_and
    candidate = _node(
        ida_hexrays.m_sub,
        _node(
            ida_hexrays.m_bnot if rule_name.endswith("2") else ida_hexrays.m_xor,
            _node(ida_hexrays.m_xor, x, y) if rule_name.endswith("2") else x,
            None if rule_name.endswith("2") else y,
        ),
        _node(
            ida_hexrays.m_mul,
            _constant(-2),
            _node(bitwise, x.clone(), y.clone()),
        ),
    )

    assert _prove(rule_name, candidate)


def test_specializes_both_negated_variable_guards():
    x, y = _leaf("x", 1), _leaf("y", 2)
    not_y = _node(ida_hexrays.m_bnot, y.clone())
    rule_1 = _node(
        ida_hexrays.m_sub,
        _node(ida_hexrays.m_sub, x, y),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(ida_hexrays.m_or, x.clone(), not_y),
        ),
    )
    not_x = _node(ida_hexrays.m_bnot, x.clone())
    rule_2 = _node(
        ida_hexrays.m_sub,
        _node(ida_hexrays.m_sub, x.clone(), y.clone()),
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(
                ida_hexrays.m_bnot,
                _node(ida_hexrays.m_and, not_x, y.clone()),
            ),
        ),
    )

    assert _prove("AddXor_Rule_1", rule_1)
    assert _prove("AddXor_Rule_2", rule_2)


@pytest.mark.parametrize("destination_size", [0, 3, 16])
def test_rejects_invalid_destination_sizes(destination_size: int):
    candidate = _node(ida_hexrays.m_add, _leaf("x", 1), _leaf("y", 2))
    assert (
        specialize(
            _catalogue_rule("Add_HackersDelightRule_3"),
            candidate,
            destination_size=destination_size,
        )
        is None
    )


def test_rejects_casts_mixed_widths_and_unsupported_nodes():
    rule = _catalogue_rule("Add_HackersDelightRule_3")
    x, y = _leaf("x", 1), _leaf("y", 2)
    cast = _node(ida_hexrays.m_xdu, x)
    cast_candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_or, cast, y),
        _node(ida_hexrays.m_and, cast.clone(), y.clone()),
    )
    mixed_candidate = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_or, x, _leaf("wide", 3, size=8)),
        _node(ida_hexrays.m_and, x.clone(), _leaf("wide", 3, size=8)),
    )
    unsupported = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_udiv, x.clone(), y.clone()),
        _node(ida_hexrays.m_and, x.clone(), y.clone()),
    )

    assert specialize(rule, cast_candidate, destination_size=4) is None
    assert specialize(rule, mixed_candidate, destination_size=4) is None
    assert specialize(rule, unsupported, destination_size=4) is None
