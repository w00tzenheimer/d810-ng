"""Diagnostic performance receipt for the certified Egglog MBA path."""

from __future__ import annotations

import json
import time

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba import egglog_add_rule_compiler  # noqa: E402
from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    compile_mba_rule_catalogue,
)
from d810.hexrays.expr.p_ast import AstBase, AstLeaf, AstNode  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.dsl import SymbolicExpressionProtocol  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)


_CLOSED_FAMILIES = ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
_REGISTER_BY_NAME = {"x_0": 1, "x_1": 2}
_OPCODE_BY_OPERATION = {
    "add": ida_hexrays.m_add,
    "and": ida_hexrays.m_and,
    "bnot": ida_hexrays.m_bnot,
    "mul": ida_hexrays.m_mul,
    "neg": ida_hexrays.m_neg,
    "or": ida_hexrays.m_or,
    "sub": ida_hexrays.m_sub,
    "xor": ida_hexrays.m_xor,
}


def _candidate_from_pattern(expression: SymbolicExpressionProtocol) -> AstBase:
    leaves: dict[str, AstLeaf] = {}

    def materialize(item: SymbolicExpressionProtocol) -> AstBase:
        if item.operation is None:
            assert item.name is not None
            leaf = leaves.get(item.name)
            if leaf is None:
                leaf = AstLeaf(item.name)
                leaf.mop = MopSnapshot(
                    t=ida_hexrays.mop_r,
                    size=4,
                    reg=_REGISTER_BY_NAME[item.name],
                )
                leaf.dest_size = 4
                leaves[item.name] = leaf
            return leaf.clone()

        assert item.left is not None
        node = AstNode(
            _OPCODE_BY_OPERATION[item.operation],
            materialize(item.left),
            materialize(item.right) if item.right is not None else None,
        )
        node.dest_size = 4
        return node

    return materialize(expression)


@pytest.mark.profile
def test_cold_catalogue_and_selected_root_work_have_separate_receipts(
    monkeypatch,
):
    cold_started = time.perf_counter()
    catalogue = compile_mba_rule_catalogue()
    cold_seconds = time.perf_counter() - cold_started

    selected_rules = tuple(
        rule for rule in catalogue.compiled_rules if rule.family in _CLOSED_FAMILIES
    )

    class _SelectedCatalogue:
        compiled_rules = selected_rules

    handler = EgglogOptimizer()
    handler.families = _CLOSED_FAMILIES
    handler._catalogue = _SelectedCatalogue()
    target = next(
        rule
        for rule in selected_rules
        if rule.family == "xor" and rule.source_name == "Xor_FactorRule_3"
    )
    candidate = _candidate_from_pattern(target.pattern)
    assert isinstance(candidate, AstNode)
    root_bucket = handler._rules_by_root_opcode[candidate.opcode]

    specialization_attempts = []
    real_specialize = egglog_add_rule_compiler.specialize

    def observe(rule, ast, *, destination_size, rounds):
        specialization_attempts.append(rule)
        return real_specialize(
            rule,
            ast,
            destination_size=destination_size,
            rounds=rounds,
        )

    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.egraph.egglog_handler.specialize",
        observe,
    )
    bucket_started = time.perf_counter()
    specialization = handler._select_specialization(candidate, destination_size=4)
    bucket_seconds = time.perf_counter() - bucket_started

    receipt = {
        "cold_catalogue_seconds": cold_seconds,
        "compiled_rule_count": len(selected_rules),
        "selected_root": "xor",
        "selected_root_bucket_candidates": len(root_bucket),
        "specialization_attempts": len(specialization_attempts),
        "selected_bucket_seconds": bucket_seconds,
        "native_fixture_runtime": "measured by the focused Docker e2e receipt",
    }
    print("\nEGGLOG_MBA_PERFORMANCE_RECEIPT=" + json.dumps(receipt, sort_keys=True))

    assert len(catalogue.receipts) == 188
    assert len(selected_rules) == 108
    assert len(root_bucket) == 14
    assert tuple(specialization_attempts) == root_bucket
    assert all(rule.pattern.operation == "xor" for rule in specialization_attempts)
    assert specialization is not None
