"""Runtime coverage for deterministic instruction-rule scheduling."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.instructions import handler as instruction_handler
from d810.optimizers.microcode.instructions.peephole.fold_constant_subtree import (
    ConstantSubtreeFoldRule,
)
from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeOptimizer,
)


def test_instruction_optimizer_uses_first_registered_matching_rule(monkeypatch) -> None:
    """Hash-table layout must not change first-match callback scheduling."""
    optimizer = PeepholeOptimizer([ida_hexrays.MMAT_GLBOPT1], stats=None)
    calls: list[str] = []
    first_replacement = object()
    second_replacement = object()
    monkeypatch.setattr(FoldReadonlyDataRule, "__hash__", lambda _self: 7)
    monkeypatch.setattr(ConstantSubtreeFoldRule, "__hash__", lambda _self: 0)
    first = FoldReadonlyDataRule()
    second = ConstantSubtreeFoldRule()
    monkeypatch.setattr(
        first,
        "check_and_replace",
        lambda _blk, _ins: calls.append("readonly") or first_replacement,
    )
    monkeypatch.setattr(
        second,
        "check_and_replace",
        lambda _blk, _ins: calls.append("subtree") or second_replacement,
    )

    assert optimizer.add_rule(first)
    assert optimizer.add_rule(second)
    monkeypatch.setattr(instruction_handler, "format_minsn_t", lambda _ins: "probe")

    block = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1))
    replacement = optimizer.get_optimized_instruction(block, object())

    assert replacement is first_replacement
    assert calls == ["readonly"]


def test_instruction_rules_deduplicate_without_reordering(monkeypatch) -> None:
    optimizer = PeepholeOptimizer([ida_hexrays.MMAT_GLBOPT1], stats=None)
    monkeypatch.setattr(FoldReadonlyDataRule, "__hash__", lambda _self: 7)
    monkeypatch.setattr(ConstantSubtreeFoldRule, "__hash__", lambda _self: 0)
    first = FoldReadonlyDataRule()
    second = ConstantSubtreeFoldRule()

    assert optimizer.add_rule(first)
    assert optimizer.add_rule(second)
    assert optimizer.add_rule(first)
    assert tuple(type(rule).__name__ for rule in optimizer.rules) == (
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
    )
