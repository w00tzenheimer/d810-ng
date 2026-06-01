"""Portable tests for semantic return lowering (no IDA)."""
from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.graph_modification import DirectTerminalLoweringKind
from d810.transforms.semantic_return_lowering import (
    TerminalReturnIntent,
    plan_semantic_returns,
)


def _edge(kind_name: str, serial: int, arm=None):
    return SimpleNamespace(
        kind=SimpleNamespace(name=kind_name),
        source_anchor=SimpleNamespace(block_serial=serial, branch_arm=arm),
    )


def _dag(*edges):
    return SimpleNamespace(edges=list(edges))


def _reg_intent(edge):
    anchor = edge.source_anchor
    return TerminalReturnIntent(
        anchor_serial=int(anchor.block_serial),
        branch_arm=anchor.branch_arm,
        kind=DirectTerminalLoweringKind.RETURN_FROM_REG,
        source_mreg=8,
    )


def test_one_intent_per_return_edge_ignores_others():
    dag = _dag(
        _edge("CONDITIONAL_RETURN", 10, 1),
        _edge("TRANSITION", 20),
        _edge("CONDITIONAL_TRANSITION", 25, 0),
        _edge("CONDITIONAL_RETURN", 30, 0),
    )
    out = plan_semantic_returns(dag, resolve_carrier=_reg_intent)
    assert len(out) == 2
    assert {i.anchor_serial for i in out} == {10, 30}
    assert all(i.kind is DirectTerminalLoweringKind.RETURN_FROM_REG for i in out)


def test_unresolved_carrier_is_skipped():
    dag = _dag(_edge("CONDITIONAL_RETURN", 10, 1))
    assert plan_semantic_returns(dag, resolve_carrier=lambda e: None) == ()


def test_dedup_by_anchor_and_arm():
    dag = _dag(_edge("CONDITIONAL_RETURN", 10, 1), _edge("CONDITIONAL_RETURN", 10, 1))

    def resolve(edge):
        return TerminalReturnIntent(
            anchor_serial=10,
            branch_arm=1,
            kind=DirectTerminalLoweringKind.RETURN_CONST,
            const_value=0x41FB8FBB,
        )

    out = plan_semantic_returns(dag, resolve_carrier=resolve)
    assert len(out) == 1
    assert out[0].const_value == 0x41FB8FBB


def test_anchor_without_serial_skipped():
    bad = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_RETURN"),
        source_anchor=SimpleNamespace(block_serial=None, branch_arm=None),
    )
    out = plan_semantic_returns(_dag(bad), resolve_carrier=_reg_intent)
    assert out == ()
