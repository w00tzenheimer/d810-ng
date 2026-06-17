"""Engine registry tests (P1, llr-5knz).

Covers the selection seam: ``default_engines`` is StaticShape-only;
``recover_machine_via_engines`` ranks by ``(soundness_rank, confidence)`` and is a
no-op single-result pass in P1; registration is idempotent-by-name and isolatable.
"""
from __future__ import annotations

import pytest

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_recovery import (
    clear_extra_dispatcher_resolvers,
)
from d810.analyses.control_flow.engine_registry import (
    SOUNDNESS_RANK,
    clear_extra_engines,
    default_engines,
    extra_engines,
    recover_machine_via_engines,
    register_extra_engine,
)
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.control_flow.static_shape_engine import StaticShapeEngine
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)


def _mop(**kw) -> MopSnapshot:
    return MopSnapshot(**kw)


def _block(serial, *, preds=(), succs=(), tail=None) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0,
        insn_snapshots=() if tail is None else (tail,),
    )


def _switch_flow_graph() -> FlowGraph:
    state_operand = _mop(kind=OperandKind.SUBINSN, stack_refs=(0x10,))
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(((0,), 4), ((1, 2), 5), ((), 3)),
    )
    guard_tail = InsnSnapshot(
        opcode=1,
        ea=0,
        operands=(),
        l=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        r=_mop(kind=OperandKind.NUMBER, value=0xFF),
        kind=InsnKind.COND_JUMP,
    )
    table_tail = InsnSnapshot(
        opcode=1, ea=0, operands=(), l=state_operand, r=switch_cases,
        kind=InsnKind.TABLE_JUMP,
    )
    return FlowGraph(
        blocks={
            0: _block(0, succs=(2,)),
            2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
            3: _block(3, preds=(2, 6), succs=(4, 5), tail=table_tail),
            4: _block(4),
            5: _block(5),
            6: _block(6, succs=(3,)),
            9: _block(9),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


class _FakeEngine:
    """Protocol-shaped fake engine that always returns a fixed machine."""

    def __init__(self, name: str, *, soundness: Soundness, confidence: float) -> None:
        self.name = name
        self._soundness = soundness
        self._confidence = confidence

    def recover(self, graph, anchors=None, caps=None) -> RecoveredMachine:
        return RecoveredMachine(
            rows=(MachineRow(state_const=1, target_block=2, dispatcher_block=0),),
            source=RouterKind.UNKNOWN,
            soundness=self._soundness,
            confidence=self._confidence,
            provenance=(self.name,),
        )


class _NoneEngine:
    def __init__(self, name: str) -> None:
        self.name = name

    def recover(self, graph, anchors=None, caps=None):
        return None


@pytest.fixture(autouse=True)
def _isolate_registries():
    clear_extra_engines()
    clear_extra_dispatcher_resolvers()
    yield
    clear_extra_engines()
    clear_extra_dispatcher_resolvers()


def test_default_engines_is_static_shape_only():
    assert default_engines() == (StaticShapeEngine(),)


def test_recover_via_engines_matches_single_engine():
    g = _switch_flow_graph()
    via = recover_machine_via_engines(g, default_engines())
    direct = StaticShapeEngine().recover(g)
    assert via == direct


def test_register_extra_engine_idempotent_by_name():
    register_extra_engine(_FakeEngine("dup", soundness=Soundness.PATTERN, confidence=1.0))
    register_extra_engine(_FakeEngine("dup", soundness=Soundness.PATTERN, confidence=9.0))
    assert len(extra_engines()) == 1


def test_clear_extra_engines():
    register_extra_engine(_FakeEngine("x", soundness=Soundness.PATTERN, confidence=1.0))
    assert len(extra_engines()) == 1
    clear_extra_engines()
    assert extra_engines() == ()


def test_ranking_prefers_higher_soundness():
    g = _switch_flow_graph()
    pattern = _FakeEngine("pat", soundness=Soundness.PATTERN, confidence=1.0)
    exact = _FakeEngine("exa", soundness=Soundness.EXACT_BOUNDED, confidence=1.0)
    winner = recover_machine_via_engines(g, (pattern, exact))
    assert winner is not None
    assert winner.soundness is Soundness.EXACT_BOUNDED
    assert SOUNDNESS_RANK[Soundness.EXACT_BOUNDED] > SOUNDNESS_RANK[Soundness.PATTERN]


def test_ranking_breaks_ties_by_confidence():
    g = _switch_flow_graph()
    low = _FakeEngine("low", soundness=Soundness.PATTERN, confidence=1.0)
    high = _FakeEngine("high", soundness=Soundness.PATTERN, confidence=5.0)
    winner = recover_machine_via_engines(g, (low, high))
    assert winner is not None
    assert winner.confidence == 5.0


def test_returns_none_when_no_engine_recovers():
    g = _switch_flow_graph()
    winner = recover_machine_via_engines(g, (_NoneEngine("a"), _NoneEngine("b")))
    assert winner is None


def test_none_graph_returns_none():
    assert recover_machine_via_engines(None, default_engines()) is None


def test_recover_via_engines_passes_anchors():
    g = _switch_flow_graph()
    anchors = DispatcherAnchors(dispatcher_entry_block=3, state_var_stkoff=0x10)
    # StaticShape ignores anchors; this asserts the call signature accepts them.
    via = recover_machine_via_engines(g, default_engines(), anchors=anchors)
    assert via == StaticShapeEngine().recover(g)
