"""Round-trip identity tests for the ``RecoveredMachine`` adapter (P1, llr-5knz).

The load-bearing P1 invariant: ``from_state_dispatcher_map(m).to_state_dispatcher_map()``
is the identity on every field a consumer / the emit path reads, so offering the
contract as a parallel artifact loses nothing. Maps are built two ways: directly
(explicit field control) and via ``build_dispatch_map_any_kind`` on a real
switch-table ``FlowGraph`` (the end-to-end shape).
"""
from __future__ import annotations

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_recovery import build_dispatch_map_any_kind
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.recovered_machine import (
    RecoveredMachine,
    Soundness,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)


# --- FlowGraph builders (mirror tests/unit/recon/flow/test_dispatcher_resolver.py) ----


def _mop(
    *,
    kind: OperandKind = OperandKind.UNKNOWN,
    stkoff: int | None = None,
    value: int | None = None,
    stack_refs: tuple[int, ...] = (),
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = (),
) -> MopSnapshot:
    return MopSnapshot(
        kind=kind,
        stkoff=stkoff,
        value=value,
        stack_refs=stack_refs,
        switch_cases=switch_cases,
    )


def _insn(
    *,
    kind: InsnKind,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(opcode=1, ea=0, operands=(), l=left, r=right, kind=kind)


def _block(
    serial: int,
    *,
    preds=(),
    succs=(),
    tail: InsnSnapshot | None = None,
) -> BlockSnapshot:
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
    """A real SWITCH graph (mirrors test_dispatcher_resolver fixture)."""
    state_operand = _mop(kind=OperandKind.SUBINSN, stack_refs=(0x10,))
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(((0,), 4), ((1, 2), 5), ((), 3)),
    )
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    table_tail = _insn(kind=InsnKind.TABLE_JUMP, left=state_operand, right=switch_cases)
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


# --- Direct StateDispatcherMap builders --------------------------------------


def _equality_chain_map() -> StateDispatcherMap:
    rows = (
        StateDispatcherRow(
            state_const=0x01000010,
            target_block=7,
            dispatcher_block=2,
            compare_block=2,
            branch_kind="eq",
            source=RouterKind.CONDITION_CHAIN,
            confidence=2.0,
            row_kind="handler",
            payload={"note": "first"},
        ),
        StateDispatcherRow(
            state_const=0x01000020,
            target_block=9,
            dispatcher_block=3,
            compare_block=3,
            branch_kind="eq",
            source=RouterKind.CONDITION_CHAIN,
            row_kind="handler",
        ),
    )
    return StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
    )


def test_round_trip_identity_equality_chain():
    m = _equality_chain_map()
    assert RecoveredMachine.from_state_dispatcher_map(m).to_state_dispatcher_map() == m


def test_round_trip_identity_switch_table():
    m = build_dispatch_map_any_kind(_switch_flow_graph())
    assert m is not None
    assert m.source is RouterKind.SWITCH
    assert RecoveredMachine.from_state_dispatcher_map(m).to_state_dispatcher_map() == m


def test_round_trip_preserves_initial_state():
    base = _equality_chain_map()
    from dataclasses import replace

    m = replace(base, initial_state=0x1234)
    rm = RecoveredMachine.from_state_dispatcher_map(m)
    assert rm.initial_states == (0x1234,)
    back = rm.to_state_dispatcher_map()
    assert back.initial_state == 0x1234
    assert back == m


def test_round_trip_preserves_none_initial_state():
    m = _equality_chain_map()
    assert m.initial_state is None
    rm = RecoveredMachine.from_state_dispatcher_map(m)
    assert rm.initial_states == ()
    back = rm.to_state_dispatcher_map()
    assert back.initial_state is None


def test_default_target_and_row_kind_preserved():
    from dataclasses import replace

    m = replace(
        _equality_chain_map(),
        default_target_block=42,
        default_row_kind="default_handler",
    )
    back = RecoveredMachine.from_state_dispatcher_map(m).to_state_dispatcher_map()
    assert back.default_target_block == 42
    assert back.default_row_kind == "default_handler"
    assert back == m


def test_row_fields_byte_identical():
    m = _equality_chain_map()
    back = RecoveredMachine.from_state_dispatcher_map(m).to_state_dispatcher_map()
    assert len(back.rows) == len(m.rows)
    for original, restored in zip(m.rows, back.rows):
        assert restored.state_const == original.state_const
        assert restored.target_block == original.target_block
        assert restored.dispatcher_block == original.dispatcher_block
        assert restored.compare_block == original.compare_block
        assert restored.branch_kind == original.branch_kind
        assert restored.source is original.source
        assert restored.confidence == original.confidence
        assert restored.row_kind == original.row_kind
        assert restored.payload == original.payload


def test_soundness_default_is_pattern():
    m = _equality_chain_map()
    assert RecoveredMachine.from_state_dispatcher_map(m).soundness is Soundness.PATTERN
