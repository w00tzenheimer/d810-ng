"""Tests for in-memory state-dispatcher transition resolution."""
from __future__ import annotations

import pytest

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.semantic_transition import (
    StateTransitionFact,
    StateWriteAnchor,
    facts_from_validated_view,
    resolve_state_transitions_with_dispatcher_map,
)
from d810.analyses.value_flow.model import FactObservation, ValidatedFactView
from d810.analyses.value_flow.state_write import (
    MicrocodeEvalSeams,
    forward_eval_insn as _portable_forward_eval_insn,
)
from d810.capabilities.providers import (
    BstWalkerProvider,
    register_bst_walkers,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)


def _dispatch_map() -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=7,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=RouterKind.SWITCH,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_self_loop",
                source=RouterKind.SWITCH,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=RouterKind.SWITCH,
    )


def test_resolves_exact_state_and_next_state_write() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=100",
                source_block_serial=100,
                source_state_const=0x10,
                source_state_const_hex="0x00000010",
                state_var_stkoff=0x3C,
            ),
        ),
        dispatch_map=_dispatch_map(),
        state_write_anchors=(
            StateWriteAnchor(
                block_serial=7,
                state_const=0x55,
                state_var_stkoff=0x3C,
            ),
        ),
    )

    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial == 7
    assert resolutions[0].resolved_next_state_const_u64 == 0x55
    assert resolutions[0].resolved_next_state_const_hex == "0x0000000000000055"
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_reports_dispatcher_self_loop_target() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=101",
                source_block_serial=101,
                source_state_const=0x20,
            ),
        ),
        dispatch_map=_dispatch_map(),
    )

    assert resolutions[0].resolved_next_block_serial is None
    assert resolutions[0].resolution_reason == "target_is_dispatcher_block"


def test_non_branch_successor_is_not_dispatcher_bound() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=102",
                source_block_serial=102,
                source_state_const=0x10,
                successor_kind="fallthrough",
            ),
        ),
        dispatch_map=_dispatch_map(),
    )

    assert resolutions[0].resolved_next_block_serial is None
    assert "not a dispatcher-bound transition" in resolutions[0].resolution_reason


def test_projects_validated_fact_view_to_transition_evidence() -> None:
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(
            FactObservation(
                fact_id="state_transition_anchor:blk=100",
                kind="StateTransitionAnchorFact",
                semantic_key="state_transition_anchor:blk=100",
                maturity="MMAT_GLBOPT1",
                phase="pre_d810",
                confidence=0.85,
                payload={
                    "source_block_serial": 100,
                    "source_state_const": 0x10,
                    "source_state_const_hex": "0x00000010",
                    "successor_kind": "branch",
                    "state_var_stkoff": 0x3C,
                },
            ),
            FactObservation(
                fact_id="state_write_anchor:blk=7",
                kind="StateWriteAnchorFact",
                semantic_key="state_write_anchor:blk=7",
                maturity="MMAT_GLBOPT1",
                phase="pre_d810",
                confidence=0.9,
                payload={
                    "block_serial": 7,
                    "state_const_u64": 0x55,
                    "state_var_stkoff": 0x3C,
                },
            ),
        ),
    )

    transition_facts, state_write_anchors = facts_from_validated_view(view)

    assert transition_facts == (
        StateTransitionFact(
            fact_id="state_transition_anchor:blk=100",
            source_block_serial=100,
            source_state_const=0x10,
            source_state_const_hex="0x00000010",
            successor_kind="branch",
            state_var_stkoff=0x3C,
        ),
    )
    assert state_write_anchors == (
        StateWriteAnchor(
            block_serial=7,
            state_const=0x55,
            state_var_stkoff=0x3C,
        ),
    )


# --- Surface-1 binop-over-register next-state folding (ticket d81-7zf7) -------
#
# A handler whose next-state is COMPUTED (``xor eax,ecx -> state_var``) rather
# than a literal ``mov #const`` produces no ``StateWriteAnchor``.  The portable
# resolver folds it along the handler's single corridor via the snapshot
# path-eval and accepts the folded value only when it is a known dispatcher
# target.

# Synthetic opcode / operand-type integer tags.  The portable evaluator reads
# them through the injected seams below, so any self-consistent scheme works.
_OP_MOV = 4
_OP_XOR = 31
_T_NUM = 2
_T_STK = 4
_T_REG = 1
_T_LVAR = 9

_OPCODE_NAMES = {_OP_MOV: "m_mov", _OP_XOR: "m_xor"}
_OPCODE_VALUES = {"m_mov": _OP_MOV, "m_xor": _OP_XOR}
_MOP_NAMES = {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r", _T_LVAR: "mop_l"}
_MOP_VALUES = {"mop_n": _T_NUM, "mop_S": _T_STK, "mop_r": _T_REG, "mop_l": _T_LVAR}


def _eval_seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: _MOP_NAMES.get(t),
        mop_type_value=lambda name, default: _MOP_VALUES.get(name, default),
        opcode_value=lambda name, default: _OPCODE_VALUES.get(name, default),
        opcode_name=lambda op: _OPCODE_NAMES.get(op),
        fetch_stable_global_value=lambda _addr, _size: None,
        lvar_stkoff=lambda _mba, _idx: -1,
    )


@pytest.fixture
def _portable_bst_walkers():
    """Register a portable ``forward_eval_insn`` for the fold path; reset after."""
    from d810.capabilities import providers as _providers

    seams = _eval_seams()

    def _forward_eval_insn(insn, stk_map, reg_map, state_var_stkoff, **kwargs):
        kwargs.pop("seams", None)
        return _portable_forward_eval_insn(
            insn,
            stk_map,
            reg_map,
            state_var_stkoff,
            seams=seams,
            mba=kwargs.pop("mba", None),
            state_var_lvar_idx=kwargs.pop("state_var_lvar_idx", None),
        )

    provider = BstWalkerProvider(
        detect_state_var_stkoff=lambda *a, **k: None,
        dump_dispatcher_node=lambda *a, **k: None,
        find_pre_header_state=lambda *a, **k: None,
        walk_handler_chain=lambda *a, **k: None,
        forward_eval_insn=_forward_eval_insn,
        resolve_via_bst_walk=lambda *a, **k: None,
        get_block=lambda mba, serial: mba.get_block(serial),
        block_successors=lambda blk: tuple(blk.succs),
    )
    register_bst_walkers(provider)
    try:
        yield
    finally:
        _providers.reset_providers_for_tests()


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=_T_NUM, size=4, value=value, kind=OperandKind.NUMBER)


def _reg(reg: int) -> MopSnapshot:
    return MopSnapshot(t=_T_REG, size=4, reg=reg, kind=OperandKind.REGISTER)


def _stk(off: int) -> MopSnapshot:
    return MopSnapshot(t=_T_STK, size=4, stkoff=off, kind=OperandKind.STACK)


def _mov(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV
    )


def _xor(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_XOR, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND
    )


def _fold_dispatch_map() -> StateDispatcherMap:
    """Dispatcher whose state set contains the folded next-state 0x1A2893D9.

    State 0x10 routes to handler blk 10 (no literal write); 0x1A2893D9 is the
    next-state that the handler corridor computes via ``xor``, and it routes to
    handler blk 20 so the fold is accepted.
    """
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=10,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=RouterKind.SWITCH,
            ),
            StateDispatcherRow(
                state_const=0x1A2893D9,
                target_block=20,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=RouterKind.SWITCH,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x64,
        state_var_lvar_idx=None,
        source=RouterKind.SWITCH,
    )


def _fold_flow_graph() -> FlowGraph:
    """Handler blk 10 loads two reg consts; its single-succ blk 11 xors them.

    0x12345678 ^ 0x081CC5A1 == 0x1A2893D9, written to the state slot (0x64).
    Block 2 is the dispatcher (re-entry stop); blk 20 is the resolved target.
    """
    state_off = 0x64
    blk10 = BlockSnapshot(
        serial=10,
        block_type=0,
        succs=(11,),
        preds=(2,),
        flags=0,
        start_ea=0x1000,
        insn_snapshots=(
            _mov(0x1000, _num(0x12345678), _reg(8)),
            _mov(0x1004, _num(0x081CC5A1), _reg(9)),
        ),
    )
    blk11 = BlockSnapshot(
        serial=11,
        block_type=0,
        succs=(2,),
        preds=(10,),
        flags=0,
        start_ea=0x1008,
        insn_snapshots=(_xor(0x1008, _reg(8), _reg(9), _stk(state_off)),),
    )
    blk2 = BlockSnapshot(
        serial=2,
        block_type=0,
        succs=(10, 20),
        preds=(11,),
        flags=0,
        start_ea=0x2000,
        insn_snapshots=(_mov(0x2000, _num(0), _reg(0)),),
    )
    blk20 = BlockSnapshot(
        serial=20,
        block_type=0,
        succs=(),
        preds=(2,),
        flags=0,
        start_ea=0x3000,
        insn_snapshots=(_mov(0x3000, _num(0), _reg(0)),),
    )
    return FlowGraph(
        blocks={10: blk10, 11: blk11, 2: blk2, 20: blk20},
        entry_serial=2,
        func_ea=0x1000,
    )


def test_folds_binop_over_register_next_state(_portable_bst_walkers) -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=100",
                source_block_serial=100,
                source_state_const=0x10,
                source_state_const_hex="0x00000010",
                state_var_stkoff=0x64,
            ),
        ),
        dispatch_map=_fold_dispatch_map(),
        state_write_anchors=(),  # NO literal anchor at the routed handler blk 10
        graph=_fold_flow_graph(),
        state_var_stkoff=0x64,
    )

    assert len(resolutions) == 1
    res = resolutions[0]
    assert res.resolved_next_block_serial == 10
    assert res.resolved_next_state_const_u64 == 0x1A2893D9
    assert res.resolved_next_state_const_hex == "0x000000001a2893d9"
    assert res.resolution_reason == "resolved_folded_state_write"


def test_fold_rejected_when_value_not_a_known_target(_portable_bst_walkers) -> None:
    # Same graph, but the dispatcher map lacks 0x1A2893D9 in its state set, so
    # the folded value is not a known target -> next-state stays BLANK.
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=10,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=RouterKind.SWITCH,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x64,
        state_var_lvar_idx=None,
        source=RouterKind.SWITCH,
    )

    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=100",
                source_block_serial=100,
                source_state_const=0x10,
                state_var_stkoff=0x64,
            ),
        ),
        dispatch_map=dispatch_map,
        state_write_anchors=(),
        graph=_fold_flow_graph(),
        state_var_stkoff=0x64,
    )

    res = resolutions[0]
    assert res.resolved_next_block_serial == 10
    assert res.resolved_next_state_const_u64 is None
    assert res.resolution_reason == "resolved_exact_state"


def test_literal_anchor_is_not_overridden_by_fold(_portable_bst_walkers) -> None:
    # A literal write anchor present at the routed handler wins; the fold path
    # is never consulted (additive/safe: only fills previously-BLANK states).
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=100",
                source_block_serial=100,
                source_state_const=0x10,
                state_var_stkoff=0x64,
            ),
        ),
        dispatch_map=_fold_dispatch_map(),
        state_write_anchors=(
            StateWriteAnchor(block_serial=10, state_const=0x10, state_var_stkoff=0x64),
        ),
        graph=_fold_flow_graph(),
        state_var_stkoff=0x64,
    )

    res = resolutions[0]
    assert res.resolved_next_state_const_u64 == 0x10
    assert res.resolution_reason == "resolved_exact_state"
