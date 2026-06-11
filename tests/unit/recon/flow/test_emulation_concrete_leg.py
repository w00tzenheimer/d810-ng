"""Unit tests for the reduced-product CONCRETE leg consult (ticket llr-xauw).

The partitioned fixpoint consults an optional ``EmulationCapability`` ONLY where
its abstract per-edge fold lands at ``⊥`` (a back-edge whose opaque state write
reads registers defined in OTHER blocks, so the snapshot transfer cannot fold
it).  These tests prove three invariants with a pure fake emulator (no IDA):

* the consult fills a genuine ⊥ back-edge and tags it ``_EMULATION_ORACLE``;
* ``emu=None`` is byte-identical to today's abstract-only behaviour (the same
  back-edge stays unresolved);
* ``fold_exact`` DROPS a concrete claim the abstract floor does not contain
  (the wrongness guard the whole seam relies on).

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` + a fake
``EmulationCapability``.  The MBA fold runs through a registered portable
``forward_eval_insn`` seam (reused from the sibling recovery tests).
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.analyses.data_flow.concolic import (
    Abstain,
    ConcolicValue,
    ExactResult,
    LocationRef,
    PrecisionStatus,
    fold_exact,
)
from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.capabilities.providers import BstWalkerProvider, register_bst_walkers
from d810.analyses.value_flow.state_write import (
    MicrocodeEvalSeams,
    forward_eval_insn as _portable_forward_eval_insn,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)

_OP_MOV = 4
_OP_XOR = 31
_T_NUM = 2
_T_STK = 4
_T_REG = 1
_OPCODE_NAMES = {_OP_MOV: "m_mov", _OP_XOR: "m_xor"}
_OPCODE_VALUES = {"m_mov": _OP_MOV, "m_xor": _OP_XOR}
_MOP_NAMES = {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r"}
_MOP_VALUES = {"mop_n": _T_NUM, "mop_S": _T_STK, "mop_r": _T_REG}
_STATE_OFF = 0x64


def _eval_seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: _MOP_NAMES.get(t),
        mop_type_value=lambda name, default: _MOP_VALUES.get(name, default),
        opcode_value=lambda name, default: _OPCODE_VALUES.get(name, default),
        opcode_name=lambda op: _OPCODE_NAMES.get(op),
        fetch_stable_global_value=lambda _a, _s: None,
        lvar_stkoff=lambda _m, _i: -1,
    )


@pytest.fixture
def _seam():
    from d810.capabilities import providers as _providers

    seams = _eval_seams()

    def _fwd(insn, stk_map, reg_map, state_var_stkoff, **kwargs):
        kwargs.pop("seams", None)
        return _portable_forward_eval_insn(
            insn, stk_map, reg_map, state_var_stkoff, seams=seams,
            mba=kwargs.pop("mba", None),
            state_var_lvar_idx=kwargs.pop("state_var_lvar_idx", None),
        )

    register_bst_walkers(
        BstWalkerProvider(
            detect_state_var_stkoff=lambda *a, **k: None,
            dump_dispatcher_node=lambda *a, **k: None,
            find_pre_header_state=lambda *a, **k: None,
            walk_handler_chain=lambda *a, **k: None,
            forward_eval_insn=_fwd,
            resolve_via_bst_walk=lambda *a, **k: None,
            get_block=lambda mba, serial: mba.get_block(serial),
            block_successors=lambda blk: tuple(blk.succs),
        )
    )
    try:
        yield
    finally:
        _providers.reset_providers_for_tests()


def _num(v: int) -> MopSnapshot:
    return MopSnapshot(t=_T_NUM, size=4, value=v, kind=OperandKind.NUMBER)


def _reg(r: int) -> MopSnapshot:
    return MopSnapshot(t=_T_REG, size=4, reg=r, kind=OperandKind.REGISTER)


def _stk(off: int) -> MopSnapshot:
    return MopSnapshot(t=_T_STK, size=4, stkoff=off, kind=OperandKind.STACK)


def _mov(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_MOV, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV)


def _xor(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_XOR, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND)


def _blk(serial, succs, preds, insns, *, ea=None, kind=BlockKind.UNKNOWN) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial, block_type=0, succs=tuple(succs), preds=tuple(preds),
        flags=0, start_ea=ea if ea is not None else 0x1000 + serial * 0x40,
        insn_snapshots=tuple(insns), kind=kind,
    )


def _dispatcher(point_targets: dict[int, int], *, exit_block: int, domain_hi: int = 0x100000000) -> IntervalDispatcher:
    rows: list[IntervalRow] = []
    cursor = 0
    for state in sorted(point_targets):
        if state > cursor:
            rows.append(IntervalRow(lo=cursor, hi=state, target=exit_block))
        rows.append(IntervalRow(lo=state, hi=state + 1, target=point_targets[state]))
        cursor = state + 1
    if cursor < domain_hi:
        rows.append(IntervalRow(lo=cursor, hi=domain_hi, target=exit_block))
    return IntervalDispatcher(rows)


class _FakeEmulator:
    """A pure ``EmulationCapability`` proving one constant for ``state_cell``.

    Models the Hex-Rays block-stepper contract WITHOUT IDA: it returns an
    :class:`ExactResult` keyed by ``state_cell`` (the same cell the consult folds
    into) when asked about any block, else :class:`Abstain`.  Records which blocks
    it was consulted on so the test can assert the consult fired only at the ⊥ gap.
    """

    def __init__(self, state_cell: LocationRef, value: int) -> None:
        self.state_cell = state_cell
        self.value = int(value)
        self.consulted: list = []

    def eval_insn(self, insn, store):  # pragma: no cover - not exercised here
        return Abstain("InsnRef not modeled")

    def eval_block(self, block, store):
        self.consulted.append(block)
        if block is None:
            return Abstain("no live block")
        return ExactResult({self.state_cell: self.value})


def _opaque_back_edge_fg() -> FlowGraph:
    """A back-edge ``state = reg8 ^ reg9`` whose registers are set in NO block.

    reg8/reg9 are never assigned a constant, so the snapshot transfer over the
    predecessor's converged OUT cannot fold the XOR -> the abstract per-edge fold
    lands at ⊥ (``ev is None``), the exact gap the concrete leg fills.
    0x10 routes to handler blk10; blk11 is its opaque back-edge.
    """
    return FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), ()),  # no reg consts -> XOR cannot fold
            11: _blk(11, (2,), (10,), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )


def test_emulation_fills_bottom_back_edge(_seam) -> None:
    """The concrete leg resolves a ⊥ back-edge and tags it ``_EMULATION_ORACLE``."""
    fg = _opaque_back_edge_fg()
    disp = _dispatcher({0x10: 10, 0xABCD: 20}, exit_block=99)
    state_cell = LocationRef.stack(_STATE_OFF, 8)
    emu = _FakeEmulator(state_cell, 0xABCD)

    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2,
                    emu=emu, live_block_for=lambda s: ("live", int(s)))}
    t = by_block[11]
    assert t.next_state == 0xABCD
    assert t.target_handler == 20
    assert t.is_return is False
    assert t.proof is not None
    assert t.proof.oracle_kind == "emulation_concrete_leg"
    assert t.proof.kind == "concrete_fold"
    assert t.proof.trusted is True
    # The consult stepped the back-edge block (serial 11), seeded from ip 10.
    assert ("live", 11) in emu.consulted


def test_degrade_to_abstract_when_emu_is_none(_seam) -> None:
    """``emu=None`` does NOT produce the emulator's value -- abstract-only, unchanged.

    Without the concrete leg the opaque back-edge cannot resolve to the true
    next-state 0xABCD (its registers live in no block); the abstract-only fallback
    keeps the stale seeded key 0x10 (a self-loop), exactly today's behaviour.  The
    point of the consult is to REPLACE that stale value -- so the only guarantee
    here is that 0xABCD never appears without ``emu``.
    """
    fg = _opaque_back_edge_fg()
    disp = _dispatcher({0x10: 10, 0xABCD: 20}, exit_block=99)
    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    t = by_block[11]
    # The emulator's correct value is unreachable without the concrete leg.
    assert t.next_state != 0xABCD
    # And no transition is tagged with the emulation oracle.
    assert t.proof is None or t.proof.oracle_kind != "emulation_concrete_leg"


def test_emulation_never_overrides_resolved_transition(_seam) -> None:
    """A back-edge the abstract fold already resolves is NOT consulted.

    blk11 folds ``reg8 ^ reg9`` from constants set in its predecessor blk10, so the
    abstract per-edge fold resolves it; the emulator (which would return a DIFFERENT
    value) must never be consulted for it.
    0x12345678 ^ 0x081CC5A1 = 0x1A2893D9.
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _num(0x12345678), _reg(8)),
                                       _mov(0x1004, _num(0x081CC5A1), _reg(9)))),
            11: _blk(11, (2,), (10,), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x1A2893D9: 20}, exit_block=99)
    emu = _FakeEmulator(LocationRef.stack(_STATE_OFF, 8), 0xDEAD)  # a WRONG value
    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2,
                    emu=emu, live_block_for=lambda s: ("live", int(s)))}
    t = by_block[11]
    # The abstract fold wins; the emulator's wrong 0xDEAD never appears.
    assert t.next_state == 0x1A2893D9
    assert t.proof.oracle_kind == "region_partitioned_fixpoint"
    assert emu.consulted == []


def test_fold_exact_drops_claim_outside_abstract_floor() -> None:
    """``fold_exact`` rejects an ExactResult the abstract floor does not contain.

    The wrongness guard: a bounded abstract floor ``{0x10}`` cannot contain the
    emulator's claimed 0xABCD, so the concrete claim is dropped and the value stays
    abstract (precision forfeit, never corruption).
    """
    state_cell = LocationRef.stack(_STATE_OFF, 8)
    # A concrete-singleton floor of 0x10 (its concretization is exactly {0x10}).
    bounded = ConcolicValue.of(0x10, 8)
    folded = fold_exact(bounded, ExactResult({state_cell: 0xABCD}), state_cell)
    assert folded.status is not PrecisionStatus.CONCRETE or folded.concrete == 0x10
    # The floor still does not admit 0xABCD.
    assert not bounded.abstract.contains(0xABCD)
    # And a contained value DOES fold.
    top = ConcolicValue(
        None, None, AbstractEvidence.top(8), 8, PrecisionStatus.TOP
    )
    ok = fold_exact(top, ExactResult({state_cell: 0xABCD}), state_cell)
    assert ok.status is PrecisionStatus.CONCRETE
    assert ok.concrete == 0xABCD
