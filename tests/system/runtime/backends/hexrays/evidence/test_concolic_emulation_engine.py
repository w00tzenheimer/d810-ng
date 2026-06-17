"""Runtime tests for the ConcolicEmulationEngine + selector-anchored discovery (P2, llr-8wq9).

Drives the engine's live-``mba`` logic with ``SimpleNamespace`` shims shaped like
``mba_t`` / ``mblock_t`` / ``minsn_t`` / ``mop_t`` (real ``ida_hexrays`` opcode +
mop-type constants, no full decompile), exactly the pattern of
``test_decision_dag_extract``. This exercises the two P2 bug fixes structurally:

* **bug #1 (state-var mis-ID)**: ``discover_anchors`` anchors on the ``m_jtbl``
  SWITCHED slot (``var_8``), NOT the dominant self-update accumulator (``result``).
* **bug #2 (fork collapse)**: ``_fork_region_facts`` enumerates an identity-switch
  handler's ``mov #const`` next-state arms (which the self-update-only Slice 5 region
  scan misses) and surfaces a conditional handler as a complete 2-arm fork.

IDA-dependent (reads ``ida_hexrays`` constants) -> system/runtime, not a unit. The
runtime conftest auto-marks this ``ida_required``.
"""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import RecoveredMachine, Soundness
from d810.backends.hexrays.evidence.concolic_emulation_engine import (
    ConcolicEmulationEngine,
    ConcolicProvenance,
    RecoveryCaps,
)
from d810.backends.hexrays.evidence.dispatcher_anchor_discovery import (
    _jtbl_selector_stkoff,
    _resolve_mop_to_stkoff,
    discover_anchors,
)
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    EmulationDispatcherResolver,
)

# Stack offsets: var_8 is the SWITCHED state slot; result is the accumulator that the
# Slice 5 dominant-self-update heuristic would wrongly pick.
OFF_STATE = 0x8
OFF_RESULT = 0x18


# --- mop / insn / block / mba shims ---------------------------------------------------
def _stk(off, size=4):
    return SimpleNamespace(
        t=ida_hexrays.mop_S, s=SimpleNamespace(off=off), size=size, d=None, l=None
    )


def _const(value, size=4):
    return SimpleNamespace(
        t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value), size=size, s=None, d=None, l=None
    )


def _xdu_of(inner):
    """A widening ``xdu.4(inner)`` operand: mop_d wrapping an m_xdu minsn."""
    return SimpleNamespace(
        t=ida_hexrays.mop_d,
        d=SimpleNamespace(opcode=ida_hexrays.m_xdu, l=inner),
        s=None,
        l=None,
        size=4,
    )


def _insn(opcode, d=None, l=None, r=None):
    return SimpleNamespace(opcode=opcode, d=d, l=l, r=r, next=None)


def _chain(*insns):
    for a, b in zip(insns, insns[1:]):
        a.next = b
    return insns[0] if insns else None


def _blk(serial, *, head=None, tail=None, succs=()):
    return SimpleNamespace(
        serial=serial,
        head=head,
        tail=tail,
        _succs=[int(s) for s in succs],
        nsucc=lambda s=succs: len(s),
        succ=lambda i, s=succs: int(list(s)[i]),
    )


def _self_update(off, opcode, const):
    """``stkvar = stkvar OP #const`` (matches EmulationDispatcherResolver._as_self_update)."""
    d = _stk(off)
    return _insn(opcode, d=d, l=_stk(off), r=_const(const))


def _mov_const(off, const):
    """``stkvar = mov #const`` (the identity-switch next-state write)."""
    return _insn(ida_hexrays.m_mov, d=_stk(off), l=_const(const))


def _mba(blocks):
    by_serial = {int(b.serial): b for b in blocks}
    return SimpleNamespace(
        qty=len(blocks),
        get_mblock=lambda s: by_serial.get(int(s)),
        entry_ea=0,
        maturity=0,
    )


# =====================================================================================
# bug #1 -- selector-anchored discovery
# =====================================================================================
class TestSelectorAnchoring:
    def test_resolve_mop_peels_xdu_to_stack_slot(self):
        # xdu.4(var_8.1) -> the slot var_8, not a temporary.
        off, idx = _resolve_mop_to_stkoff(None, _xdu_of(_stk(OFF_STATE, size=1)))
        assert off == OFF_STATE
        assert idx is None

    def test_resolve_mop_direct_stack_slot(self):
        off, idx = _resolve_mop_to_stkoff(None, _stk(OFF_STATE))
        assert off == OFF_STATE and idx is None

    def test_resolve_mop_non_slot_returns_none(self):
        off, idx = _resolve_mop_to_stkoff(None, _const(5))
        assert off is None and idx is None

    def test_jtbl_selector_reads_switched_operand(self):
        # entry tail: jtbl xdu.4(var_8), <cases>  -> the switched value is var_8.
        jtbl = _insn(ida_hexrays.m_jtbl, l=_xdu_of(_stk(OFF_STATE, size=1)))
        entry = _blk(1, head=jtbl, tail=jtbl, succs=(2, 3))
        mba = _mba([entry])
        off, idx = _jtbl_selector_stkoff(mba, 1)
        assert off == OFF_STATE

    def test_anchor_picks_jtbl_selector_not_result_accumulator(self):
        # The dispatcher is switch(var_8); var_8 is the selector. The prelim mistakenly
        # carries result (OFF_RESULT) as the state slot (simulating the dominant-self-
        # update bug). discover_anchors must OVERRIDE it with the jtbl selector var_8.
        jtbl = _insn(ida_hexrays.m_jtbl, l=_xdu_of(_stk(OFF_STATE, size=1)))
        entry = _blk(1, head=jtbl, tail=jtbl, succs=(2, 3))
        mba = _mba([entry])
        prelim = StateDispatcherMap(
            rows=(),
            dispatcher_entry_block=1,
            dispatcher_blocks=frozenset(),
            state_var_stkoff=OFF_RESULT,  # the WRONG slot the bug would pick
            state_var_lvar_idx=None,
            router_kind=RouterKind.SWITCH,
            initial_state=0,
        )
        anchors = discover_anchors(mba, graph=None, prelim=prelim)
        assert anchors is not None
        assert anchors.dispatcher_entry_block == 1
        assert anchors.state_var_stkoff == OFF_STATE  # selector, not result
        assert anchors.live_mba is mba

    def test_anchor_keeps_equality_slot_when_no_jtbl(self):
        # No jtbl tail (equality chain): keep the prelim compared slot, no override.
        cmp_tail = _insn(ida_hexrays.m_jz, l=_stk(OFF_STATE), r=_const(7))
        entry = _blk(1, head=cmp_tail, tail=cmp_tail, succs=(2, 3))
        mba = _mba([entry])
        prelim = StateDispatcherMap(
            rows=(),
            dispatcher_entry_block=1,
            dispatcher_blocks=frozenset(),
            state_var_stkoff=OFF_STATE,
            state_var_lvar_idx=None,
            router_kind=RouterKind.CONDITION_CHAIN,
            initial_state=0,
        )
        anchors = discover_anchors(mba, graph=None, prelim=prelim)
        assert anchors is not None
        assert anchors.state_var_stkoff == OFF_STATE

    def test_anchor_none_when_no_entry(self):
        mba = _mba([])
        assert discover_anchors(mba, graph=None, prelim=None) is None


# =====================================================================================
# bug #2 -- forking arm enumeration (mov-const next states + 2-arm fork)
# =====================================================================================
def _engine_with(mba):
    return ConcolicEmulationEngine(mba=mba)


def _disc(entry, stkoff, init=0):
    return SimpleNamespace(
        entry=entry, stkoff=stkoff, var_size=4, state_mop=_stk(stkoff), initial_state=init
    )


class TestForkRegionFacts:
    def test_linear_mov_const_handler_yields_one_arm(self):
        # Handler block writes state = mov #5 (identity-switch next state). Slice 5's
        # self-update-only scan misses this; the engine's region scan records 1 arm.
        h = _blk(10, head=_chain(_mov_const(OFF_STATE, 5)), tail=None, succs=())
        mba = _mba([h])
        eng = _engine_with(mba)
        host = EmulationDispatcherResolver(mba=mba)
        facts = eng._fork_region_facts(host, _disc(1, OFF_STATE), 10, {}, RecoveryCaps())
        assert facts.arms == ((None, 5),)
        assert facts.complete is True
        assert facts.via_block == 10

    def test_self_update_handler_yields_op_arm(self):
        # state ^= 0x11 -> one (m_xor, 0x11) arm (the XOR-machine path, preserved).
        h = _blk(
            10, head=_chain(_self_update(OFF_STATE, ida_hexrays.m_xor, 0x11)), succs=()
        )
        mba = _mba([h])
        eng = _engine_with(mba)
        host = EmulationDispatcherResolver(mba=mba)
        facts = eng._fork_region_facts(host, _disc(1, OFF_STATE), 10, {}, RecoveryCaps())
        assert facts.arms == ((ida_hexrays.m_xor, 0x11),)

    def test_conditional_handler_yields_two_arm_fork(self):
        # Handler forks: block 10 -> {11 writes state=2, 12 writes state=3}. Two arms.
        h0 = _blk(10, head=None, tail=None, succs=(11, 12))
        h1 = _blk(11, head=_chain(_mov_const(OFF_STATE, 2)), succs=())
        h2 = _blk(12, head=_chain(_mov_const(OFF_STATE, 3)), succs=())
        mba = _mba([h0, h1, h2])
        eng = _engine_with(mba)
        host = EmulationDispatcherResolver(mba=mba)
        facts = eng._fork_region_facts(host, _disc(1, OFF_STATE), 10, {}, RecoveryCaps())
        assert facts.complete is True
        assert set(facts.arms) == {(None, 2), (None, 3)}
        assert len(facts.arms) == 2

    def test_more_than_two_arms_is_incomplete_abstain(self):
        # A 3-way branch the engine cannot fully enumerate -> complete=False (abstain).
        h0 = _blk(10, succs=(11, 12, 13))
        h1 = _blk(11, head=_chain(_mov_const(OFF_STATE, 2)), succs=())
        h2 = _blk(12, head=_chain(_mov_const(OFF_STATE, 3)), succs=())
        h3 = _blk(13, head=_chain(_mov_const(OFF_STATE, 4)), succs=())
        mba = _mba([h0, h1, h2, h3])
        eng = _engine_with(mba)
        host = EmulationDispatcherResolver(mba=mba)
        facts = eng._fork_region_facts(host, _disc(1, OFF_STATE), 10, {}, RecoveryCaps())
        assert len(facts.arms) == 3
        assert facts.complete is False

    def test_region_never_crosses_dispatcher_entry(self):
        # A handler whose successor is the dispatcher entry must not read entry's writes.
        h = _blk(10, head=_chain(_mov_const(OFF_STATE, 9)), succs=(1,))
        entry = _blk(1, head=_chain(_mov_const(OFF_STATE, 0xDEAD)), succs=())
        mba = _mba([h, entry])
        eng = _engine_with(mba)
        host = EmulationDispatcherResolver(mba=mba)
        facts = eng._fork_region_facts(host, _disc(1, OFF_STATE), 10, {}, RecoveryCaps())
        assert facts.arms == ((None, 9),)  # 0xDEAD from entry excluded


class TestApplyArm:
    def test_mov_const_arm_is_absolute(self):
        host = EmulationDispatcherResolver(mba=_mba([]))
        # opcode None -> next state IS the const (identity switch), masked.
        assert ConcolicEmulationEngine._apply_arm(host, 0x99, None, 5, 0xFFFFFFFF) == 5

    def test_self_update_arm_applies_op(self):
        host = EmulationDispatcherResolver(mba=_mba([]))
        # state ^ const via the Slice 5 operator table (single source of truth).
        got = ConcolicEmulationEngine._apply_arm(
            host, 0xFF, ida_hexrays.m_xor, 0x0F, 0xFFFFFFFF
        )
        assert got == (0xFF ^ 0x0F)


# =====================================================================================
# engine assembly -- EXACT_BOUNDED tagging, populated transitions, abstain rules
# =====================================================================================
class TestEngineAssembly:
    def test_disabled_engine_abstains(self):
        eng = ConcolicEmulationEngine(mba=_mba([]), enabled=False)
        assert eng.recover(graph=None, anchors=DispatcherAnchors()) is None

    def test_no_state_slot_abstains(self):
        eng = ConcolicEmulationEngine(mba=_mba([]))
        anchors = DispatcherAnchors(dispatcher_entry_block=1)  # no state slot
        assert eng.recover(graph=None, anchors=anchors) is None

    def test_build_machine_rejects_truncated(self):
        eng = _engine_with(_mba([]))
        out = eng._build_machine(
            _disc(1, OFF_STATE),
            DispatcherAnchors(dispatcher_entry_block=1, state_var_stkoff=OFF_STATE),
            rows_map={0: 10, 1: 11, 2: 12},
            transitions=[],
            dispatch_blocks_seen=set(),
            truncated=True,  # runaway -> reject
            caps=RecoveryCaps(),
            prov=ConcolicProvenance(),
        )
        assert out is None

    def test_build_machine_rejects_sub_threshold(self):
        eng = _engine_with(_mba([]))
        out = eng._build_machine(
            _disc(1, OFF_STATE),
            DispatcherAnchors(dispatcher_entry_block=1, state_var_stkoff=OFF_STATE),
            rows_map={0: 10},  # 1 row < min_recovered_rows=2
            transitions=[],
            dispatch_blocks_seen=set(),
            truncated=False,
            caps=RecoveryCaps(),
            prov=ConcolicProvenance(),
        )
        assert out is None

    def test_build_machine_tags_exact_bounded_with_transitions(self):
        from d810.analyses.control_flow.concolic_machine_walk import WalkTransition

        eng = _engine_with(_mba([]))
        out = eng._build_machine(
            _disc(1, OFF_STATE, init=0),
            DispatcherAnchors(dispatcher_entry_block=1, state_var_stkoff=OFF_STATE),
            rows_map={0: 10, 1: 11, 2: 12},
            transitions=[
                WalkTransition(src_state=0, next_states=(1, 2), via_block=10),
                WalkTransition(src_state=1, next_states=(2,), via_block=11, op="^", const=3),
            ],
            dispatch_blocks_seen={1, 5},
            truncated=False,
            caps=RecoveryCaps(),
            prov=ConcolicProvenance(visited_state_count=3),
        )
        assert isinstance(out, RecoveredMachine)
        assert out.soundness is Soundness.EXACT_BOUNDED
        assert len(out.rows) == 3
        # The forking transitions are carried (the new P2 contract data).
        assert len(out.transitions) == 2
        fork = [t for t in out.transitions if t.via_block == 10][0]
        assert fork.next_states == (1, 2)  # first-class 2-arm fork preserved
        assert fork.context == ()
        linear = [t for t in out.transitions if t.via_block == 11][0]
        assert linear.next_states == (2,)
        assert linear.op == "^" and linear.const == 3
        assert out.dispatcher_entry_block == 1
        assert {1, 5} <= out.dispatcher_blocks
        assert out.state_var_stkoff == OFF_STATE
        assert "concolic_emulation" in out.provenance

    def test_provenance_as_tuple_serializes_counters(self):
        prov = ConcolicProvenance(
            visited_state_count=4, unresolved_state_count=1, fold_count=2
        )
        t = prov.as_tuple()
        assert "concolic_emulation" in t
        assert "visited=4" in t
        assert "unresolved=1" in t
        assert "fold_count=2" in t

    def test_recover_caps_defaults_match_slice5_constants(self):
        from d810.backends.hexrays.evidence import emulation_dispatcher_resolver as r

        caps = RecoveryCaps()
        assert caps.max_dispatch_steps == r._MAX_DISPATCH_STEPS
        assert caps.max_region_blocks == r._MAX_REGION_BLOCKS
        assert caps.min_recovered_rows == r._MIN_RECOVERED_ROWS

    def test_engine_satisfies_machine_recovery_engine_protocol(self):
        from d810.analyses.control_flow.machine_recovery_engine import (
            MachineRecoveryEngine,
        )

        eng = ConcolicEmulationEngine(mba=_mba([]))
        assert isinstance(eng, MachineRecoveryEngine)
        assert eng.name == "concolic_emulation"
