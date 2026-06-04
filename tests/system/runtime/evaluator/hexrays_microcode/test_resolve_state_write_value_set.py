"""Wiring tests for the T2 value-set state-write resolver (S5d).

``resolve_state_write_value_set`` recovers the ``OneOf`` powerset when a handler
writes the dispatcher state var from a *bare source variable* that is itself
written by several distinct const ``mov`` sites (a shared OLLVM temp).  T1's
local const-fold returns ``⊤`` for such a multi-valued source; T2 DU-collects
all reaching defs and projects their consts into a value set.

The reaching-def provider is injectable, so these tests drive it with a fake
(no real DU graph) -- but the resolver still reads real ``ida_hexrays`` mop /
opcode constants to identify the bare source and read each def's const ``mov``,
so the fixtures are ``SimpleNamespace`` shims shaped like ``mop_t`` / ``minsn_t``.

IDA-dependent (reads ``ida_hexrays`` constants) -> system/runtime, not a unit.
"""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.analyses.data_flow.abstract_value import TOP, Const, OneOf
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    resolve_state_write_value_set,
)

# The grounded S5d case: state var ``var_7BC`` @ stkoff 0x3C, shared source temp
# ``var_70`` @ stkoff 0x788 with two const writers.
_STATE_OFF = 0x3C
_SRC_OFF = 0x788
_W = 4
_A = 0x41FB8FBB  # blk194: mov #0x41FB8FBB, var_70
_B = 0x71E22BF3  # blk51:  mov #0x71E22BF3, var_70


# --------------------------------------------------------------------------- shims
def _mop_S(off: int, size: int = _W):
    return SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=off), size=size)


def _mop_n(value: int, size: int = _W):
    return SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value), size=size)


def _insn(opcode, *, d=None, l=None, r=None):
    return SimpleNamespace(opcode=opcode, d=d, l=l, r=r, ea=0, next=None)


def _block(*insns, succset=()):
    head = None
    for ins in reversed(insns):
        ins.next = head
        head = ins
    return SimpleNamespace(head=head, succset=tuple(int(s) for s in succset))


def _mba(blocks: dict[int, object]):
    return SimpleNamespace(get_mblock=lambda serial: blocks.get(int(serial)))


# --------------------------------------------------------------------------- tests
def test_value_set_resolver_returns_oneof_for_shared_temp():
    # blk195: mov var_70, var_7BC   (state write reads the bare shared source)
    state_write_blk = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(_SRC_OFF))
    )
    # blk194 / blk51: the two distinct const writers of var_70.
    def_a = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_A)))
    def_b = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_B)))
    mba = _mba({195: state_write_blk, 194: def_a, 51: def_b})

    def fake_provider(_mba, *, block_serial, stkoff, size):
        assert block_serial == 195 and stkoff == _SRC_OFF
        return [194, 51]

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=195,
        state_var_stkoff=_STATE_OFF,
        reaching_def_blocks_provider=fake_provider,
    )
    assert isinstance(v, OneOf)
    assert v.values == frozenset({_A, _B})


def test_value_set_resolver_singleton_is_const():
    state_write_blk = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(_SRC_OFF))
    )
    def_a = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_A)))
    mba = _mba({195: state_write_blk, 194: def_a})

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=195,
        state_var_stkoff=_STATE_OFF,
        reaching_def_blocks_provider=lambda *a, **k: [194],
    )
    assert v == Const(_A, 4)


def test_value_set_resolver_non_const_def_falls_back_to_top():
    # One reaching def is non-const (mov var_X, var_70) -> value set not fully
    # known -> T1 fold of the state-write block also yields ⊤ (bare cross-block
    # source, no resolver) -> ⊤.
    state_write_blk = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(_SRC_OFF))
    )
    def_a = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_A)))
    def_nonconst = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_S(0x999))
    )
    mba = _mba({195: state_write_blk, 194: def_a, 51: def_nonconst})

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=195,
        state_var_stkoff=_STATE_OFF,
        reaching_def_blocks_provider=lambda *a, **k: [194, 51],
    )
    assert v is TOP


def test_value_set_resolver_follows_corridor_to_staging_block():
    # Live sub_7FFD shape: handler 51 ``mov #placeholder, statevar`` then flows to
    # a dispatcher STAGING block 195 that ``mov var_70, statevar`` (the shared
    # temp).  The handler's own block has no bare-temp state write, so the
    # resolver must follow the corridor 51 -> 195 and value-set-resolve there.
    handler = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_n(0x258ED455)),
        succset=(195,),
    )
    staging = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(_SRC_OFF)),
        succset=(2,),  # -> dispatcher entry (corridor stop)
    )
    def_a = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_A)))
    def_b = _block(_insn(ida_hexrays.m_mov, d=_mop_S(_SRC_OFF), l=_mop_n(_B)))
    mba = _mba({51: handler, 195: staging, 194: def_a, 82: def_b})

    seen_block: list[int] = []

    def fake_provider(_mba, *, block_serial, stkoff, size):
        seen_block.append(int(block_serial))  # must be the staging block, not 51
        return [194, 82]

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=51,
        state_var_stkoff=_STATE_OFF,
        corridor_stop_serial=2,
        reaching_def_blocks_provider=fake_provider,
    )
    assert isinstance(v, OneOf)
    assert v.values == frozenset({_A, _B})
    assert seen_block == [195]  # reaching defs collected at the staging block


def test_value_set_resolver_corridor_stops_at_dispatcher_entry():
    # The corridor walk must not cross the dispatcher entry: a staging write that
    # only exists past corridor_stop is invisible -> T1 fold of the handler.
    handler = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_n(0x258ED455)),
        succset=(2,),  # only successor is the dispatcher entry itself
    )
    staging = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(_SRC_OFF)),
        succset=(),
    )
    mba = _mba({51: handler, 2: staging})

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=51,
        state_var_stkoff=_STATE_OFF,
        corridor_stop_serial=2,
        reaching_def_blocks_provider=lambda *a, **k: [0],
    )
    # No bare-temp write reachable before the stop -> T1 fold of handler 51's own
    # const write.
    assert v == Const(0x258ED455, 4)


def test_value_set_resolver_const_source_delegates_to_t1():
    # A bare local-constant state write (mov #const, statevar) is not a shared
    # temp; the source is not a stack var, so T2 delegates to T1 -> Const.
    state_write_blk = _block(
        _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_n(0x1234))
    )
    mba = _mba({7: state_write_blk})
    consulted: list[int] = []

    def fake_provider(*a, **k):
        consulted.append(1)
        return [0]

    v = resolve_state_write_value_set(
        mba=mba,
        block_serial=7,
        state_var_stkoff=_STATE_OFF,
        reaching_def_blocks_provider=fake_provider,
    )
    assert v == Const(0x1234, 4)
    assert consulted == []  # const source never reaches the value-set provider
