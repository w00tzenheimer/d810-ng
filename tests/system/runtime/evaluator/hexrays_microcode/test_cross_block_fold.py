"""Wiring tests for cross-block operand resolution in the next-state fold.

The MBA next-state fold (``fold_block_state_write``) does local forward
constant-propagation over a handler block.  When an operand is defined in a
*predecessor* block it is unresolved locally and the fold degrades to ⊤.  These
tests prove the optional ``cross_block_resolver`` seam is threaded through
``_eval_mop`` / ``_eval_insn`` and consumed by the fold — driven by a stub
resolver so the assertions are deterministic and do not depend on a real SCCP /
DU graph (those whole-function sources are exercised by the e2e pipeline).

IDA-dependent: the fold reads real ``ida_hexrays`` mop/opcode constants, so the
fixtures are ``SimpleNamespace`` shims shaped like ``mop_t`` / ``minsn_t``.
"""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.analyses.data_flow.abstract_value import TOP, Const
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    fold_block_state_write,
)

_STATE_OFF = 0x64  # state var stack offset
_W = 8  # operand size (bytes)
_MASK = 0xFFFFFFFF


# --------------------------------------------------------------------------- shims
def _mop_S(off: int, size: int = _W):
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        s=SimpleNamespace(off=off),
        size=size,
        nnn=None,
        dstr=lambda: f"S{off:#x}",
    )


def _mop_n(value: int, size: int = _W):
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        nnn=SimpleNamespace(value=value),
        size=size,
        dstr=lambda: hex(value),
    )


def _mop_d(sub, size: int = _W):
    return SimpleNamespace(t=ida_hexrays.mop_d, d=sub, size=size, dstr=lambda: "d")


def _insn(opcode, *, d=None, l=None, r=None):
    return SimpleNamespace(opcode=opcode, d=d, l=l, r=r, ea=0, next=None)


def _mba_with_block(insn):
    blk = SimpleNamespace(head=insn)
    return SimpleNamespace(get_mblock=lambda serial: blk if int(serial) == 0 else None)


def _offset_resolver(values: dict[int, int]):
    """Resolve a ``mop_S`` operand to a constant keyed by its stack offset."""

    def resolve(mop, use_block=None):
        off = getattr(getattr(mop, "s", None), "off", None)
        if off is None:
            return None
        return values.get(int(off))

    return resolve


# --------------------------------------------------------------------------- tests
def test_local_only_fold_leaves_cross_block_operand_top():
    # state = S[0x100]  (S[0x100] is defined in a predecessor, not here)
    insn = _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(0x100))
    mba = _mba_with_block(insn)
    # No resolver -> operand is ⊤ -> not provably constant (S3: AbstractValue Top).
    assert (
        fold_block_state_write(
            mba=mba, block_serial=0, state_var_stkoff=_STATE_OFF
        )
        is TOP
    )


def test_fold_consumes_cross_block_resolver_for_simple_mov():
    insn = _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(0x100))
    mba = _mba_with_block(insn)
    resolver = _offset_resolver({0x100: 0x2A5E29F6})
    folded = fold_block_state_write(
        mba=mba,
        block_serial=0,
        state_var_stkoff=_STATE_OFF,
        cross_block_resolver=resolver,
    )
    assert folded == Const(0x2A5E29F6, 4)


def test_fold_consumes_cross_block_operands_in_mba():
    # state = (S[0x110] ^ S[0x118]) - S[0x120]  -- all three cross-block.
    a, b, c = 0x77535232, 0x71D1654B, 0xDC240D83
    xor = _insn(ida_hexrays.m_xor, l=_mop_S(0x110), r=_mop_S(0x118))
    sub = _insn(ida_hexrays.m_sub, l=_mop_d(xor), r=_mop_S(0x120))
    state_write = _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_d(sub))
    mba = _mba_with_block(state_write)
    resolver = _offset_resolver({0x110: a, 0x118: b, 0x120: c})
    folded = fold_block_state_write(
        mba=mba,
        block_serial=0,
        state_var_stkoff=_STATE_OFF,
        cross_block_resolver=resolver,
    )
    assert folded == Const(((a ^ b) - c) & _MASK, 4)


def test_resolver_returning_none_never_invents_a_state():
    # Safety: an ambiguous cross-block operand must degrade to ⊤, not a value.
    insn = _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_S(0x100))
    mba = _mba_with_block(insn)
    resolver = _offset_resolver({})  # resolves nothing
    assert (
        fold_block_state_write(
            mba=mba,
            block_serial=0,
            state_var_stkoff=_STATE_OFF,
            cross_block_resolver=resolver,
        )
        is TOP
    )


def test_local_constant_still_wins_over_resolver():
    # A locally-assigned constant must be used directly (resolver not consulted
    # for an operand that is already a local constant).
    seen: list[int] = []

    def resolver(mop, use_block=None):
        seen.append(getattr(getattr(mop, "s", None), "off", -1))
        return 0xDEADBEEF

    # state = 0x1234  (a bare local constant write)
    insn = _insn(ida_hexrays.m_mov, d=_mop_S(_STATE_OFF), l=_mop_n(0x1234))
    mba = _mba_with_block(insn)
    folded = fold_block_state_write(
        mba=mba,
        block_serial=0,
        state_var_stkoff=_STATE_OFF,
        cross_block_resolver=resolver,
    )
    assert folded == Const(0x1234, 4)
    assert seen == []  # resolver never consulted for a local constant
