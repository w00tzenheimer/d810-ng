"""Runtime: a state write derived from a synthetic call return is not EXACT.

Ticket ``d81-1t9x``.  ``HexRaysBlockEmulator.eval_block`` publishes an
``ExactResult`` -- a PROVEN dispatcher next-state -- from what the microcode
interpreter resolved for the block's state-var write.  An unmodeled call hands
out a concrete synthetic integer so the enclosing ``mov call(...), state``
evaluates; that integer must never leave the emulator as a proven state.

The block here is a stand-in (``head``/``nextb``), but every INSTRUCTION and the
state ``mop_S`` are real Hex-Rays objects built against a live ``mba``, so the
interpreter walks the same code path it walks in production.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field

import ida_hexrays
import pytest

from d810.analyses.data_flow.concolic import Abstain, ConcreteStore, ExactResult
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator
from d810.core.observability_state_write import CAUSE_SYNTHETIC_TAINT

from tests.system.runtime.conftest import gen_microcode_at_maturity


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    system = platform.system()
    if system == "Windows":
        return "libobfuscated.dll"
    if system == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.so"


_MAX_FUNCS = 200
_UNSUPPORTED_CALLEE = (ida_hexrays.mop_v, ida_hexrays.mop_b)
_STATE_STKOFF = 0x3C
_STATE_SIZE = 4


@dataclass
class _StubBlock:
    """A block stand-in carrying REAL instructions (see module docstring)."""

    head: object | None = None
    nextb: object | None = None
    serial: int = 0
    mba: object | None = None
    predset: list = field(default_factory=list)


def _find_call(mba):
    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insn = blk.head
        while insn is not None:
            if (
                insn.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall)
                and insn.l is not None
                and insn.l.t in _UNSUPPORTED_CALLEE
                and insn.d is not None
            ):
                return insn
            insn = insn.next
    return None


@pytest.fixture(scope="class")
def live_call_insn(libobfuscated_setup):
    """``(mba, call_insn)`` with a callee operand the emulator does not model."""
    import idautils

    for index, func_ea in enumerate(idautils.Functions()):
        if index >= _MAX_FUNCS:
            break
        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            continue
        found = _find_call(mba)
        if found is not None:
            return mba, found
    pytest.skip("no unmodeled-callee call found in the sample binary")


def _state_mop(mba):
    mop = ida_hexrays.mop_t()
    mop.erase()
    mop._make_stkvar(mba, _STATE_STKOFF)
    mop.size = _STATE_SIZE
    return mop


def _emulator(mba) -> HexRaysBlockEmulator:
    return HexRaysBlockEmulator(
        mba=mba,
        state_var_stkoff=_STATE_STKOFF,
        state_cell=LocationRef.stack(_STATE_STKOFF, _STATE_SIZE),
    )


def _block_with(insn) -> _StubBlock:
    return _StubBlock(head=insn, nextb=_StubBlock(head=None, serial=1))


class TestTaintedStateTransitionIsNotPublished:
    binary_name = _get_default_binary()

    def test_a_call_derived_state_write_abstains(self, live_call_insn):
        mba, call_insn = live_call_insn
        write = ida_hexrays.minsn_t(call_insn.ea)
        write.opcode = ida_hexrays.m_mov
        write.l = ida_hexrays.mop_t()
        write.l._make_insn(ida_hexrays.minsn_t(call_insn))
        write.l.size = _STATE_SIZE
        write.r = ida_hexrays.mop_t()
        write.d = _state_mop(mba)

        outcome = _emulator(mba).eval_block(_block_with(write), ConcreteStore.of({}))
        assert isinstance(outcome, Abstain), (
            "a next-state invented by the emulator must never be published as "
            f"exact: {outcome}"
        )
        assert getattr(outcome, "cause", None) == CAUSE_SYNTHETIC_TAINT

    def test_a_proven_state_write_is_still_published(self, live_call_insn):
        """No regression: a concrete write still yields an ExactResult."""
        mba, call_insn = live_call_insn
        write = ida_hexrays.minsn_t(call_insn.ea)
        write.opcode = ida_hexrays.m_mov
        write.l = ida_hexrays.mop_t()
        write.l.make_number(0x2A, _STATE_SIZE)
        write.r = ida_hexrays.mop_t()
        write.d = _state_mop(mba)

        outcome = _emulator(mba).eval_block(_block_with(write), ConcreteStore.of({}))
        assert isinstance(outcome, ExactResult), outcome
        assert outcome.value_for(LocationRef.stack(_STATE_STKOFF, _STATE_SIZE)) == 0x2A
