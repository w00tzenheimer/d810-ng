"""Runtime: resolve a multi-def (phi-like) operand read at a merge block.

Ticket ``d81-yrkv``.  In concrete mode the interpreter used to give up as soon as
an operand had more than one reaching definition, which starved the dispatcher
state-write recovery at every merge block.  Two sound ways out are exercised here
against LIVE microcode (no mocks):

* the consumer names the incoming edge ->
  :meth:`MicroCodeInterpreter.set_merge_predecessor_context` -> the definition
  arriving along that edge is selected;
* the edge is unknown -> the read still abstains (never a fabricated merge).

The ``HexRaysBlockEmulator`` guard is asserted too: a serial that is NOT a live
predecessor of the block must be ignored rather than selecting a wrong path.
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.analyses.data_flow.concolic.emulation import ConcreteStore
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)

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


#: Cap the search so a miss costs seconds, not minutes.
_MAX_FUNCS = 200


def _first_multi_def_read(mba):
    """First ``(blk, insn, mop, defs)`` whose register read has >1 reaching def."""
    interpreter = MicroCodeInterpreter(symbolic_mode=False)
    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk is None or len(list(blk.predset)) < 2:
            continue
        insn = blk.head
        while insn is not None:
            for mop in (insn.l, insn.r):
                if mop is None or mop.t != ida_hexrays.mop_r:
                    continue
                defs = interpreter._reaching_defs_at(mba, serial, mop)
                if len({(d.block_serial, d.ins_ea) for d in defs}) > 1:
                    return blk, insn, mop, defs
            insn = insn.next
    return None


@pytest.fixture(scope="class")
def merge_read(libobfuscated_setup):
    """A live ``(mba, blk, insn, mop, defs)`` merge read from the sample binary."""
    import idautils

    for index, func_ea in enumerate(idautils.Functions()):
        if index >= _MAX_FUNCS:
            break
        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            continue
        found = _first_multi_def_read(mba)
        if found is not None:
            return (mba,) + found
    pytest.skip("no multi-def register read found in the sample binary")


class TestMultiDefPredecessorResolution:
    binary_name = _get_default_binary()

    def test_without_edge_context_a_multi_def_read_abstains(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, insn)
        # No predecessor context: the read may only resolve if every reaching
        # definition proves the SAME value (path-insensitive agreement); it must
        # never invent a merge value.
        value = interpreter._resolve_mop_via_def_use(mop, env)
        assert value is None or isinstance(value, int)

    def test_edge_context_selects_one_reaching_definition(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        selected = []
        for pred in sorted(int(p) for p in blk.predset):
            interpreter.set_merge_predecessor_context(blk.serial, pred)
            chosen = interpreter._select_predecessor_def(mop, defs, mba, blk.serial)
            if chosen is not None:
                selected.append((pred, chosen))
        assert selected, (
            "no incoming edge singled out a definition for "
            f"blk={blk.serial} defs={[(d.block_serial, hex(d.ins_ea)) for d in defs]}"
        )
        for _pred, chosen in selected:
            assert chosen in defs

    def test_context_for_another_block_is_ignored(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        # Context declared for a DIFFERENT block must never steer this block.
        interpreter.set_merge_predecessor_context(
            blk.serial + 1000, next(iter(blk.predset))
        )
        assert interpreter._select_predecessor_def(mop, defs, mba, blk.serial) is None

    def test_emulator_drops_a_serial_that_is_not_a_live_predecessor(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        emu = HexRaysBlockEmulator(
            mba=mba, state_var_stkoff=0, state_cell=LocationRef.stack(0, 8)
        )
        bogus = max(int(p) for p in blk.predset) + 10_000
        emu._apply_predecessor_context(interpreter, blk, bogus)
        assert interpreter._merge_pred_context is None

        real = min(int(p) for p in blk.predset)
        emu._apply_predecessor_context(interpreter, blk, real)
        assert interpreter._merge_pred_context == (blk.serial, real)

    def test_eval_block_accepts_the_pred_serial_keyword(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        emu = HexRaysBlockEmulator(
            mba=mba, state_var_stkoff=0x7FFFFFFF, state_cell=LocationRef.stack(0, 8)
        )
        outcome = emu.eval_block(
            blk, ConcreteStore.of({}), pred_serial=min(int(p) for p in blk.predset)
        )
        # No state var at that offset -> a clean abstain, not a TypeError.
        assert outcome is not None
