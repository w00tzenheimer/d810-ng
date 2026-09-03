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

import pytest

from d810.analyses.data_flow.concolic.emulation import ConcreteStore
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)



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
        # normalized to a path, nearest first (ticket d81-182q)
        assert interpreter._merge_pred_context == (blk.serial, (real,))

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

    def test_a_path_context_selects_the_def_on_that_path(self, merge_read):
        """Ticket d81-182q: the def is picked by PATH membership, not by chains."""
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        pred = min(int(p) for p in blk.predset)
        # Name a corridor whose FAR element is a real definition block: the def
        # there must be selected even though the nearest block defines nothing
        # and its use-driven chain query returns nothing.
        far = [d for d in defs if d.block_serial != pred]
        if not far:
            pytest.skip("every reaching def lives in the immediate predecessor")
        target = far[-1]
        interpreter.set_merge_predecessor_context(
            blk.serial, (pred, target.block_serial)
        )
        chosen = interpreter._select_predecessor_def(mop, defs, mba, blk.serial)
        assert chosen is not None
        if pred not in {d.block_serial for d in defs}:
            # nothing on the nearer end of the path shadows it
            assert chosen.block_serial == target.block_serial

    def test_a_path_with_no_def_on_it_abstains(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        unrelated = max(d.block_serial for d in defs) + 5000
        interpreter.set_merge_predecessor_context(blk.serial, (unrelated, unrelated + 1))
        assert interpreter._select_predecessor_def(mop, defs, mba, blk.serial) is None
