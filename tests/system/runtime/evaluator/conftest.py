"""Shared live-microcode fixtures for the evaluator runtime tests.

``merge_read`` finds a real merge block whose register read has more than one
reaching definition -- the shape both the multi-def resolution tests
(``d81-yrkv`` / ``d81-182q``) and the abstain-cause tests (``d81-qt4v``) need.
"""

from __future__ import annotations

import ida_hexrays
import pytest

from d810.evaluator.hexrays_microcode.emulator import MicroCodeInterpreter

from tests.system.runtime.conftest import gen_microcode_at_maturity


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

