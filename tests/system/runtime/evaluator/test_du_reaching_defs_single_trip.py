"""Def-use reaching-def probe for single-trip / bogus-loop detection.

Third probe in the series (after ``test_sccp_reachability.py`` and
``test_valrange_single_trip.py``).  SCCP and valrange both FAILED because they
keep one merged abstract state per block, so at the loop header the entry value
(``i=0``) and the back-edge value (``i=1``) meet to ``[0,1]``/``TOP`` and the
single-trip fact is erased.

Def-use chains do NOT merge.  ``find_reaching_defs_for_reg`` returns *every*
definition of the guard var that reaches the header as a separate ``DefSite`` --
so the entry def (``i=0``) and the sole in-loop recurrence def (``i=1``) appear
distinctly.  A loop is provably single-trip when the guard var has exactly one
in-loop definition, that def is a loop-invariant constant, and that constant
makes the header exit test flip to "exit".

Ground truth is the REAL ``bogus_loops`` microcode (``for (i=0; !i; i=1)``).
This probe dumps the reaching defs (with each defining instruction's ``dstr()``)
so we can confirm the DU chain preserves what the fixpoints discarded.  It
asserts only that the mechanism runs; the peel verdict is printed to read.
"""

from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.evaluator.hexrays_microcode.chains import (
    find_reaching_defs_for_reg,
    find_reaching_defs_for_stkvar,
)
from d810.optimizers.microcode.flow.context import _flowgraph_from_live_mba


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


def get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    func = idaapi.get_func(func_ea)
    if func is None:
        return None
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    return ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )


_MATURITIES = [
    ("LOCOPT", ida_hexrays.MMAT_LOCOPT),
    ("CALLS", ida_hexrays.MMAT_CALLS),
    ("GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
    ("GLBOPT2", ida_hexrays.MMAT_GLBOPT2),
    ("GLBOPT3", ida_hexrays.MMAT_GLBOPT3),
]


def _natural_loop_nodes(mba, latch: int, header: int) -> set[int]:
    """Classic natural loop of back-edge latch->header: header plus every node
    that reaches the latch without passing through the header."""
    loop = {header, latch}
    stack = [latch]
    while stack:
        n = stack.pop()
        blk = mba.get_mblock(n)
        for p in list(blk.predset):
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


def _find_insn(blk, ea: int, opcode: int):
    """Locate the defining minsn in *blk* by (ea, opcode), then by ea alone."""
    ins = blk.head
    while ins is not None:
        if ins.ea == ea and ins.opcode == opcode:
            return ins
        ins = ins.next
    ins = blk.head
    while ins is not None:
        if ins.ea == ea:
            return ins
        ins = ins.next
    return None


def _def_const(ins) -> int | None:
    """Constant value assigned by *ins*, if it is a straight const assignment."""
    if ins is None:
        return None
    if ins.l is not None and ins.l.t == ida_hexrays.mop_n:
        try:
            return ins.l.nnn.value
        except Exception:
            return None
    return None


def _guard_locator(tail):
    """Return ('reg', mreg, size) | ('stk', stkoff, size) | None for the
    header exit-test guard operand (tail.l)."""
    if tail is None or tail.l is None:
        return None
    l = tail.l
    if l.t == ida_hexrays.mop_r:
        return ("reg", l.r, l.size)
    if l.t == ida_hexrays.mop_S and l.s is not None:
        return ("stk", l.s.off, l.size)
    return None


class TestDuReachingDefsSingleTrip:
    """Probe: does the DU chain preserve the per-iteration defs (i=0 vs i=1)?"""

    binary_name = _get_default_binary()

    def test_bogus_loops_du_reaching_defs(self, libobfuscated_setup):
        func_ea = get_func_ea("bogus_loops")
        if func_ea == idaapi.BADADDR:
            pytest.skip("bogus_loops not present in test binary")

        lines: list[str] = [
            "",
            "=== DU reaching-def probe: bogus_loops ===",
            f"func_ea=0x{func_ea:x}",
        ]
        ran_any = False
        du_proves_single_trip = False

        for label, mat in _MATURITIES:
            mba = gen_microcode_at_maturity(func_ea, mat)
            if mba is None:
                lines.append(f"[{label}] gen_microcode -> None")
                continue

            fg, _ = _flowgraph_from_live_mba(mba)
            back = sorted(fg.back_edges())
            lines.append(f"[{label}] qty={mba.qty} backedges={back}")

            for latch, header in back:
                hblk = mba.get_mblock(header)
                loc = _guard_locator(hblk.tail)
                if loc is None:
                    lines.append(
                        f"    backedge {latch}->{header}: guard not keyable "
                        f"(tail_op={hblk.tail.opcode if hblk.tail else None})"
                    )
                    continue

                loop_nodes = _natural_loop_nodes(mba, latch, header)

                kind, ident, size = loc
                if kind == "reg":
                    defs = find_reaching_defs_for_reg(mba, header, ident, size)
                    gdesc = f"reg mr{ident:#x}.{size}"
                else:
                    defs = find_reaching_defs_for_stkvar(mba, header, ident, size)
                    gdesc = f"stk {ident:#x}.{size}"
                ran_any = True

                lines.append(
                    f"    backedge {latch}->{header}: guard={gdesc} "
                    f"loop_nodes={sorted(loop_nodes)} reaching_defs={len(defs)}"
                )

                entry_consts: list[int] = []
                inloop_consts: list[int] = []
                inloop_def_count = 0
                for d in defs:
                    dblk = mba.get_mblock(d.block_serial)
                    dins = _find_insn(dblk, d.ins_ea, d.ins_opcode)
                    cval = _def_const(dins)
                    in_loop = d.block_serial in loop_nodes
                    dstr = dins.dstr() if dins is not None else "<insn not found>"
                    lines.append(
                        f"        def @blk{d.block_serial} "
                        f"{'IN-LOOP ' if in_loop else 'ENTRY   '}"
                        f"ea=0x{d.ins_ea:x} op={d.ins_opcode} "
                        f"const={cval} :: {dstr}"
                    )
                    if in_loop:
                        inloop_def_count += 1
                        if cval is not None:
                            inloop_consts.append(cval)
                    else:
                        if cval is not None:
                            entry_consts.append(cval)

                # Provable single-trip candidate: exactly ONE in-loop def, and it
                # is a loop-invariant constant, and there is a constant entry def.
                peelable = (
                    inloop_def_count == 1
                    and len(inloop_consts) == 1
                    and len(entry_consts) >= 1
                )
                lines.append(
                    f"        => entry_consts={entry_consts} "
                    f"inloop_consts={inloop_consts} "
                    f"inloop_def_count={inloop_def_count} "
                    f"PEELABLE={peelable}"
                )
                if peelable:
                    du_proves_single_trip = True

        report = "\n".join(lines)
        print(report)
        print(f"\nVERDICT: ran={ran_any} du_proves_single_trip={du_proves_single_trip}")

        assert ran_any, (
            "find_reaching_defs never produced a result (DU chains unavailable "
            "at all maturities?):\n" + report
        )
