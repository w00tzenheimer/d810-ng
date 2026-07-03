"""Value-range (valrange_dataflow) single-trip / bogus-loop REPROBE.

Companion to ``test_sccp_reachability.py``.  SCCP could not prove the
``bogus_loops`` back-edge dead (one lattice cell -> induction var meets to TOP).
This probes whether the flow-sensitive, edge-refining value-range fixpoint does
better.

``run_valrange_fixpoint`` reconstructs ``valranges_t::known`` and *deliberately*
falls back to the raw branch constraint when an intersection is empty
(``_refine_for_branch_edge`` ~L386-390) "so the fixpoint always converges" -- so
it never itself signals an infeasible edge.  We therefore do the feasibility
test ourselves: take the guard var's range ``R`` in the header's IN state and
compute ``R ∩ edge_constraint`` (solid ``valrng_t.intersect_with``/``empty``) for
each header successor.  A loop is provably single-trip iff the loop-continue
edge is empty (infeasible) while the exit edge is feasible.

Ground truth is the REAL ``bogus_loops`` microcode (``for (i=0; !i; i=1)``).
Like the SCCP probe this asserts only that the mechanism runs; the peel verdict
is printed for us to read.
"""
from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    _clone_valrng,
    _extract_key_from_mop,
    _jcc_to_cmpop,
    _vr_to_str,
    format_valrange_env,
    format_valrange_key,
    run_valrange_fixpoint,
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


def _edge_constraint(header_blk, successor_serial: int):
    """Constraint valrng_t for the header->successor edge, or (key, None).

    Mirrors ``_refine_for_branch_edge`` but returns the raw constraint so the
    caller can test genuine intersection emptiness (no convergence fallback).
    """
    if header_blk.type != ida_hexrays.BLT_2WAY:
        return None, None
    tail = header_blk.tail
    if tail is None:
        return None, None
    cmpop = _jcc_to_cmpop(tail.opcode)
    if cmpop is None:
        return None, None  # e.g. m_jcnd (nested condition) -- not keyable here
    left, right = tail.l, tail.r
    if right is None or right.t != ida_hexrays.mop_n:
        return None, None
    key = _extract_key_from_mop(left)
    if key is None:
        return None, None
    constraint = ida_hexrays.valrng_t(left.size)
    constraint.set_cmp(cmpop, right.nnn.value)
    succ_list = list(header_blk.succset)
    is_fallthrough = len(succ_list) >= 1 and succ_list[0] == successor_serial
    is_taken = len(succ_list) >= 2 and succ_list[1] == successor_serial
    if is_fallthrough and not is_taken:
        constraint.inverse()
    elif not is_taken:
        return key, None
    return key, constraint


def _edge_feasible(guard_range, constraint) -> bool:
    """True iff guard_range ∩ constraint is non-empty (edge is feasible)."""
    if guard_range is None or constraint is None:
        return True  # unknown -> assume feasible (conservative)
    t = _clone_valrng(guard_range)
    t.intersect_with(constraint)
    return not t.empty()


class TestValrangeSingleTripLoop:
    """Reprobe: can the value-range fixpoint prove bogus_loops single-trip?"""

    binary_name = _get_default_binary()

    def test_bogus_loops_valrange_probe(self, libobfuscated_setup):
        func_ea = get_func_ea("bogus_loops")
        if func_ea == idaapi.BADADDR:
            pytest.skip("bogus_loops not present in test binary")

        lines: list[str] = [
            "",
            "=== valrange single-trip reprobe: bogus_loops ===",
            f"func_ea=0x{func_ea:x}",
        ]
        ran_any = False
        valrange_proved_single_trip = False

        for label, mat in _MATURITIES:
            mba = gen_microcode_at_maturity(func_ea, mat)
            if mba is None:
                lines.append(f"[{label}] gen_microcode -> None")
                continue
            try:
                res = run_valrange_fixpoint(mba)
            except Exception as exc:  # pragma: no cover - probe robustness
                lines.append(f"[{label}] run_valrange_fixpoint raised: {exc}")
                continue
            ran_any = True

            fg, _ = _flowgraph_from_live_mba(mba)
            back = sorted(fg.back_edges())
            lines.append(
                f"[{label}] qty={mba.qty} converged={res.converged} backedges={back}"
            )

            for (latch, header) in back:
                hblk = mba.get_mblock(header)
                tail = hblk.tail
                guard_key = None
                if tail is not None and tail.l is not None:
                    try:
                        guard_key = _extract_key_from_mop(tail.l)
                    except Exception:
                        guard_key = None

                henv = res.in_states.get(header, {})
                gk_str = (
                    format_valrange_key(guard_key)
                    if guard_key is not None
                    else "<no-key>"
                )
                grange = henv.get(guard_key) if guard_key is not None else None
                grange_str = _vr_to_str(grange) if grange is not None else "<absent>"
                tail_op = tail.opcode if tail is not None else None
                lines.append(
                    f"    backedge {latch}->{header}: header tail_op={tail_op} "
                    f"guard_key={gk_str} guard_range@header_IN={grange_str}"
                )

                feasible_succs = []
                for succ in list(hblk.succset):
                    _, constraint = _edge_constraint(hblk, succ)
                    feasible = _edge_feasible(grange, constraint)
                    cstr = _vr_to_str(constraint) if constraint is not None else "<none>"
                    lines.append(
                        f"        edge {header}->{succ}: constraint={cstr} "
                        f"feasible={feasible}"
                    )
                    if feasible:
                        feasible_succs.append(succ)

                # Provable single-trip: exactly one header successor feasible
                # AND the infeasible one is the loop-continue (a successor that
                # is the back-edge's latch or reaches it).  Conservative proxy:
                # exactly one feasible successor at a genuine 2-way guard.
                if (
                    grange is not None
                    and hblk.type == ida_hexrays.BLT_2WAY
                    and len(list(hblk.succset)) == 2
                    and len(feasible_succs) == 1
                ):
                    valrange_proved_single_trip = True
                    lines.append(
                        f"        => header {header} has ONE feasible successor "
                        f"{feasible_succs[0]} (guard pins a branch)"
                    )

            if back:
                _, h0 = back[0]
                lines.append(
                    f"    header={h0} FULL IN env: "
                    f"{format_valrange_env(res.in_states.get(h0, {}))}"
                )

        report = "\n".join(lines)
        print(report)
        print(
            f"\nVERDICT: ran={ran_any} "
            f"valrange_proved_single_trip={valrange_proved_single_trip}"
        )

        assert ran_any, "run_valrange_fixpoint never produced a result:\n" + report
