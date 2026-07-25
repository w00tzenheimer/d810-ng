"""SCCP conditional-reachability probe -- single-trip / bogus-loop detection.

Validates the chain a loop-peel would consume: :func:`run_sccp_ex` surfaces the
executable-edge set the SCCP solver computes internally; intersected with
:meth:`FlowGraph.back_edges` it tells us which loop back-edges SCCP *proved*
unreachable (the loop provably runs once and is peelable).

Ground truth is the REAL ``bogus_loops`` microcode from libobfuscated
(``samples/src/c/unwrap_loops.c``), whose ``for (i = 0; !i; i = 1)`` body is a
classic opaque single-trip loop.

This is a PROBE, not a happy-path assertion: plain SCCP keeps a single lattice
cell per variable, so across the two loop visits the induction var meets
``Const(0) ⊓ Const(1) = TOP`` and the exit test may stay ``TOP`` -> both edges
live.  The test therefore dumps, per maturity, exactly what SCCP proves, so we
can decide whether plain SCCP suffices or a peel/trip-count layer is required.
It asserts only that the mechanism runs end-to-end; the peel verdict is printed.
"""

from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.evaluator.hexrays_microcode.sccp import SccpResult, run_sccp_ex
from d810.optimizers.microcode.flow.context import _flowgraph_from_live_mba


def _get_default_binary() -> str:
    """Default libobfuscated binary for the running platform (env override)."""
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
    """Resolve a function address by name (handles macOS underscore prefix)."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    """Generate microcode for *func_ea* at *maturity* (or None on failure)."""
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


def test_sccp_result_dead_edge_semantics():
    """Execute the peel-relevant DEAD-edge predicate (no IDA/binary needed).

    The bogus_loops probe only exercises the LIVE path (nothing is dead), so
    this pins the DEAD path a loop-peel would actually consume: an edge is
    "dead/peelable" iff its source block is reachable but the edge itself is
    not executable -- an edge out of an *unreached* block is not a proof.
    """
    res = SccpResult(
        constants={("i",): None},
        executable_edges=frozenset({(0, 1), (1, 2)}),  # (2, 1) back-edge is absent
        reachable_blocks=frozenset({0, 1, 2}),
    )
    # Reachable source + non-executable edge => proven dead (peelable back-edge).
    assert res.is_edge_dead(2, 1) is True
    assert res.dead_edges_among([(2, 1)]) == frozenset({(2, 1)})
    # Executable edge => live, never dead.
    assert res.is_edge_dead(0, 1) is False
    assert res.is_edge_executable(0, 1) is True
    # Edge out of an unreachable source => NOT a proof (must never license a peel).
    assert res.is_edge_dead(9, 1) is False
    assert res.dead_edges_among([(9, 1)]) == frozenset()
    # Mixed input filters correctly.
    assert res.dead_edges_among([(2, 1), (0, 1), (9, 1)]) == frozenset({(2, 1)})
    # Empty result proves nothing.
    assert SccpResult.empty().dead_edges_among([(2, 1)]) == frozenset()


class TestSccpSingleTripLoop:
    """Probe SCCP's conditional reachability on the real bogus_loops loop."""

    binary_name = _get_default_binary()

    def test_bogus_loops_reachability_probe(self, libobfuscated_setup):
        func_ea = get_func_ea("bogus_loops")
        if func_ea == idaapi.BADADDR:
            pytest.skip("bogus_loops not present in test binary")

        lines: list[str] = [
            "",
            "=== SCCP single-trip-loop probe: bogus_loops ===",
            f"func_ea=0x{func_ea:x}",
        ]
        ran_any = False
        saw_any_backedge = False
        proved_any_dead_backedge = False

        for label, mat in _MATURITIES:
            mba = gen_microcode_at_maturity(func_ea, mat)
            if mba is None:
                lines.append(f"[{label}] gen_microcode -> None")
                continue

            res = run_sccp_ex(mba)
            if res is None:
                lines.append(f"[{label}] run_sccp_ex -> None (IDA/solver failure)")
                continue
            ran_any = True

            fg, _ = _flowgraph_from_live_mba(mba)
            back = fg.back_edges()
            if back:
                saw_any_backedge = True
            dead_back = res.dead_edges_among(back)
            if dead_back:
                proved_any_dead_backedge = True

            n_const = sum(1 for v in res.constants.values() if v is not None)
            n_top = sum(1 for v in res.constants.values() if v is None)
            lines.append(
                f"[{label}] qty={mba.qty} "
                f"backedges={sorted(back)} "
                f"exec_edges={len(res.executable_edges)} "
                f"reachable_blocks={len(res.reachable_blocks)} "
                f"const_keys={n_const} top_keys={n_top}"
            )
            for u, v in sorted(back):
                if (u, v) in dead_back:
                    verdict = "DEAD (peelable: SCCP proved back-edge unreachable)"
                elif res.is_edge_executable(u, v):
                    verdict = "LIVE (SCCP could not prove single-trip)"
                else:
                    verdict = "src-unreached (no proof)"
                lines.append(f"        backedge {u}->{v}: {verdict}")

        report = "\n".join(lines)
        print(report)
        print(
            f"\nVERDICT: saw_backedge={saw_any_backedge} "
            f"sccp_proved_single_trip={proved_any_dead_backedge}"
        )

        # The mechanism must run end-to-end; the peel verdict is a finding we
        # read from the dump, not a pass/fail condition for plain SCCP.
        assert ran_any, "run_sccp_ex never produced a result:\n" + report
