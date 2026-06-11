"""Prove the lowering-primitive catalog against the compiled-source oracle.

Each case lowers a flattened ``lab_flat_*`` via a catalog primitive and asserts
the render equals the EXPECTED pseudocode -- the non-flattened ``lab_ref_*``
sibling decompiled at baseline (oracle-equivalence). The thesis: ONE primitive
(``DispatchDrain``) lowers many shapes; only the analysis front-end differs.
"""
from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from tests.system.runtime.conftest import get_func_ea
from tests.system.runtime.hexrays.lowering_catalog import (
    apply_lowering_and_render,
    recover_dispatch_jtbl,
    recover_dispatch_jzchain,
    render_reference,
    semantic_signature,
)


class TestDispatchDrainLowersToOracle:
    """The DispatchDrain lowering primitive, two analysis front-ends (jz-chain +
    jump table), each proven against its compiled-source oracle sibling."""

    binary_name = "restructuring_lab.dll"

    @pytest.mark.parametrize(
        "flat_fn, ref_fn, recover",
        [
            # ONE primitive (DispatchDrain), ONE jz-chain front-end covers linear,
            # loop (back-edge), conditional (preserved handler branch), and the
            # multi-block region (shared join) -- the shape is in the recovered
            # routing graph, not in the lowering.
            ("lab_flat_mini", "lab_ref_mini", recover_dispatch_jzchain),
            ("lab_flat_loop", "lab_ref_loop", recover_dispatch_jzchain),
            ("lab_flat_cond", "lab_ref_cond", recover_dispatch_jzchain),
            ("lab_flat_region", "lab_ref_region", recover_dispatch_jzchain),
            # ... and a SEPARATE jump-table front-end feeds the SAME primitive.
            ("lab_flat_jtbl", "lab_ref_jtbl", recover_dispatch_jtbl),
        ],
    )
    def test_dispatch_drain_matches_oracle(
        self, ida_database, configure_hexrays, flat_fn, ref_fn, recover
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        flat_ea = get_func_ea(flat_fn)
        ref_ea = get_func_ea(ref_fn)
        assert flat_ea != idaapi.BADADDR and ref_ea != idaapi.BADADDR

        lowered, applied, error = apply_lowering_and_render(flat_ea, recover)
        oracle = render_reference(ref_ea)
        sig_lowered = semantic_signature(lowered)
        sig_oracle = semantic_signature(oracle)
        print(f"\n=== {flat_fn}: applied={applied} error={error} ===")
        print(f"--- lowered ---\n{lowered}")
        print(f"--- oracle ({ref_fn}) ---\n{oracle}")
        print(f"--- signature lowered ---\n{sig_lowered}")
        print(f"--- signature oracle  ---\n{sig_oracle}")
        assert error is None, f"lowering error: {error}"
        assert applied >= 1, f"primitive emitted nothing (applied={applied})"
        assert sig_lowered == sig_oracle, (
            f"{flat_fn} did NOT lower to the {ref_fn} oracle (semantic signature "
            f"mismatch):\nlowered:  {sig_lowered}\noracle:   {sig_oracle}\n"
            f"--- lowered render ---\n{lowered}\n--- oracle render ---\n{oracle}")
