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
    apply_region_deshare_and_render,
    lower_conditional_synthesize,
    recover_branchless,
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


class TestConditionalSynthesizeLowersToOracle:
    """The ConditionalSynthesize primitive: a branchless next-state select (no
    jcc) recovered + lowered to a real if/else, composed with DispatchDrain for
    the rest of the dispatcher. Oracle = lab_ref_cond (same semantics)."""

    binary_name = "restructuring_lab.dll"

    def test_branchless_lowers_to_cond_oracle(self, ida_database, configure_hexrays):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        flat_ea = get_func_ea("lab_flat_branchless")
        ref_ea = get_func_ea("lab_ref_cond")
        assert flat_ea != idaapi.BADADDR and ref_ea != idaapi.BADADDR

        lowered, applied, error = apply_lowering_and_render(
            flat_ea, recover_branchless, lower_conditional_synthesize)
        oracle = render_reference(ref_ea)
        sig_lowered = semantic_signature(lowered)
        sig_oracle = semantic_signature(oracle)
        print(f"\n=== lab_flat_branchless: applied={applied} error={error} ===")
        print(f"--- lowered ---\n{lowered}")
        print(f"--- oracle (lab_ref_cond) ---\n{oracle}")
        print(f"--- signature lowered ---\n{sig_lowered}")
        print(f"--- signature oracle  ---\n{sig_oracle}")
        assert error is None, f"lowering error: {error}"
        assert applied >= 1, f"primitive emitted nothing (applied={applied})"
        assert sig_lowered == sig_oracle, (
            f"branchless did NOT lower to the lab_ref_cond oracle (semantic "
            f"signature mismatch):\nlowered:  {sig_lowered}\noracle:   {sig_oracle}\n"
            f"--- lowered render ---\n{lowered}\n--- oracle render ---\n{oracle}")


class TestRegionDeshareLowersToOracle:
    """The RegionDeshare primitive (2-pass): duplicate a 2-block region (head +
    internal branch + tail) per path. Oracle = lab_ref_region_deshare (the region
    duplicated into each arm)."""

    binary_name = "restructuring_lab.dll"

    def test_region_deshare_lowers_to_oracle(self, ida_database, configure_hexrays):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        flat_ea = get_func_ea("lab_flat_region")
        ref_ea = get_func_ea("lab_ref_region_deshare")
        assert flat_ea != idaapi.BADADDR and ref_ea != idaapi.BADADDR

        lowered, a0, a1, error = apply_region_deshare_and_render(flat_ea)
        oracle = render_reference(ref_ea)
        sig_lowered = semantic_signature(lowered)
        sig_oracle = semantic_signature(oracle)
        print(f"\n=== lab_flat_region deshare: a0={a0} a1={a1} error={error} ===")
        print(f"--- lowered ---\n{lowered}")
        print(f"--- oracle (lab_ref_region_deshare) ---\n{oracle}")
        print(f"--- signature lowered ---\n{sig_lowered}")
        print(f"--- signature oracle  ---\n{sig_oracle}")
        assert error is None, f"lowering error: {error}"
        assert a0 >= 1 and a1 >= 1, f"deshare passes did not both fire (a0={a0} a1={a1})"
        assert sig_lowered == sig_oracle, (
            f"region de-share did NOT lower to the lab_ref_region_deshare oracle "
            f"(semantic signature mismatch):\nlowered:  {sig_lowered}\n"
            f"oracle:   {sig_oracle}\n--- lowered ---\n{lowered}\n"
            f"--- oracle ---\n{oracle}")
