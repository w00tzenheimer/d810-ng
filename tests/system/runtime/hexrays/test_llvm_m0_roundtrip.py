"""LLVM M0 hand lower-back proof against the restructuring-lab oracle."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from tests.system.runtime.conftest import get_func_ea
from tests.system.runtime.hexrays.lowering_catalog import (
    apply_lowering_and_render,
    lower_conditional_synthesize,
    recover_branchless,
    render_reference,
    semantic_signature,
)


_REPO_ROOT = Path(__file__).resolve().parents[4]
_LOWER_BACK = _REPO_ROOT / "tools/llvm_m0_roundtrip/lab_flat_branchless.lower_back.json"


def _load_lower_back() -> dict:
    return json.loads(_LOWER_BACK.read_text(encoding="utf-8"))


class TestLLVMM0RoundTrip:
    """Prove the hand-lowered M0 interpretation reaches the compiled-source oracle."""

    binary_name = "restructuring_lab.dll"

    def test_hand_lowered_branchless_llvm_matches_cond_oracle(
        self, ida_database, configure_hexrays
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        artifact = _load_lower_back()
        assert artifact["schema"] == "d810.llvm_m0.lower_back.v1"
        assert artifact["source_fixture"] == "fixtures/lab_flat_branchless.after.ll"
        assert artifact["d810_lower_back"]["primitive"] == "ConditionalSynthesize"
        assert artifact["d810_lower_back"]["recover"] == "recover_branchless"
        assert artifact["d810_lower_back"]["lower"] == "lower_conditional_synthesize"

        flat_ea = get_func_ea(artifact["d810_lower_back"]["flat_function"])
        ref_ea = get_func_ea(artifact["d810_lower_back"]["oracle_function"])
        assert flat_ea != idaapi.BADADDR and ref_ea != idaapi.BADADDR

        lowered, applied, error = apply_lowering_and_render(
            flat_ea, recover_branchless, lower_conditional_synthesize
        )
        oracle = render_reference(ref_ea)
        sig_lowered = semantic_signature(lowered)
        sig_oracle = semantic_signature(oracle)

        print(f"\n=== LLVM M0 hand lower-back: applied={applied} error={error} ===")
        print(f"--- lowered ---\n{lowered}")
        print(f"--- oracle ({artifact['d810_lower_back']['oracle_function']}) ---\n{oracle}")
        print(f"--- signature lowered ---\n{sig_lowered}")
        print(f"--- signature oracle  ---\n{sig_oracle}")

        assert error is None, f"lowering error: {error}"
        assert applied >= 1, f"primitive emitted nothing (applied={applied})"
        assert sig_lowered == sig_oracle, (
            "LLVM M0 hand-lowered interpretation did not match the compiled-source "
            f"oracle:\nlowered:  {sig_lowered}\noracle:   {sig_oracle}\n"
            f"--- lowered render ---\n{lowered}\n--- oracle render ---\n{oracle}"
        )
