"""LLVM M3c lower-back readiness probe over M2 optimized IR."""
from __future__ import annotations

import os

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from d810.backends.hexrays.lifter import lift_function
from d810.backends.llvm import (
    LlvmLowerBackReadinessStatus,
    LlvmLowerBackUnsupportedKind,
    LlvmM2PipelineStatus,
    assess_lower_back_readiness,
    emit_flowgraph_to_llvm,
    run_llvm_m2_pipeline,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


class TestLLVMM3LowerBackReadiness:
    """Classify M3 lower-back readiness for real M2 optimized LLVM text."""

    binary_name = "restructuring_lab.dll"

    def test_lab_if_diamond_optimized_ir_has_lower_back_readiness_classification(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_name = "lab_if_diamond"
        func_ea = get_func_ea(func_name)
        assert func_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
        assert mba is not None

        flow_graph = lift_function(mba).flow_graph
        lift = emit_flowgraph_to_llvm(flow_graph, function_name=f"{func_name}_m3c")
        assert lift.supported, [reason.reason for reason in lift.unsupported]

        m2 = run_llvm_m2_pipeline(
            lift.ir_text,
            tmp_dir=tmp_path / "m2",
            require_opt=os.environ.get("D810_REQUIRE_LLVM_OPT") == "1",
        )
        assert m2.status is LlvmM2PipelineStatus.PASSED, m2.reason

        readiness = assess_lower_back_readiness(m2.after_ir)
        parse_diags = tuple(
            f"{diag.kind.value}:{diag.reason}"
            for diag in readiness.parse_result.diagnostics
        )
        plan_diags = (
            tuple(
                f"{diag.kind.value}:{diag.block_label}:{diag.reason}"
                for diag in readiness.plan_result.unsupported
            )
            if readiness.plan_result is not None
            else ()
        )
        print("\n=== LLVM M3c lower-back readiness ===")
        print(
            "row "
            f"function={func_name} m2={m2.status.value} "
            f"readiness={readiness.status.value} "
            f"parse_diags={parse_diags or '-'} plan_diags={plan_diags or '-'}"
        )
        if readiness.plan_result is not None and readiness.plan_result.plan is not None:
            plan = readiness.plan_result.plan
            print(
                "plan "
                f"blocks={plan.block_order} edge_moves={len(plan.edge_moves)} "
                f"bridges={len(plan.bridge_blocks)}"
            )

        has_unreachable_terminator = any(
            line.strip() == "unreachable" for line in m2.after_ir.splitlines()
        )
        if has_unreachable_terminator:
            assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED, (
                parse_diags,
                plan_diags,
                m2.after_ir,
            )
            assert readiness.plan_result is not None
            assert tuple(reason.kind for reason in readiness.plan_result.unsupported) == (
                LlvmLowerBackUnsupportedKind.UNSUPPORTED_CONTROL,
            )
        else:
            assert readiness.status is LlvmLowerBackReadinessStatus.PLANNED, (
                parse_diags,
                plan_diags,
                m2.after_ir,
            )
