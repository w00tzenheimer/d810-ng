"""LLVM M2a stock opt pipeline probe over real Hex-Rays-lifted snapshots."""
from __future__ import annotations

import os

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from d810.backends.hexrays.lifter import lift_function
from d810.backends.llvm import (
    LLVM_M2A_STOCK_PIPELINE,
    LlvmOptimizationStatus,
    LlvmVerificationStatus,
    emit_flowgraph_to_llvm,
    run_llvm_opt_pipeline,
    verify_llvm_ir,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


def _metrics_summary(prefix, metrics) -> str:
    return (
        f"{prefix}: blocks={metrics.block_count} insns={metrics.instruction_count} "
        f"terms={metrics.terminator_count} br={metrics.branch_count} "
        f"switch={metrics.switch_count} call={metrics.call_count} "
        f"load={metrics.load_count} store={metrics.store_count} "
        f"alloca={metrics.alloca_count} add={metrics.add_count} "
        f"and={metrics.and_count} xor={metrics.xor_count}"
    )


def _collapse_summary(before, after) -> str:
    return "\n".join(
        (
            _metrics_summary("before", before),
            _metrics_summary("after", after),
        )
    )


class TestLLVMM2StockOptPipeline:
    """Run the M2a stock pipeline on a preferred-maturity live lift."""

    binary_name = "restructuring_lab.dll"

    def test_lab_flat_branchless_stock_pipeline_verifies(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_ea = get_func_ea("lab_flat_branchless")
        assert func_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
        assert mba is not None

        flow_graph = lift_function(mba).flow_graph
        lift = emit_flowgraph_to_llvm(flow_graph, function_name="lab_flat_branchless_m2a")
        assert lift.supported, [reason.reason for reason in lift.unsupported]

        optimized = run_llvm_opt_pipeline(
            lift.ir_text,
            pipeline=LLVM_M2A_STOCK_PIPELINE,
            tmp_dir=tmp_path / "opt",
        )
        print("\n=== LLVM M2a stock opt pipeline ===")
        print(f"pipeline: {optimized.pipeline.name} passes={optimized.pipeline.pass_spec}")
        print(
            "optimization: "
            f"status={optimized.status.value} "
            f"opt={optimized.opt_path or '<none>'} "
            f"reason={optimized.reason or '-'}"
        )
        print(_metrics_summary("before", optimized.before_metrics))
        print(_metrics_summary("after", optimized.after_metrics))

        if optimized.skipped and os.environ.get("D810_REQUIRE_LLVM_OPT") != "1":
            pytest.skip(optimized.reason)
        assert optimized.status is LlvmOptimizationStatus.PASSED, (
            optimized.reason or optimized.stderr or optimized.stdout
        )
        assert optimized.optimized_ir

        verification = verify_llvm_ir(
            optimized.optimized_ir,
            function_name="lab_flat_branchless_m2a_optimized",
            opt_path=optimized.opt_path,
            tmp_dir=tmp_path / "verify",
        )
        print(
            "optimized verification: "
            f"status={verification.status.value} "
            f"opt={verification.opt_path or '<none>'} "
            f"reason={verification.reason or '-'}"
        )
        if verification.skipped and os.environ.get("D810_REQUIRE_LLVM_OPT") == "1":
            raise AssertionError(
                "D810_REQUIRE_LLVM_OPT=1 requires optimized LLVM verification to run; "
                f"reason={verification.reason or '-'}"
            )
        assert verification.status is LlvmVerificationStatus.PASSED, (
            verification.reason or verification.stderr or verification.stdout
        )
        collapse_summary = _collapse_summary(
            optimized.before_metrics,
            optimized.after_metrics,
        )
        assert (
            optimized.after_metrics.instruction_count
            < optimized.before_metrics.instruction_count
        ), collapse_summary
        assert (
            optimized.after_metrics.load_count < optimized.before_metrics.load_count
        ), collapse_summary
        assert (
            optimized.after_metrics.store_count < optimized.before_metrics.store_count
        ), collapse_summary
        assert (
            optimized.after_metrics.alloca_count < optimized.before_metrics.alloca_count
        ), collapse_summary
