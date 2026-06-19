"""LLVM M2a stock opt pipeline probe over real Hex-Rays-lifted snapshots."""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from d810.backends.hexrays.lifter import lift_function
from d810.backends.llvm import (
    LLVM_M2G_CURATED_PIPELINE,
    LLVM_M2A_STOCK_PIPELINE,
    LlvmLiftBoundary,
    LlvmLiftBoundaryInput,
    LlvmLiftBoundaryObservable,
    LlvmLiftBoundaryReturnPolicy,
    LlvmM2CensusRowStatus,
    LlvmM2OracleStatus,
    LlvmM2PipelineStatus,
    LlvmOptimizationStatus,
    LlvmVerificationStatus,
    check_m2_post_d810_branchless_oracle,
    emit_flowgraph_to_llvm,
    m2_census_row_from_pipeline,
    m2_lift_unsupported_row,
    m2_missing_row,
    measure_llvm_ir,
    run_llvm_m2_pipeline,
    run_llvm_opt_pipeline,
    summarize_m2_census,
    verify_llvm_ir,
)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.ir import Space, Varnode
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea
from tests.system.runtime.hexrays.lowering_catalog import (
    lower_conditional_synthesize,
    recover_branchless,
)


_REPO_ROOT = Path(__file__).resolve().parents[4]
_POST_D810_BRANCHLESS_ORACLE = (
    _REPO_ROOT
    / "tools/llvm_m2_post_d810/fixtures/lab_flat_branchless.structured.after.ll"
)
_POST_D810_BRANCHLESS_ORACLE_ID = "post_d810_lab_flat_branchless_structured_ir"


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


def _histogram_summary(items) -> str:
    return ",".join(f"{name}={count}" for name, count in items) or "-"


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


class TestLLVMM2CustomPipelineComposition:
    """Run the opt-in M2 custom+stock pipeline on a preferred-maturity live lift."""

    binary_name = "restructuring_lab.dll"

    def test_lab_flat_branchless_custom_stock_pipeline_verifies(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_ea = get_func_ea("lab_flat_branchless")
        assert func_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
        assert mba is not None

        flow_graph = lift_function(mba).flow_graph
        lift = emit_flowgraph_to_llvm(flow_graph, function_name="lab_flat_branchless_m2c")
        assert lift.supported, [reason.reason for reason in lift.unsupported]

        result = run_llvm_m2_pipeline(
            lift.ir_text,
            tmp_dir=tmp_path / "m2c",
            require_opt=os.environ.get("D810_REQUIRE_LLVM_OPT") == "1",
        )
        print("\n=== LLVM M2c custom+stock opt pipeline ===")
        print(
            "pipeline: "
            f"status={result.status.value} custom_rewrites={result.custom_rewrite_count} "
            f"reason={result.reason or '-'}"
        )
        for phase in result.phases:
            print(
                f"phase={phase.kind.value} name={phase.name} "
                f"status={phase.status.value} reason={phase.reason or '-'}"
            )
            print(_metrics_summary("  before", phase.before_metrics))
            print(_metrics_summary("  after", phase.after_metrics))
            if phase.optimization_result is not None:
                opt = phase.optimization_result.opt_path or "<none>"
                print(f"  opt={opt}")
            if phase.verification_result is not None:
                opt = phase.verification_result.opt_path or "<none>"
                print(f"  verification_opt={opt}")

        if result.skipped and os.environ.get("D810_REQUIRE_LLVM_OPT") != "1":
            pytest.skip(result.reason)
        assert result.status is LlvmM2PipelineStatus.PASSED, result.reason
        assert len(result.phases) == 3
        assert result.phases[0].status is LlvmM2PipelineStatus.PASSED
        assert result.phases[1].status is LlvmM2PipelineStatus.PASSED
        assert result.phases[2].status is LlvmM2PipelineStatus.PASSED


class TestLLVMM2PipelineCensus:
    """Run the opt-in M2 pipeline over curated preferred-maturity lab rows."""

    binary_name = "restructuring_lab.dll"

    FUNCTIONS = (
        "lab_if_diamond",
        "lab_flat_branchless",
        "lab_flat_jtbl",
        "lab_flat_mini",
        "lab_flat_cond",
        "lab_flat_loop",
        "lab_flat_region",
        "hexrays_lab_side_effect_boundary_anchor",
    )

    def test_preferred_maturity_live_m2_pipeline_census(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        rows = []
        require_opt = os.environ.get("D810_REQUIRE_LLVM_OPT") == "1"
        for func_name in self.FUNCTIONS:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                rows.append(
                    m2_missing_row(
                        func_name,
                        "GLOBAL_ANALYZED",
                        reason="function missing from restructuring_lab.dll",
                    )
                )
                continue

            mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
            assert mba is not None, func_name
            flow_graph = lift_function(mba).flow_graph
            lift = emit_flowgraph_to_llvm(
                flow_graph,
                function_name=f"{func_name}_m2d",
            )
            if not lift.supported:
                rows.append(
                    m2_lift_unsupported_row(
                        func_name,
                        "GLOBAL_ANALYZED",
                        reason="; ".join(reason.reason for reason in lift.unsupported),
                        ir_text=lift.ir_text,
                    )
                )
                continue

            result = run_llvm_m2_pipeline(
                lift.ir_text,
                tmp_dir=tmp_path / func_name,
                require_opt=require_opt,
            )
            rows.append(
                m2_census_row_from_pipeline(
                    func_name,
                    "GLOBAL_ANALYZED",
                    result,
                )
            )

        summary = summarize_m2_census(tuple(rows))
        print("\n=== LLVM M2e live pipeline census ===")
        for row in summary.rows:
            delta = row.metric_delta
            print(
                "row "
                f"function={row.function_name} status={row.status.value} "
                f"oracle={row.oracle_status.value} "
                f"oracle_id={row.oracle_id or '-'} "
                f"present={row.present} lift_supported={row.lift_supported} "
                f"pipeline={row.pipeline_status or '-'} "
                f"verification={row.verification_status or '-'} "
                f"custom_rewrites={row.custom_rewrite_count} "
                f"insns={row.before_metrics.instruction_count}"
                f"->{row.after_metrics.instruction_count} "
                f"loads={row.before_metrics.load_count}->{row.after_metrics.load_count} "
                f"stores={row.before_metrics.store_count}->{row.after_metrics.store_count} "
                f"allocas={row.before_metrics.alloca_count}"
                f"->{row.after_metrics.alloca_count} "
                f"delta=({delta.instruction_delta},"
                f"{delta.load_delta},{delta.store_delta},{delta.alloca_delta}) "
                f"reason={row.reason or '-'} "
                f"oracle_reason={row.oracle_reason or '-'}"
            )
        print(
            "summary "
            f"present={summary.present_count} missing={summary.missing_count} "
            f"passed={summary.passed_count} failed={summary.failed_count} "
            f"skipped={summary.skipped_count} "
            f"lift_unsupported={summary.lift_unsupported_count} "
            f"custom_rewrites={summary.custom_rewrite_total}"
        )
        print(
            "aggregate "
            f"insns={summary.before_instruction_total}"
            f"->{summary.after_instruction_total} "
            f"loads={summary.before_load_total}->{summary.after_load_total} "
            f"stores={summary.before_store_total}->{summary.after_store_total} "
            f"allocas={summary.before_alloca_total}->{summary.after_alloca_total}"
        )
        print(f"status_histogram={_histogram_summary(summary.status_histogram)}")
        print(
            "oracle_histogram="
            f"{_histogram_summary(summary.oracle_status_histogram)}"
        )
        print(f"collapse_histogram={_histogram_summary(summary.collapse_histogram)}")

        present_non_passed = [
            row
            for row in summary.rows
            if row.present and row.status is not LlvmM2CensusRowStatus.PASSED
        ]
        assert not present_non_passed, [
            (row.function_name, row.status.value, row.reason)
            for row in present_non_passed
        ]
        assert all(
            row.oracle_status is LlvmM2OracleStatus.NOT_APPLICABLE
            for row in summary.rows
        ), [(row.function_name, row.oracle_status.value) for row in summary.rows]
        assert ("not_applicable", len(summary.rows)) in summary.oracle_status_histogram

        branchless = next(
            row for row in summary.rows if row.function_name == "lab_flat_branchless"
        )
        collapse_summary = _collapse_summary(
            branchless.before_metrics,
            branchless.after_metrics,
        )
        assert branchless.metric_delta.collapsed_instruction_count, collapse_summary
        assert branchless.metric_delta.collapsed_load_count, collapse_summary
        assert branchless.metric_delta.collapsed_store_count, collapse_summary
        assert branchless.metric_delta.collapsed_alloca_count, collapse_summary


class TestLLVMM2PostD810StructuredOracle:
    """Run the structure-first branchless feed against its post-D810 oracle."""

    binary_name = "restructuring_lab.dll"

    def test_branchless_post_d810_structured_oracle_passes(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_ea = get_func_ea("lab_flat_branchless")
        assert func_ea != idaapi.BADADDR
        expected_ir = _POST_D810_BRANCHLESS_ORACLE.read_text(encoding="utf-8")
        require_opt = os.environ.get("D810_REQUIRE_LLVM_OPT") == "1"
        artifact_dir = _REPO_ROOT / ".tmp/llvm-m2o-post-d810-structured-oracle"
        shutil.rmtree(artifact_dir, ignore_errors=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)

        lift = _lift_post_d810_branchless(func_ea)
        artifact_dir.joinpath("post-d810-before-m2.ll").write_text(
            lift["ir_text"],
            encoding="utf-8",
        )
        assert lift["error"] is None, lift["error"]
        assert lift["applied"] >= 1, lift
        assert lift["supported"], lift["unsupported"]

        result = run_llvm_m2_pipeline(
            lift["ir_text"],
            tmp_dir=tmp_path / "m2o",
            require_opt=require_opt,
        )
        artifact_dir.joinpath("post-d810-after-m2.ll").write_text(
            result.after_ir,
            encoding="utf-8",
        )
        oracle = check_m2_post_d810_branchless_oracle(
            subject="lab_flat_branchless",
            actual_ir=result.after_ir,
            expected_ir=expected_ir,
            oracle_id=_POST_D810_BRANCHLESS_ORACLE_ID,
        )
        row = m2_census_row_from_pipeline(
            "lab_flat_branchless",
            "GLOBAL_ANALYZED_POST_D810",
            result,
            oracle_result=oracle,
        )
        summary = {
            "applied": lift["applied"],
            "lift_supported": lift["supported"],
            "lift_unsupported": lift["unsupported"],
            "pipeline_status": result.status.value,
            "pipeline_reason": result.reason,
            "oracle_status": oracle.status.value,
            "oracle_id": oracle.oracle_id,
            "oracle_reason": oracle.reason,
            "expected_signature": list(oracle.expected_signature),
            "actual_signature": list(oracle.actual_signature),
            "before_metrics": asdict(measure_llvm_ir(lift["ir_text"])),
            "after_metrics": asdict(measure_llvm_ir(result.after_ir)),
        }
        artifact_dir.joinpath("summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        print("\n=== LLVM M2o post-D810 structured branchless oracle ===")
        print(f"artifact_dir={artifact_dir}")
        print(
            "row "
            f"function={row.function_name} status={row.status.value} "
            f"oracle={row.oracle_status.value} "
            f"oracle_id={row.oracle_id or '-'} "
            f"pipeline={row.pipeline_status or '-'} "
            f"custom_rewrites={row.custom_rewrite_count} "
            f"reason={row.reason or '-'} "
            f"oracle_reason={row.oracle_reason or '-'}"
        )
        print(f"expected_signature={oracle.expected_signature}")
        print(f"actual_signature={oracle.actual_signature}")

        assert result.status is LlvmM2PipelineStatus.PASSED, result.reason
        assert oracle.status is LlvmM2OracleStatus.PASSED, (
            oracle.reason,
            oracle.expected_signature,
            oracle.actual_signature,
        )
        assert row.oracle_status is LlvmM2OracleStatus.PASSED
        assert "return:constant_zero" not in oracle.actual_signature
        assert "return:phi:odd_even" in oracle.actual_signature


class TestLLVMM2CuratedPipelineComparison:
    """Compare the opt-in M2g curated stock pipeline against the M2a default."""

    binary_name = "restructuring_lab.dll"

    FUNCTIONS = TestLLVMM2PipelineCensus.FUNCTIONS
    KNOWN_MISSING = frozenset({"hexrays_lab_side_effect_boundary_anchor"})

    def test_preferred_maturity_curated_pipeline_verifies_and_improves(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        rows = []
        missing_rows = []
        unsupported_rows = []
        require_opt = os.environ.get("D810_REQUIRE_LLVM_OPT") == "1"
        for func_name in self.FUNCTIONS:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                missing_rows.append(
                    (
                        func_name,
                        "function missing from restructuring_lab.dll",
                    )
                )
                continue

            mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
            assert mba is not None, func_name
            flow_graph = lift_function(mba).flow_graph
            lift = emit_flowgraph_to_llvm(
                flow_graph,
                function_name=f"{func_name}_m2g",
            )
            if not lift.supported:
                unsupported_rows.append(
                    (
                        func_name,
                        tuple(reason.reason for reason in lift.unsupported),
                    )
                )
                continue

            m2a_result = run_llvm_m2_pipeline(
                lift.ir_text,
                stock_pipeline=LLVM_M2A_STOCK_PIPELINE,
                tmp_dir=tmp_path / func_name / "m2a",
                require_opt=require_opt,
            )
            curated_result = run_llvm_m2_pipeline(
                lift.ir_text,
                stock_pipeline=LLVM_M2G_CURATED_PIPELINE,
                tmp_dir=tmp_path / func_name / "curated",
                require_opt=require_opt,
            )
            rows.append((func_name, m2a_result, curated_result))

        assert rows, "no supported live M2 rows available for curated comparison"
        print("\n=== LLVM M2g curated pipeline comparison ===")
        print(f"m2a_pipeline={LLVM_M2A_STOCK_PIPELINE.pass_spec}")
        print(f"curated_pipeline={LLVM_M2G_CURATED_PIPELINE.pass_spec}")
        for func_name, reason in missing_rows:
            print(f"row function={func_name} status=missing reason={reason}")
        for func_name, reasons in unsupported_rows:
            print(
                f"row function={func_name} status=lift_unsupported "
                f"reasons={'; '.join(reasons) or '-'}"
            )
        for func_name, m2a_result, curated_result in rows:
            m2a_metrics = measure_llvm_ir(m2a_result.after_ir)
            curated_metrics = measure_llvm_ir(curated_result.after_ir)
            print(
                "row "
                f"function={func_name} "
                f"m2a={m2a_result.status.value} "
                f"curated={curated_result.status.value} "
                f"insns={m2a_metrics.instruction_count}"
                f"->{curated_metrics.instruction_count} "
                f"loads={m2a_metrics.load_count}->{curated_metrics.load_count} "
                f"stores={m2a_metrics.store_count}->{curated_metrics.store_count} "
                f"allocas={m2a_metrics.alloca_count}->{curated_metrics.alloca_count} "
                f"m2a_reason={m2a_result.reason or '-'} "
                f"curated_reason={curated_result.reason or '-'}"
            )

        unexpected_missing = [
            row for row in missing_rows if row[0] not in self.KNOWN_MISSING
        ]
        compared_names = {func_name for func_name, _, _ in rows}
        missing_names = {func_name for func_name, _ in missing_rows}
        expected_compared = set(self.FUNCTIONS) - missing_names
        assert not unexpected_missing, unexpected_missing
        assert not unsupported_rows, unsupported_rows
        assert compared_names == expected_compared, {
            "compared": sorted(compared_names),
            "expected": sorted(expected_compared),
            "missing": missing_rows,
            "unsupported": unsupported_rows,
        }

        m2a_totals = _metric_totals(m2a_result for _, m2a_result, _ in rows)
        curated_totals = _metric_totals(curated_result for _, _, curated_result in rows)
        print(
            "aggregate "
            f"insns={m2a_totals['instruction']}"
            f"->{curated_totals['instruction']} "
            f"loads={m2a_totals['load']}->{curated_totals['load']} "
            f"stores={m2a_totals['store']}->{curated_totals['store']} "
            f"allocas={m2a_totals['alloca']}->{curated_totals['alloca']}"
        )

        m2a_failures = [
            (func_name, result.status.value, result.reason)
            for func_name, result, _ in rows
            if result.status is not LlvmM2PipelineStatus.PASSED
        ]
        curated_failures = [
            (func_name, result.status.value, result.reason)
            for func_name, _, result in rows
            if result.status is not LlvmM2PipelineStatus.PASSED
        ]
        assert not m2a_failures, m2a_failures
        assert not curated_failures, curated_failures

        non_regressed = {
            metric: curated_totals[metric] <= m2a_totals[metric]
            for metric in ("instruction", "load", "store", "alloca")
        }
        improved = {
            metric: curated_totals[metric] < m2a_totals[metric]
            for metric in ("instruction", "load", "store", "alloca")
        }
        assert all(non_regressed.values()), {
            "m2a": m2a_totals,
            "curated": curated_totals,
        }
        assert any(improved.values()), {
            "m2a": m2a_totals,
            "curated": curated_totals,
        }


def _metric_totals(results) -> dict[str, int]:
    totals = {
        "instruction": 0,
        "load": 0,
        "store": 0,
        "alloca": 0,
    }
    for result in results:
        metrics = measure_llvm_ir(result.after_ir)
        totals["instruction"] += metrics.instruction_count
        totals["load"] += metrics.load_count
        totals["store"] += metrics.store_count
        totals["alloca"] += metrics.alloca_count
    return totals


def _lift_post_d810_branchless(func_ea) -> dict[str, object]:
    boundary = LlvmLiftBoundary(
        inputs=(
            LlvmLiftBoundaryInput(
                "token",
                Varnode(Space.REGISTER, 24, 4),
                aliases=(Varnode(Space.REGISTER, 24, 1),),
            ),
        ),
        observables=(
            LlvmLiftBoundaryObservable(
                "state_sink",
                Varnode(Space.STACK, 16, 4),
            ),
            LlvmLiftBoundaryObservable(
                "value_sink",
                Varnode(Space.GLOBAL, 6442475664, 4),
            ),
        ),
        return_cell=Varnode(Space.REGISTER, 8, 4),
        return_policy=LlvmLiftBoundaryReturnPolicy.OVERRIDE,
    )
    box = {
        "applied": 0,
        "done": False,
        "error": None,
        "ir_text": "",
        "supported": False,
        "unsupported": (),
    }

    class _PostD810LiftOptblock(ida_hexrays.optblock_t):
        def func(self, blk):
            try:
                mba = blk.mba
                if (
                    box["done"]
                    or mba is None
                    or int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1)
                ):
                    return 0
                plan = recover_branchless(mba)
                if plan is None:
                    return 0
                box["done"] = True
                mod = DeferredGraphModifier(mba)
                lower_conditional_synthesize(mod, plan)
                mod.coalesce()
                box["applied"] = mod.apply(run_optimize_local=True)
                flow_graph = lift_function(mba).flow_graph
                lift = emit_flowgraph_to_llvm(
                    flow_graph,
                    function_name="lab_flat_branchless_post_d810_m2o",
                    boundary=boundary,
                )
                box["ir_text"] = lift.ir_text
                box["supported"] = lift.supported
                box["unsupported"] = tuple(
                    reason.reason for reason in lift.unsupported
                )
                return box["applied"]
            except Exception as exc:  # noqa: BLE001
                box["error"] = repr(exc)
                return 0

    opt = _PostD810LiftOptblock()
    opt.install()
    hf = ida_hexrays.hexrays_failure_t()
    try:
        ida_hexrays.mark_cfunc_dirty(func_ea)
        ida_hexrays.decompile(func_ea, hf)
    finally:
        opt.remove()
    return box
