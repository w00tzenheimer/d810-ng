from __future__ import annotations

from pathlib import Path

import pytest

from d810.backends.llvm import (
    LLVM_M2G_CURATED_PIPELINE,
    LLVM_M2A_STOCK_PIPELINE,
    LlvmOptimizationStatus,
    find_llvm_opt,
    measure_llvm_ir,
    normalize_llvm_ir,
    run_llvm_opt_pipeline,
)


def _write_fake_opt(tmp_path: Path, body: str) -> Path:
    opt = tmp_path / "opt"
    opt.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    opt.chmod(0o755)
    return opt


def test_measure_llvm_ir_counts_coarse_structure():
    ir = """
define i32 @x(i32 %a) {
entry:
  %slot = alloca i32
  store i32 %a, ptr %slot
  %v = load i32, ptr %slot
  %c = call i32 @opaque(i32 %v)
  br label %exit
exit:
  ret i32 %c
}
"""

    metrics = measure_llvm_ir(ir)

    assert metrics.block_count == 2
    assert metrics.instruction_count == 6
    assert metrics.terminator_count == 2
    assert metrics.branch_count == 1
    assert metrics.switch_count == 0
    assert metrics.call_count == 1
    assert metrics.load_count == 1
    assert metrics.store_count == 1
    assert metrics.alloca_count == 1
    assert metrics.add_count == 0
    assert metrics.and_count == 0
    assert metrics.xor_count == 0


def test_normalize_llvm_ir_uses_neutral_module_id_placeholder():
    text = "; ModuleID = '../unrelated.ll'\ndefine i32 @x() { ret i32 0 }\n"

    normalized = normalize_llvm_ir(text)

    assert "lab_flat_branchless.before.ll" not in normalized
    assert "; ModuleID = '<normalized>'" in normalized
    assert "define i32 @x()" in normalized


def test_run_llvm_opt_pipeline_reports_passed_status_with_fake_opt(tmp_path):
    opt = _write_fake_opt(tmp_path, 'cat "$3" > "$5"\nexit 0\n')
    ir = "define i32 @x() {\nentry:\n  ret i32 0\n}\n"

    result = run_llvm_opt_pipeline(ir, opt_path=opt, tmp_dir=tmp_path / "work")

    assert result.status is LlvmOptimizationStatus.PASSED
    assert result.opt_path == opt
    assert result.command[:3] == (
        str(opt),
        "-S",
        f"-passes={LLVM_M2A_STOCK_PIPELINE.pass_spec}",
    )
    assert result.command[3].endswith("d810-opt-input.ll")
    assert result.command[5].endswith("d810-opt-output.ll")
    assert result.input_ir == ir
    assert result.optimized_ir == ir
    assert result.before_metrics == result.after_metrics
    assert result.pipeline is LLVM_M2A_STOCK_PIPELINE


def test_m2g_curated_pipeline_has_stable_pass_spec():
    assert LLVM_M2G_CURATED_PIPELINE.name == (
        "m2g_curated_ssa_cse_gvn_dse_aggressive_instcombine_simplifycfg_adce"
    )
    assert LLVM_M2G_CURATED_PIPELINE.passes == (
        "sroa",
        "mem2reg",
        "early-cse",
        "instcombine",
        "reassociate",
        "sccp",
        "correlated-propagation",
        "gvn",
        "dse",
        "aggressive-instcombine",
        "simplifycfg<no-switch-to-lookup>",
        "adce",
    )
    assert LLVM_M2G_CURATED_PIPELINE.pass_spec == (
        "sroa,mem2reg,early-cse,instcombine,reassociate,sccp,"
        "correlated-propagation,gvn,dse,aggressive-instcombine,"
        "simplifycfg<no-switch-to-lookup>,adce"
    )


def test_run_llvm_opt_pipeline_uses_curated_pass_spec_with_fake_opt(tmp_path):
    opt = _write_fake_opt(tmp_path, 'printf "%s\\n" "$2" > "$5"\nexit 0\n')

    result = run_llvm_opt_pipeline(
        "define i32 @x() {\nentry:\n  ret i32 0\n}\n",
        pipeline=LLVM_M2G_CURATED_PIPELINE,
        opt_path=opt,
        tmp_dir=tmp_path / "work",
    )

    assert result.status is LlvmOptimizationStatus.PASSED
    assert result.command[:3] == (
        str(opt),
        "-S",
        f"-passes={LLVM_M2G_CURATED_PIPELINE.pass_spec}",
    )
    assert result.optimized_ir == f"-passes={LLVM_M2G_CURATED_PIPELINE.pass_spec}\n"
    assert result.pipeline is LLVM_M2G_CURATED_PIPELINE


def test_run_llvm_opt_pipeline_reports_failed_status_with_fake_opt(tmp_path):
    opt = _write_fake_opt(tmp_path, "echo bad-out\necho bad-err >&2\nexit 7\n")

    result = run_llvm_opt_pipeline(
        "define i32 @x() { ret i32 0 }\n",
        opt_path=opt,
        tmp_dir=tmp_path / "work",
    )

    assert result.status is LlvmOptimizationStatus.FAILED
    assert result.optimized_ir == ""
    assert "bad-out" in result.stdout
    assert "bad-err" in result.stderr
    assert "bad-err" in result.reason


def test_run_llvm_opt_pipeline_reports_skipped_when_opt_missing(tmp_path):
    result = run_llvm_opt_pipeline(
        "define i32 @x() { ret i32 0 }\n",
        opt_path=tmp_path / "missing-opt",
        tmp_dir=tmp_path / "work",
    )

    assert result.status is LlvmOptimizationStatus.SKIPPED
    assert result.command == ()
    assert result.optimized_ir == ""
    assert "not executable" in result.reason


def test_run_llvm_opt_pipeline_keeps_temp_paths_inside_tmp_dir(tmp_path):
    opt = _write_fake_opt(tmp_path, 'cat "$3" > "$5"\nexit 0\n')
    work = tmp_path / "inside"

    result = run_llvm_opt_pipeline(
        "define i32 @x() { ret i32 0 }\n",
        opt_path=opt,
        tmp_dir=work,
    )

    assert result.status is LlvmOptimizationStatus.PASSED
    assert Path(result.command[3]).resolve().parent == work.resolve()
    assert Path(result.command[5]).resolve().parent == work.resolve()
    assert {path.name for path in work.iterdir()} == {
        "d810-opt-input.ll",
        "d810-opt-output.ll",
    }


def test_m0_fixture_optimizes_to_checked_in_after_when_opt_available():
    opt = find_llvm_opt()
    if opt is None:
        pytest.skip("LLVM opt not found; M2a fixture comparison requires opt")

    fixture_dir = Path("tools/llvm_m0_roundtrip/fixtures")
    before = (fixture_dir / "lab_flat_branchless.before.ll").read_text(encoding="utf-8")
    expected = (fixture_dir / "lab_flat_branchless.after.ll").read_text(encoding="utf-8")

    result = run_llvm_opt_pipeline(before, opt_path=opt)

    assert result.status is LlvmOptimizationStatus.PASSED, (
        result.reason or result.stderr or result.stdout
    )
    assert normalize_llvm_ir(result.optimized_ir) == normalize_llvm_ir(expected)
    assert result.before_metrics.xor_count == result.after_metrics.xor_count + 1
    assert result.after_metrics.store_count == 2
