from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    LlvmCustomProofResult,
    LlvmM2PipelinePhaseKind,
    LlvmM2PipelineStatus,
    LlvmOptimizationStatus,
    LlvmVerificationStatus,
    run_llvm_m2_pipeline,
    run_llvm_opt_pipeline,
)


def _write_fake_opt(tmp_path: Path, body: str | None = None) -> Path:
    opt = tmp_path / "opt"
    opt.write_text(
        "#!/bin/sh\n"
        + (
            body
            or 'if [ "$2" = "-passes=verify" ]; then cat "$3"; '
            'else cat "$3" > "$5"; fi\nexit 0\n'
        ),
        encoding="utf-8",
    )
    opt.chmod(0o755)
    return opt


def _fixture_ir() -> str:
    return Path(
        "tools/llvm_m2_custom_pass/fixtures/mba_xor_with_unrelated_sub.ll"
    ).read_text(encoding="utf-8")


def _or_fixture_ir() -> str:
    return Path(
        "tools/llvm_m2_custom_pass/fixtures/mba_or_and_xor.ll"
    ).read_text(encoding="utf-8")


def test_m2_pipeline_runs_custom_then_stock_then_verify(tmp_path):
    opt = _write_fake_opt(tmp_path)

    result = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
    )

    assert result.status is LlvmM2PipelineStatus.PASSED
    assert [phase.kind for phase in result.phases] == [
        LlvmM2PipelinePhaseKind.CUSTOM_PRE,
        LlvmM2PipelinePhaseKind.STOCK_OPT,
        LlvmM2PipelinePhaseKind.VERIFY_OPTIMIZED,
    ]
    assert result.custom_rewrite_count == 1
    assert "  %out = xor i32 %x, %y" in result.after_ir
    assert "  %other = sub i32 %or2, %x" in result.after_ir
    custom = result.phases[0].custom_result
    stock = result.phases[1].optimization_result
    verification = result.phases[2].verification_result
    assert custom is not None and len(custom.pass_results[0].rewrites) == 1
    assert stock is not None and stock.status is LlvmOptimizationStatus.PASSED
    assert verification is not None
    assert verification.status is LlvmVerificationStatus.PASSED
    assert result.phases[2].reason == ""
    assert verification.stdout


def test_m2_pipeline_counts_or_custom_rewrite_before_stock_opt(tmp_path):
    opt = _write_fake_opt(tmp_path)

    result = run_llvm_m2_pipeline(
        _or_fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
    )

    assert result.status is LlvmM2PipelineStatus.PASSED
    assert result.custom_rewrite_count == 1
    assert "  %out = or i32 %x, %y" in result.after_ir
    custom = result.phases[0].custom_result
    assert custom is not None
    assert [len(pass_result.rewrites) for pass_result in custom.pass_results] == [0, 1]


def test_m2_pipeline_custom_failure_stops_before_stock_opt(tmp_path):
    opt = _write_fake_opt(tmp_path)

    result = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
        proof_checker=lambda _bits: LlvmCustomProofResult(
            verified=False,
            reason="proof unavailable in test",
        ),
    )

    assert result.status is LlvmM2PipelineStatus.FAILED
    assert len(result.phases) == 1
    assert result.phases[0].kind is LlvmM2PipelinePhaseKind.CUSTOM_PRE
    assert result.after_ir == _fixture_ir()
    assert "proof unavailable in test" in result.reason


def test_m2_pipeline_custom_no_change_still_runs_stock_opt(tmp_path):
    opt = _write_fake_opt(tmp_path)
    ir = """define i32 @plain(i32 %x, i32 %y) {
entry:
  %out = add i32 %x, %y
  ret i32 %out
}
"""

    result = run_llvm_m2_pipeline(
        ir,
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
    )

    assert result.status is LlvmM2PipelineStatus.PASSED
    assert result.custom_rewrite_count == 0
    assert [phase.kind for phase in result.phases] == [
        LlvmM2PipelinePhaseKind.CUSTOM_PRE,
        LlvmM2PipelinePhaseKind.STOCK_OPT,
        LlvmM2PipelinePhaseKind.VERIFY_OPTIMIZED,
    ]
    assert result.after_ir == ir


def test_m2_pipeline_stock_opt_failure_is_structured(tmp_path):
    opt = _write_fake_opt(tmp_path, "echo opt-bad >&2\nexit 9\n")

    result = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
    )

    assert result.status is LlvmM2PipelineStatus.FAILED
    assert [phase.kind for phase in result.phases] == [
        LlvmM2PipelinePhaseKind.CUSTOM_PRE,
        LlvmM2PipelinePhaseKind.STOCK_OPT,
    ]
    assert result.phases[1].optimization_result is not None
    assert result.phases[1].optimization_result.status is LlvmOptimizationStatus.FAILED
    assert "opt-bad" in result.reason


def test_m2_pipeline_missing_opt_skips_unless_required(tmp_path):
    opt = tmp_path / "missing-opt"

    skipped = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "skip",
        require_opt=False,
    )
    required = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "required",
        require_opt=True,
    )

    assert skipped.status is LlvmM2PipelineStatus.SKIPPED
    assert required.status is LlvmM2PipelineStatus.FAILED
    assert skipped.phases[1].status is LlvmM2PipelineStatus.SKIPPED
    assert required.phases[1].status is LlvmM2PipelineStatus.FAILED


def test_m2_pipeline_verification_failure_is_structured(tmp_path):
    opt = _write_fake_opt(
        tmp_path,
        'if [ "$2" = "-passes=verify" ]; then echo verify-bad >&2; exit 3; '
        'else cat "$3" > "$5"; fi\nexit 0\n',
    )

    result = run_llvm_m2_pipeline(
        _fixture_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "work",
        require_opt=True,
    )

    assert result.status is LlvmM2PipelineStatus.FAILED
    assert result.phases[-1].kind is LlvmM2PipelinePhaseKind.VERIFY_OPTIMIZED
    assert result.phases[-1].verification_result is not None
    assert result.phases[-1].verification_result.status is LlvmVerificationStatus.FAILED
    assert "verify-bad" in result.reason


def test_m2a_stock_runner_default_behavior_remains_unchanged(tmp_path):
    result = run_llvm_opt_pipeline(
        "define i32 @x() { ret i32 0 }\n",
        opt_path=tmp_path / "missing-opt",
        tmp_dir=tmp_path / "stock",
    )

    assert result.status is LlvmOptimizationStatus.SKIPPED
    assert result.optimized_ir == ""
    assert result.command == ()
