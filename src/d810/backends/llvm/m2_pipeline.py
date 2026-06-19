"""Opt-in M2 orchestration over d810 custom passes and stock LLVM opt.

This module is IDA-free. It composes the M2b d810 MBA/Z3 custom-pass socket
with the M2a stock ``opt`` runner and structured verifier without changing the
default behavior of either lower-level API.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .custom_passes import (
    D810_MBA_XOR_OR_SUB_AND_PASS,
    LlvmCustomPass,
    LlvmCustomPassRunResult,
    LlvmCustomPassStatus,
    ProofChecker,
    run_d810_custom_passes,
)
from .optimization import (
    LLVM_M2A_STOCK_PIPELINE,
    LlvmIrMetrics,
    LlvmOptimizationResult,
    LlvmOptimizationStatus,
    LlvmOptPipeline,
    measure_llvm_ir,
    run_llvm_opt_pipeline,
)
from .verification import (
    LlvmVerificationResult,
    LlvmVerificationStatus,
    verify_llvm_ir,
)


class LlvmM2PipelineStatus(str, Enum):
    PASSED = "passed"
    SKIPPED = "skipped"
    FAILED = "failed"


class LlvmM2PipelinePhaseKind(str, Enum):
    CUSTOM_PRE = "custom_pre"
    STOCK_OPT = "stock_opt"
    VERIFY_OPTIMIZED = "verify_optimized"


@dataclass(frozen=True, slots=True)
class LlvmM2PipelinePhaseResult:
    kind: LlvmM2PipelinePhaseKind
    name: str
    status: LlvmM2PipelineStatus
    before_ir: str
    after_ir: str
    before_metrics: LlvmIrMetrics
    after_metrics: LlvmIrMetrics
    reason: str = ""
    custom_result: LlvmCustomPassRunResult | None = None
    optimization_result: LlvmOptimizationResult | None = None
    verification_result: LlvmVerificationResult | None = None


@dataclass(frozen=True, slots=True)
class LlvmM2PipelineResult:
    status: LlvmM2PipelineStatus
    before_ir: str
    after_ir: str
    phases: tuple[LlvmM2PipelinePhaseResult, ...]
    custom_rewrite_count: int
    reason: str = ""

    @property
    def passed(self) -> bool:
        return self.status is LlvmM2PipelineStatus.PASSED

    @property
    def skipped(self) -> bool:
        return self.status is LlvmM2PipelineStatus.SKIPPED

    @property
    def failed(self) -> bool:
        return self.status is LlvmM2PipelineStatus.FAILED


def run_llvm_m2_pipeline(
    ir_text: str,
    *,
    custom_passes: tuple[LlvmCustomPass, ...] = (D810_MBA_XOR_OR_SUB_AND_PASS,),
    stock_pipeline: LlvmOptPipeline = LLVM_M2A_STOCK_PIPELINE,
    opt_path: Path | None = None,
    tmp_dir: Path | None = None,
    require_opt: bool | None = None,
    proof_checker: ProofChecker | None = None,
) -> LlvmM2PipelineResult:
    """Run the opt-in M2 custom-pre + stock-opt + verify pipeline."""
    require_opt = (
        os.environ.get("D810_REQUIRE_LLVM_OPT") == "1"
        if require_opt is None
        else require_opt
    )
    phases: list[LlvmM2PipelinePhaseResult] = []
    before_metrics = measure_llvm_ir(ir_text)

    custom = run_d810_custom_passes(
        ir_text,
        passes=custom_passes,
        proof_checker=proof_checker,
    )
    custom_status = _custom_status_to_phase_status(custom.status)
    custom_phase = LlvmM2PipelinePhaseResult(
        kind=LlvmM2PipelinePhaseKind.CUSTOM_PRE,
        name="d810_custom_pre",
        status=custom_status,
        before_ir=ir_text,
        after_ir=custom.after_ir,
        before_metrics=before_metrics,
        after_metrics=measure_llvm_ir(custom.after_ir),
        reason=_custom_reason(custom),
        custom_result=custom,
    )
    phases.append(custom_phase)
    if custom.failed:
        return LlvmM2PipelineResult(
            status=LlvmM2PipelineStatus.FAILED,
            before_ir=ir_text,
            after_ir=ir_text,
            phases=tuple(phases),
            custom_rewrite_count=0,
            reason=custom_phase.reason or "custom pre-pass failed",
        )

    opt_tmp = tmp_dir / "stock-opt" if tmp_dir is not None else None
    optimized = run_llvm_opt_pipeline(
        custom.after_ir,
        pipeline=stock_pipeline,
        opt_path=opt_path,
        tmp_dir=opt_tmp,
    )
    stock_status = _optimization_status_to_phase_status(optimized.status, require_opt)
    stock_reason = (
        ""
        if optimized.passed
        else optimized.reason or optimized.stderr or optimized.stdout
    )
    phases.append(
        LlvmM2PipelinePhaseResult(
            kind=LlvmM2PipelinePhaseKind.STOCK_OPT,
            name=stock_pipeline.name,
            status=stock_status,
            before_ir=custom.after_ir,
            after_ir=optimized.optimized_ir or custom.after_ir,
            before_metrics=optimized.before_metrics,
            after_metrics=(
                optimized.after_metrics
                if optimized.optimized_ir
                else measure_llvm_ir(custom.after_ir)
            ),
            reason=stock_reason,
            optimization_result=optimized,
        )
    )
    custom_rewrite_count = sum(
        len(result.rewrites) for result in custom.pass_results
    )
    if optimized.failed or (optimized.skipped and require_opt):
        return LlvmM2PipelineResult(
            status=LlvmM2PipelineStatus.FAILED,
            before_ir=ir_text,
            after_ir=custom.after_ir,
            phases=tuple(phases),
            custom_rewrite_count=custom_rewrite_count,
            reason=stock_reason or "stock opt failed",
        )
    if optimized.skipped:
        return LlvmM2PipelineResult(
            status=LlvmM2PipelineStatus.SKIPPED,
            before_ir=ir_text,
            after_ir=custom.after_ir,
            phases=tuple(phases),
            custom_rewrite_count=custom_rewrite_count,
            reason=optimized.reason,
        )

    verify_tmp = tmp_dir / "verify-optimized" if tmp_dir is not None else None
    verification = verify_llvm_ir(
        optimized.optimized_ir,
        function_name="d810_m2_optimized",
        opt_path=optimized.opt_path,
        tmp_dir=verify_tmp,
    )
    verify_status = _verification_status_to_phase_status(
        verification.status,
        require_opt,
    )
    verify_reason = (
        ""
        if verification.passed
        else verification.reason or verification.stderr or verification.stdout
    )
    phases.append(
        LlvmM2PipelinePhaseResult(
            kind=LlvmM2PipelinePhaseKind.VERIFY_OPTIMIZED,
            name="verify_optimized",
            status=verify_status,
            before_ir=optimized.optimized_ir,
            after_ir=optimized.optimized_ir,
            before_metrics=optimized.after_metrics,
            after_metrics=optimized.after_metrics,
            reason=verify_reason,
            verification_result=verification,
        )
    )
    if verification.failed or (verification.skipped and require_opt):
        return LlvmM2PipelineResult(
            status=LlvmM2PipelineStatus.FAILED,
            before_ir=ir_text,
            after_ir=optimized.optimized_ir,
            phases=tuple(phases),
            custom_rewrite_count=custom_rewrite_count,
            reason=verify_reason or "optimized verification failed",
        )
    if verification.skipped:
        return LlvmM2PipelineResult(
            status=LlvmM2PipelineStatus.SKIPPED,
            before_ir=ir_text,
            after_ir=optimized.optimized_ir,
            phases=tuple(phases),
            custom_rewrite_count=custom_rewrite_count,
            reason=verification.reason,
        )

    return LlvmM2PipelineResult(
        status=LlvmM2PipelineStatus.PASSED,
        before_ir=ir_text,
        after_ir=optimized.optimized_ir,
        phases=tuple(phases),
        custom_rewrite_count=custom_rewrite_count,
    )


def _custom_status_to_phase_status(
    status: LlvmCustomPassStatus,
) -> LlvmM2PipelineStatus:
    if status is LlvmCustomPassStatus.FAILED:
        return LlvmM2PipelineStatus.FAILED
    return LlvmM2PipelineStatus.PASSED


def _optimization_status_to_phase_status(
    status: LlvmOptimizationStatus,
    require_opt: bool,
) -> LlvmM2PipelineStatus:
    if status is LlvmOptimizationStatus.PASSED:
        return LlvmM2PipelineStatus.PASSED
    if status is LlvmOptimizationStatus.SKIPPED and not require_opt:
        return LlvmM2PipelineStatus.SKIPPED
    return LlvmM2PipelineStatus.FAILED


def _verification_status_to_phase_status(
    status: LlvmVerificationStatus,
    require_opt: bool,
) -> LlvmM2PipelineStatus:
    if status is LlvmVerificationStatus.PASSED:
        return LlvmM2PipelineStatus.PASSED
    if status is LlvmVerificationStatus.SKIPPED and not require_opt:
        return LlvmM2PipelineStatus.SKIPPED
    return LlvmM2PipelineStatus.FAILED


def _custom_reason(result: LlvmCustomPassRunResult) -> str:
    if not result.failed:
        return ""
    for pass_result in result.pass_results:
        if pass_result.diagnostics:
            return pass_result.diagnostics[0].reason
    return "custom pre-pass failed"
