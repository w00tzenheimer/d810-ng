"""IDA-free DTOs for M2 live coverage and collapse census rows."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .m2_pipeline import LlvmM2PipelinePhaseKind, LlvmM2PipelineResult
from .optimization import LlvmIrMetrics, measure_llvm_ir


class LlvmM2CensusRowStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    MISSING = "missing"
    LIFT_UNSUPPORTED = "lift_unsupported"


@dataclass(frozen=True, slots=True)
class LlvmM2MetricDelta:
    instruction_delta: int
    load_delta: int
    store_delta: int
    alloca_delta: int

    @property
    def collapsed_instruction_count(self) -> bool:
        return self.instruction_delta < 0

    @property
    def collapsed_load_count(self) -> bool:
        return self.load_delta < 0

    @property
    def collapsed_store_count(self) -> bool:
        return self.store_delta < 0

    @property
    def collapsed_alloca_count(self) -> bool:
        return self.alloca_delta < 0


@dataclass(frozen=True, slots=True)
class LlvmM2CensusRow:
    function_name: str
    maturity: str
    status: LlvmM2CensusRowStatus
    present: bool
    lift_supported: bool
    pipeline_status: str
    verification_status: str
    custom_rewrite_count: int
    before_metrics: LlvmIrMetrics
    after_metrics: LlvmIrMetrics
    reason: str = ""

    @property
    def metric_delta(self) -> LlvmM2MetricDelta:
        return LlvmM2MetricDelta(
            instruction_delta=(
                self.after_metrics.instruction_count
                - self.before_metrics.instruction_count
            ),
            load_delta=self.after_metrics.load_count - self.before_metrics.load_count,
            store_delta=self.after_metrics.store_count - self.before_metrics.store_count,
            alloca_delta=(
                self.after_metrics.alloca_count - self.before_metrics.alloca_count
            ),
        )


@dataclass(frozen=True, slots=True)
class LlvmM2CensusSummary:
    rows: tuple[LlvmM2CensusRow, ...]

    @property
    def present_count(self) -> int:
        return sum(1 for row in self.rows if row.present)

    @property
    def missing_count(self) -> int:
        return sum(1 for row in self.rows if not row.present)

    @property
    def passed_count(self) -> int:
        return sum(1 for row in self.rows if row.status is LlvmM2CensusRowStatus.PASSED)

    @property
    def failed_count(self) -> int:
        return sum(1 for row in self.rows if row.status is LlvmM2CensusRowStatus.FAILED)

    @property
    def skipped_count(self) -> int:
        return sum(1 for row in self.rows if row.status is LlvmM2CensusRowStatus.SKIPPED)

    @property
    def lift_unsupported_count(self) -> int:
        return sum(
            1 for row in self.rows if row.status is LlvmM2CensusRowStatus.LIFT_UNSUPPORTED
        )

    @property
    def custom_rewrite_total(self) -> int:
        return sum(row.custom_rewrite_count for row in self.rows)

    @property
    def before_instruction_total(self) -> int:
        return sum(row.before_metrics.instruction_count for row in self.rows)

    @property
    def after_instruction_total(self) -> int:
        return sum(row.after_metrics.instruction_count for row in self.rows)

    @property
    def before_load_total(self) -> int:
        return sum(row.before_metrics.load_count for row in self.rows)

    @property
    def after_load_total(self) -> int:
        return sum(row.after_metrics.load_count for row in self.rows)

    @property
    def before_store_total(self) -> int:
        return sum(row.before_metrics.store_count for row in self.rows)

    @property
    def after_store_total(self) -> int:
        return sum(row.after_metrics.store_count for row in self.rows)

    @property
    def before_alloca_total(self) -> int:
        return sum(row.before_metrics.alloca_count for row in self.rows)

    @property
    def after_alloca_total(self) -> int:
        return sum(row.after_metrics.alloca_count for row in self.rows)

    @property
    def status_histogram(self) -> tuple[tuple[str, int], ...]:
        counts: dict[str, int] = {}
        for row in self.rows:
            counts[row.status.value] = counts.get(row.status.value, 0) + 1
        return tuple(sorted(counts.items()))

    @property
    def collapse_histogram(self) -> tuple[tuple[str, int], ...]:
        counts = {
            "instruction": 0,
            "load": 0,
            "store": 0,
            "alloca": 0,
        }
        for row in self.rows:
            if row.status is not LlvmM2CensusRowStatus.PASSED:
                continue
            delta = row.metric_delta
            counts["instruction"] += int(delta.collapsed_instruction_count)
            counts["load"] += int(delta.collapsed_load_count)
            counts["store"] += int(delta.collapsed_store_count)
            counts["alloca"] += int(delta.collapsed_alloca_count)
        return tuple(sorted(counts.items()))


def m2_census_row_from_pipeline(
    function_name: str,
    maturity: str,
    result: LlvmM2PipelineResult,
) -> LlvmM2CensusRow:
    """Build a census row from the actual composed M2 pipeline result."""
    verification_status = ""
    for phase in result.phases:
        if phase.kind is LlvmM2PipelinePhaseKind.VERIFY_OPTIMIZED:
            if phase.verification_result is not None:
                verification_status = phase.verification_result.status.value
            else:
                verification_status = phase.status.value
            break

    before_metrics = measure_llvm_ir(result.before_ir)
    after_metrics = measure_llvm_ir(result.after_ir)
    return LlvmM2CensusRow(
        function_name=function_name,
        maturity=maturity,
        status=LlvmM2CensusRowStatus(result.status.value),
        present=True,
        lift_supported=True,
        pipeline_status=result.status.value,
        verification_status=verification_status,
        custom_rewrite_count=result.custom_rewrite_count,
        before_metrics=before_metrics,
        after_metrics=after_metrics,
        reason=result.reason,
    )


def m2_missing_row(
    function_name: str,
    maturity: str,
    *,
    reason: str = "function missing",
) -> LlvmM2CensusRow:
    return LlvmM2CensusRow(
        function_name=function_name,
        maturity=maturity,
        status=LlvmM2CensusRowStatus.MISSING,
        present=False,
        lift_supported=False,
        pipeline_status="",
        verification_status="",
        custom_rewrite_count=0,
        before_metrics=measure_llvm_ir(""),
        after_metrics=measure_llvm_ir(""),
        reason=reason,
    )


def m2_lift_unsupported_row(
    function_name: str,
    maturity: str,
    *,
    reason: str,
    ir_text: str = "",
) -> LlvmM2CensusRow:
    return LlvmM2CensusRow(
        function_name=function_name,
        maturity=maturity,
        status=LlvmM2CensusRowStatus.LIFT_UNSUPPORTED,
        present=True,
        lift_supported=False,
        pipeline_status="",
        verification_status="",
        custom_rewrite_count=0,
        before_metrics=measure_llvm_ir(ir_text),
        after_metrics=measure_llvm_ir(""),
        reason=reason,
    )


def summarize_m2_census(rows: tuple[LlvmM2CensusRow, ...]) -> LlvmM2CensusSummary:
    return LlvmM2CensusSummary(rows=rows)
