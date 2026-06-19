from __future__ import annotations

from d810.backends.llvm import (
    LlvmM2CensusRow,
    LlvmM2CensusRowStatus,
    LlvmM2OracleStatus,
    check_m2_fixture_oracle,
    m2_lift_unsupported_row,
    m2_missing_row,
    measure_llvm_ir,
    m2_oracle_unavailable,
    summarize_m2_census,
)


def _row(name: str, before: str, after: str, rewrites: int = 0) -> LlvmM2CensusRow:
    return LlvmM2CensusRow(
        function_name=name,
        maturity="GLOBAL_ANALYZED",
        status=LlvmM2CensusRowStatus.PASSED,
        present=True,
        lift_supported=True,
        pipeline_status="passed",
        verification_status="passed",
        custom_rewrite_count=rewrites,
        before_metrics=measure_llvm_ir(before),
        after_metrics=measure_llvm_ir(after),
    )


def test_m2_census_summary_aggregates_statuses_and_metrics():
    before = """define i32 @x() {
entry:
  %a = alloca i32, align 4
  %v = load i32, ptr %a, align 4
  store i32 %v, ptr %a, align 4
  ret i32 %v
}
"""
    after = """define i32 @x() {
entry:
  ret i32 0
}
"""
    rows = (
        _row("supported", before, after, rewrites=2),
        m2_missing_row("missing", "GLOBAL_ANALYZED"),
        m2_lift_unsupported_row(
            "unsupported",
            "GLOBAL_ANALYZED",
            reason="unsupported lift",
            ir_text=before,
        ),
    )

    summary = summarize_m2_census(rows)

    assert summary.present_count == 2
    assert summary.missing_count == 1
    assert summary.passed_count == 1
    assert summary.lift_unsupported_count == 1
    assert summary.custom_rewrite_total == 2
    assert ("missing", 1) in summary.status_histogram
    assert ("passed", 1) in summary.status_histogram
    assert ("not_applicable", 3) in summary.oracle_status_histogram
    assert summary.before_instruction_total > summary.after_instruction_total
    assert ("instruction", 1) in summary.collapse_histogram
    assert ("load", 1) in summary.collapse_histogram
    assert ("store", 1) in summary.collapse_histogram
    assert ("alloca", 1) in summary.collapse_histogram


def test_m2_census_row_delta_tracks_no_collapse():
    row = _row(
        "flat",
        """define i32 @x() {
entry:
  ret i32 0
}
""",
        """define i32 @x() {
entry:
  ret i32 0
}
""",
    )

    assert row.metric_delta.instruction_delta == 0
    assert not row.metric_delta.collapsed_instruction_count


def test_m2_census_summary_counts_oracle_status_separately_from_pipeline_status():
    before = """define i32 @x() {
entry:
  ret i32 0
}
"""
    after = """define i32 @x() {
entry:
  ret i32 0
}
"""
    passed_oracle = check_m2_fixture_oracle(
        subject="fixture",
        actual_ir=after,
        expected_ir=after,
        oracle_id="fixture_oracle",
    )
    unavailable_oracle = m2_oracle_unavailable(
        subject="live",
        oracle_id="native_oracle",
        reason="native M3 oracle unavailable",
    )
    rows = (
        LlvmM2CensusRow(
            function_name="fixture",
            maturity="GLOBAL_ANALYZED",
            status=LlvmM2CensusRowStatus.PASSED,
            present=True,
            lift_supported=True,
            pipeline_status="passed",
            verification_status="passed",
            custom_rewrite_count=0,
            before_metrics=measure_llvm_ir(before),
            after_metrics=measure_llvm_ir(after),
            oracle_status=passed_oracle.status,
            oracle_id=passed_oracle.oracle_id,
            oracle_reason=passed_oracle.reason,
        ),
        LlvmM2CensusRow(
            function_name="live",
            maturity="GLOBAL_ANALYZED",
            status=LlvmM2CensusRowStatus.PASSED,
            present=True,
            lift_supported=True,
            pipeline_status="passed",
            verification_status="passed",
            custom_rewrite_count=0,
            before_metrics=measure_llvm_ir(before),
            after_metrics=measure_llvm_ir(after),
            oracle_status=unavailable_oracle.status,
            oracle_id=unavailable_oracle.oracle_id,
            oracle_reason=unavailable_oracle.reason,
        ),
    )

    summary = summarize_m2_census(rows)

    assert summary.passed_count == 2
    assert ("passed", 1) in summary.oracle_status_histogram
    assert ("unavailable", 1) in summary.oracle_status_histogram
    assert rows[1].oracle_status is LlvmM2OracleStatus.UNAVAILABLE
