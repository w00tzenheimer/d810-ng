from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    LlvmM2OracleStatus,
    check_m2_fixture_oracle,
    llvm_m2_fixture_signature,
    m2_oracle_not_applicable,
    run_llvm_m2_pipeline,
)


FIXTURE_DIR = Path("tools/llvm_m0_roundtrip/fixtures")


def _expected_after_ir() -> str:
    return (FIXTURE_DIR / "lab_flat_branchless.after.ll").read_text(encoding="utf-8")


def _before_ir() -> str:
    return (FIXTURE_DIR / "lab_flat_branchless.before.ll").read_text(encoding="utf-8")


def test_m2_fixture_oracle_passes_for_checked_in_optimized_fixture():
    expected = _expected_after_ir()

    result = check_m2_fixture_oracle(
        subject="lab_flat_branchless",
        actual_ir=expected,
        expected_ir=expected,
        oracle_id="m0_lab_flat_branchless_optimized_ir",
    )

    assert result.status is LlvmM2OracleStatus.PASSED
    assert result.oracle_id == "m0_lab_flat_branchless_optimized_ir"
    assert result.subject == "lab_flat_branchless"
    assert result.actual_signature == result.expected_signature
    assert result.actual_signature


def test_m2_fixture_oracle_checks_pipeline_optimized_output(tmp_path):
    expected_path = tmp_path / "expected-after.ll"
    expected_path.write_text(_expected_after_ir(), encoding="utf-8")
    opt = tmp_path / "opt"
    opt.write_text(
        "#!/bin/sh\n"
        'if [ "$2" = "-passes=verify" ]; then cat "$3"; '
        f'else cat "{expected_path}" > "$5"; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    opt.chmod(0o755)

    pipeline = run_llvm_m2_pipeline(
        _before_ir(),
        opt_path=opt,
        tmp_dir=tmp_path / "m2",
        require_opt=True,
    )
    result = check_m2_fixture_oracle(
        subject="lab_flat_branchless",
        actual_ir=pipeline.after_ir,
        expected_ir=_expected_after_ir(),
        oracle_id="m0_lab_flat_branchless_optimized_ir",
    )

    assert pipeline.passed
    assert result.status is LlvmM2OracleStatus.PASSED


def test_m2_fixture_oracle_fails_on_signature_mismatch():
    expected = _expected_after_ir()
    corrupted = expected.replace("ret i32 %value", "ret i32 %base")

    result = check_m2_fixture_oracle(
        subject="lab_flat_branchless",
        actual_ir=corrupted,
        expected_ir=expected,
        oracle_id="m0_lab_flat_branchless_optimized_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert result.reason == "optimized LLVM fixture signature mismatch"
    assert result.actual_signature != result.expected_signature


def test_m2_fixture_oracle_fails_when_actual_has_extra_function_definition():
    expected = """declare i32 @helper(i32)

define i32 @x(i32 %a) {
entry:
  ret i32 %a
}
"""
    actual = expected + """
define i32 @evil(i32 %a) {
entry:
  ret i32 999
}
"""

    result = check_m2_fixture_oracle(
        subject="x",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="single_function_fixture",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "actual optimized LLVM IR must contain exactly one function" in result.reason


def test_m2_fixture_oracle_reports_unavailable_when_expected_has_extra_function():
    actual = """define i32 @x(i32 %a) {
entry:
  ret i32 %a
}
"""
    expected = actual + """
define i32 @unexpected_expected(i32 %a) {
entry:
  ret i32 999
}
"""

    result = check_m2_fixture_oracle(
        subject="x",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="single_function_fixture",
    )

    assert result.status is LlvmM2OracleStatus.UNAVAILABLE
    assert (
        "expected optimized LLVM fixture must contain exactly one function"
        in result.reason
    )


def test_m2_fixture_oracle_allows_declarations_with_single_definition():
    expected = """declare i32 @helper(i32)

define i32 @x(i32 %a) {
entry:
  %v = call i32 @helper(i32 %a)
  ret i32 %v
}
"""

    result = check_m2_fixture_oracle(
        subject="x",
        actual_ir=expected,
        expected_ir=expected,
        oracle_id="single_function_with_declaration",
    )

    assert result.status is LlvmM2OracleStatus.PASSED


def test_m2_fixture_oracle_reports_unavailable_missing_expected_fixture():
    result = check_m2_fixture_oracle(
        subject="lab_flat_branchless",
        actual_ir=_expected_after_ir(),
        expected_ir="",
        oracle_id="m0_lab_flat_branchless_optimized_ir",
    )

    assert result.status is LlvmM2OracleStatus.UNAVAILABLE
    assert "expected optimized LLVM fixture unavailable" in result.reason


def test_m2_fixture_oracle_reports_unavailable_missing_actual_ir():
    result = check_m2_fixture_oracle(
        subject="lab_flat_branchless",
        actual_ir="",
        expected_ir=_expected_after_ir(),
        oracle_id="m0_lab_flat_branchless_optimized_ir",
    )

    assert result.status is LlvmM2OracleStatus.UNAVAILABLE
    assert "actual optimized LLVM IR unavailable" in result.reason


def test_m2_not_applicable_oracle_is_not_success():
    result = m2_oracle_not_applicable(
        subject="live_lab_row",
        reason="no fixture oracle for live row",
    )

    assert result.status is LlvmM2OracleStatus.NOT_APPLICABLE
    assert not result.passed


def test_m2_fixture_signature_ignores_module_noise_but_keeps_body():
    expected = _expected_after_ir()
    with_different_module = expected.replace(
        "; ModuleID = 'lab_flat_branchless.before.ll'",
        "; ModuleID = '/tmp/volatile/input.ll'",
    )

    assert llvm_m2_fixture_signature(with_different_module) == (
        llvm_m2_fixture_signature(expected)
    )
