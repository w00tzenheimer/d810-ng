from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    LlvmM2OracleStatus,
    check_m2_fixture_oracle,
    check_m2_post_d810_branchless_oracle,
    llvm_m2_fixture_signature,
    llvm_m2_post_d810_branchless_signature,
    m2_oracle_not_applicable,
    run_llvm_m2_pipeline,
)


FIXTURE_DIR = Path("tools/llvm_m0_roundtrip/fixtures")
POST_D810_FIXTURE_DIR = Path("tools/llvm_m2_post_d810/fixtures")


def _expected_after_ir() -> str:
    return (FIXTURE_DIR / "lab_flat_branchless.after.ll").read_text(encoding="utf-8")


def _before_ir() -> str:
    return (FIXTURE_DIR / "lab_flat_branchless.before.ll").read_text(encoding="utf-8")


def _post_d810_expected_ir() -> str:
    return (
        POST_D810_FIXTURE_DIR / "lab_flat_branchless.structured.after.ll"
    ).read_text(encoding="utf-8")


def _post_d810_actual_ir() -> str:
    return """@state_sink = external global i32
@value_sink = external global i32

define i32 @lab_flat_branchless_m2o(i32 %arg_token) {
entry:
  store volatile i32 -966241705, ptr @state_sink
  %t10 = add i32 %arg_token, 17
  store volatile i32 %t10, ptr @value_sink
  %t139 = and i32 %arg_token, 1
  %t15.not = icmp eq i32 %t139, 0
  br i1 %t15.not, label %bb7, label %bb8

bb5:
  %S12_4.0 = phi i32 [ %t17, %bb8 ], [ %t20, %bb7 ]
  ret i32 %S12_4.0

bb7:
  %t20 = add i32 %arg_token, -34
  store volatile i32 %t20, ptr @value_sink
  store volatile i32 439041101, ptr @state_sink
  br label %bb5

bb8:
  %t17 = xor i32 %t10, 34
  store volatile i32 %t17, ptr @value_sink
  store volatile i32 439041101, ptr @state_sink
  br label %bb5
}
"""


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


def test_post_d810_branchless_oracle_passes_for_structured_signature():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir()

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.PASSED
    assert result.oracle_id == "post_d810_lab_flat_branchless_structured_ir"
    assert result.actual_signature == result.expected_signature
    assert result.actual_signature == (
        "value:base:add_token_17",
        "cfg:branch:eq_zero:true_even:false_odd",
        "value:odd:xor_base_34",
        "value:even:add_token_-34",
        "observable:value_sink:base",
        "observable:value_sink:odd",
        "observable:value_sink:even",
        "observable:state_sink:initial_k0:count=1",
        "observable:state_sink:terminal:count=2",
        "return:phi:odd_even",
    )


def test_post_d810_branchless_oracle_fails_on_swapped_branch_arms():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "br i1 %t15.not, label %bb7, label %bb8",
        "br i1 %t15.not, label %bb8, label %bb7",
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "cfg:branch:eq_zero:true_even:false_odd" not in result.actual_signature
    assert any(
        feature.startswith("cfg:branch:polarity_mismatch")
        for feature in result.actual_signature
    )


def test_post_d810_branchless_oracle_fails_on_swapped_phi_labels():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "%S12_4.0 = phi i32 [ %t17, %bb8 ], [ %t20, %bb7 ]",
        "%S12_4.0 = phi i32 [ %t17, %bb7 ], [ %t20, %bb8 ]",
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "return:phi:odd_even" not in result.actual_signature


def test_post_d810_branchless_signature_rejects_old_m0_mask_fixture():
    assert llvm_m2_post_d810_branchless_signature(_expected_after_ir()) != (
        llvm_m2_post_d810_branchless_signature(_post_d810_expected_ir())
    )


def test_post_d810_branchless_oracle_fails_on_constant_zero_return():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace("ret i32 %S12_4.0", "ret i32 0")

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert result.reason == "post-D810 structured LLVM signature mismatch"
    assert "return:constant_zero" in result.actual_signature
    assert "return:phi:odd_even" not in result.actual_signature


def test_post_d810_branchless_oracle_fails_when_value_sink_disappears():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "  store volatile i32 %t20, ptr @value_sink\n",
        "",
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "observable:value_sink:even" not in result.actual_signature


def test_post_d810_branchless_oracle_fails_when_state_sink_disappears():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "  store volatile i32 439041101, ptr @state_sink\n",
        "",
        1,
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "observable:state_sink:terminal:count=1" in result.actual_signature


def test_post_d810_branchless_oracle_fails_on_wrong_constants():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace("-34", "-35", 1)

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "value:even:add_token_-34" not in result.actual_signature


def test_post_d810_branchless_oracle_fails_on_unexpected_observable_store():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "  store volatile i32 439041101, ptr @state_sink\n",
        "  store volatile i32 439041101, ptr @state_sink\n"
        "  store volatile i32 123, ptr @state_sink\n",
        1,
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "unexpected_observable:state_sink:123" in result.actual_signature


def test_post_d810_branchless_oracle_fails_on_nonvolatile_state_sink_store():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "  store volatile i32 439041101, ptr @state_sink\n",
        "  store volatile i32 439041101, ptr @state_sink\n"
        "  store i32 123, ptr @state_sink\n",
        1,
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "unexpected_observable:state_sink:nonvolatile:123" in (
        result.actual_signature
    )


def test_post_d810_branchless_oracle_fails_when_value_sink_is_nonvolatile():
    expected = _post_d810_expected_ir()
    actual = _post_d810_actual_ir().replace(
        "  store volatile i32 %t20, ptr @value_sink\n",
        "  store i32 %t20, ptr @value_sink\n",
    )

    result = check_m2_post_d810_branchless_oracle(
        subject="lab_flat_branchless",
        actual_ir=actual,
        expected_ir=expected,
        oracle_id="post_d810_lab_flat_branchless_structured_ir",
    )

    assert result.status is LlvmM2OracleStatus.FAILED
    assert "observable:value_sink:even" not in result.actual_signature
    assert "unexpected_observable:value_sink:nonvolatile:%t20" in (
        result.actual_signature
    )
