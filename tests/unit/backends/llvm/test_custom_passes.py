from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    D810_MBA_OR_AND_XOR_ADD_PASS,
    D810_MBA_XOR_OR_SUB_AND_PASS,
    LlvmCustomPass,
    LlvmCustomPassDiagnosticKind,
    LlvmCustomPassStatus,
    LlvmCustomProofResult,
    LlvmOptimizationStatus,
    run_d810_custom_passes,
    run_llvm_opt_pipeline,
)


def _write_fake_opt(tmp_path: Path, body: str) -> Path:
    opt = tmp_path / "opt"
    opt.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    opt.chmod(0o755)
    return opt


def _xor_candidate_ir() -> str:
    return """define i32 @mba(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  ret i32 %out
}
"""


def _or_candidate_ir() -> str:
    return Path(
        "tools/llvm_m2_custom_pass/fixtures/mba_or_and_xor.ll"
    ).read_text(encoding="utf-8")


def test_d810_mba_xor_pass_rewrites_or_sub_and_with_z3_proof():
    result = run_d810_custom_passes(_xor_candidate_ir())

    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.changed
    assert result.after_ir == """define i32 @mba(i32 %x, i32 %y) {
entry:
  %out = xor i32 %x, %y
  ret i32 %out
}
"""
    pass_result = result.pass_results[0]
    assert pass_result.pass_id == D810_MBA_XOR_OR_SUB_AND_PASS.pass_id
    assert pass_result.diagnostics == ()
    assert len(pass_result.rewrites) == 1
    rewrite = pass_result.rewrites[0]
    assert rewrite.result_name == "%out"
    assert rewrite.removed_lines == (
        "  %or = or i32 %x, %y",
        "  %and = and i32 %x, %y",
    )
    assert rewrite.proof.verified is True
    assert rewrite.proof.engine == "d810.backends.mba.z3"
    assert rewrite.proof.bit_width == 32


def test_d810_mba_or_pass_rewrites_and_plus_xor_with_z3_proof():
    result = run_d810_custom_passes(
        _or_candidate_ir(),
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.after_ir == """define i32 @mba_or(i32 %x, i32 %y) {
entry:
  %out = or i32 %x, %y
  ret i32 %out
}
"""
    pass_result = result.pass_results[0]
    assert pass_result.pass_id == D810_MBA_OR_AND_XOR_ADD_PASS.pass_id
    assert pass_result.diagnostics == ()
    assert len(pass_result.rewrites) == 1
    rewrite = pass_result.rewrites[0]
    assert rewrite.rule_name == "Or_MbaRule_1"
    assert rewrite.removed_lines == (
        "  %and = and i32 %x, %y",
        "  %xor = xor i32 %x, %y",
    )
    assert rewrite.proof.verified is True
    assert rewrite.proof.engine == "d810.backends.mba.z3"
    assert rewrite.proof.bit_width == 32


def test_d810_mba_or_pass_rewrites_commuted_add_operands():
    ir = """define i32 @mba_or(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i32 %x, %y
  %out = add i32 %xor, %and
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.PASSED
    assert "  %out = or i32 %x, %y" in result.after_ir
    assert result.pass_results[0].rewrites[0].rule_name == "Or_MbaRule_1_Commuted"


def test_d810_mba_or_pass_preserves_live_producers_used_elsewhere():
    ir = """define i32 @mba_or(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i32 %x, %y
  %out = add i32 %and, %xor
  %keep = add i32 %xor, %and
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.PASSED
    assert "  %and = and i32 %x, %y" in result.after_ir
    assert "  %xor = xor i32 %x, %y" in result.after_ir
    assert "  %out = or i32 %x, %y" in result.after_ir


def test_d810_mba_or_pass_handles_function_local_ssa_names():
    ir = """define i32 @a(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i32 %x, %y
  %out = add i32 %and, %xor
  ret i32 %out
}

define i32 @b(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i32 %x, %y
  %out = add i32 %and, %xor
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.after_ir.count("%out = or i32 %x, %y") == 2
    assert "duplicate SSA definition" not in repr(result.pass_results[0].diagnostics)
    assert len(result.pass_results[0].rewrites) == 2


def test_d810_mba_or_pass_reports_no_change_for_unrelated_add():
    ir = """define i32 @plain(i32 %x, i32 %y) {
entry:
  %out = add i32 %x, %y
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.NO_CHANGE
    assert result.after_ir == ir
    assert result.pass_results[0].rewrites == ()
    assert result.pass_results[0].diagnostics == ()


def test_d810_mba_or_pass_fails_closed_on_width_mismatch():
    ir = """define i32 @bad(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, %y
  %xor = xor i64 %x, %y
  %out = add i32 %and, %xor
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == ir
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.WIDTH_MISMATCH
    )


def test_d810_mba_or_pass_fails_closed_on_constant_operand():
    ir = """define i32 @bad(i32 %x, i32 %y) {
entry:
  %and = and i32 %x, 1
  %xor = xor i32 %x, %y
  %out = add i32 %and, %xor
  ret i32 %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == ir
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE
    )


def test_d810_mba_or_pass_fails_closed_on_vector_type():
    ir = """define <2 x i32> @bad(<2 x i32> %x, <2 x i32> %y) {
entry:
  %and = and <2 x i32> %x, %y
  %xor = xor <2 x i32> %x, %y
  %out = add <2 x i32> %and, %xor
  ret <2 x i32> %out
}
"""

    result = run_d810_custom_passes(
        ir,
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
    )

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE
    )


def test_d810_mba_or_pass_fails_closed_when_proof_fails():
    result = run_d810_custom_passes(
        _or_candidate_ir(),
        passes=(D810_MBA_OR_AND_XOR_ADD_PASS,),
        proof_checker=lambda _bits: LlvmCustomProofResult(
            verified=False,
            reason="injected proof failure",
        ),
    )

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == _or_candidate_ir()
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.PROOF_FAILED
    )
    assert "injected proof failure" in result.pass_results[0].diagnostics[0].reason


def test_d810_mba_xor_pass_preserves_live_producers_used_elsewhere():
    ir = """define i32 @mba(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  %keep = add i32 %or, 1
  ret i32 %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.PASSED
    assert "  %or = or i32 %x, %y" in result.after_ir
    assert "  %and = and i32 %x, %y" not in result.after_ir
    assert "  %out = xor i32 %x, %y" in result.after_ir


def test_d810_mba_xor_pass_handles_function_local_ssa_names():
    ir = """define i32 @a(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  ret i32 %out
}

define i32 @b(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  ret i32 %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.after_ir.count("%out = xor i32 %x, %y") == 2
    assert "duplicate SSA definition" not in repr(result.pass_results[0].diagnostics)
    assert len(result.pass_results[0].rewrites) == 2


def test_d810_mba_xor_pass_ignores_unrelated_sub_using_one_local_producer():
    ir = """define i32 @mixed(i32 %x, i32 %y, i32 %z) {
entry:
  %or = or i32 %x, %y
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  %or2 = or i32 %out, %z
  %other = sub i32 %or2, %x
  ret i32 %other
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.pass_results[0].diagnostics == ()
    assert "  %out = xor i32 %x, %y" in result.after_ir
    assert "  %or2 = or i32 %out, %z" in result.after_ir
    assert "  %other = sub i32 %or2, %x" in result.after_ir


def test_d810_mba_xor_pass_reports_no_change_for_unrelated_ir():
    ir = """define i32 @plain(i32 %x, i32 %y) {
entry:
  %out = add i32 %x, %y
  ret i32 %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.NO_CHANGE
    assert result.after_ir == ir
    assert result.pass_results[0].rewrites == ()
    assert result.pass_results[0].diagnostics == ()


def test_d810_mba_xor_pass_fails_closed_on_width_mismatch():
    ir = """define i32 @bad(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, %y
  %and = and i64 %x, %y
  %out = sub i32 %or, %and
  ret i32 %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == ir
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.WIDTH_MISMATCH
    )


def test_d810_mba_xor_pass_fails_closed_on_constant_operand():
    ir = """define i32 @bad(i32 %x, i32 %y) {
entry:
  %or = or i32 %x, 1
  %and = and i32 %x, %y
  %out = sub i32 %or, %and
  ret i32 %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == ir
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE
    )
    assert "non-SSA" in result.pass_results[0].diagnostics[0].reason


def test_d810_mba_xor_pass_fails_closed_on_vector_type():
    ir = """define <2 x i32> @bad(<2 x i32> %x, <2 x i32> %y) {
entry:
  %or = or <2 x i32> %x, %y
  %and = and <2 x i32> %x, %y
  %out = sub <2 x i32> %or, %and
  ret <2 x i32> %out
}
"""

    result = run_d810_custom_passes(ir)

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE
    )


def test_d810_mba_xor_pass_fails_closed_when_proof_fails():
    result = run_d810_custom_passes(
        _xor_candidate_ir(),
        proof_checker=lambda _bits: LlvmCustomProofResult(
            verified=False,
            reason="injected proof failure",
        ),
    )

    assert result.status is LlvmCustomPassStatus.FAILED
    assert result.after_ir == _xor_candidate_ir()
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.PROOF_FAILED
    )
    assert "injected proof failure" in result.pass_results[0].diagnostics[0].reason


def test_d810_custom_pass_unknown_pass_id_is_skipped():
    result = run_d810_custom_passes(
        _xor_candidate_ir(),
        passes=(LlvmCustomPass(pass_id="unknown", name="Unknown"),),
    )

    assert result.status is LlvmCustomPassStatus.NO_CHANGE
    assert result.after_ir == _xor_candidate_ir()
    assert result.pass_results[0].status is LlvmCustomPassStatus.SKIPPED
    assert result.pass_results[0].diagnostics[0].kind is (
        LlvmCustomPassDiagnosticKind.UNSUPPORTED_SHAPE
    )


def test_d810_custom_pass_default_passes_include_xor_then_or():
    result = run_d810_custom_passes(_or_candidate_ir())

    assert [pass_result.pass_id for pass_result in result.pass_results] == [
        D810_MBA_XOR_OR_SUB_AND_PASS.pass_id,
        D810_MBA_OR_AND_XOR_ADD_PASS.pass_id,
    ]
    assert result.status is LlvmCustomPassStatus.PASSED
    assert result.pass_results[0].status is LlvmCustomPassStatus.NO_CHANGE
    assert result.pass_results[1].status is LlvmCustomPassStatus.PASSED


def test_d810_custom_pass_output_composes_with_stock_opt_runner(tmp_path):
    custom = run_d810_custom_passes(_xor_candidate_ir())
    opt = _write_fake_opt(tmp_path, 'cat "$3" > "$5"\nexit 0\n')

    optimized = run_llvm_opt_pipeline(
        custom.after_ir,
        opt_path=opt,
        tmp_dir=tmp_path / "work",
    )

    assert custom.status is LlvmCustomPassStatus.PASSED
    assert optimized.status is LlvmOptimizationStatus.PASSED
    assert optimized.input_ir == custom.after_ir
    assert optimized.optimized_ir == custom.after_ir
