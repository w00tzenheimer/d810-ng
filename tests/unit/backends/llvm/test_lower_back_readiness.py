from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    LlvmLowerBackParseDiagnosticKind,
    LlvmLowerBackParseStatus,
    LlvmLowerBackReadinessStatus,
    LlvmLowerBackStatus,
    LlvmLowerBackTerminatorKind,
    LlvmLowerBackUnsupportedKind,
    assess_lower_back_readiness,
    parse_lower_back_function,
)


_TINY_PHI = (
    Path(__file__).parents[4]
    / "tools"
    / "llvm_m3_lowerback"
    / "fixtures"
    / "tiny_phi.ll"
)


def _unsupported_kinds(result):
    assert result.plan_result is not None
    return tuple(reason.kind for reason in result.plan_result.unsupported)


def _parse_diag_kinds(result):
    return tuple(diag.kind for diag in result.parse_result.diagnostics)


def test_tiny_phi_fixture_parses_and_plans_edge_moves():
    parse = parse_lower_back_function(_TINY_PHI.read_text(encoding="utf-8"))

    assert parse.status is LlvmLowerBackParseStatus.PARSED
    assert parse.function is not None
    assert parse.function.name == "tiny_phi"
    assert tuple(block.label for block in parse.function.blocks) == (
        "entry",
        "then",
        "else",
        "merge",
    )

    readiness = assess_lower_back_readiness(_TINY_PHI.read_text(encoding="utf-8"))

    assert readiness.status is LlvmLowerBackReadinessStatus.PLANNED
    assert readiness.plan_result is not None
    assert readiness.plan_result.status is LlvmLowerBackStatus.PLANNED
    assert readiness.plan_result.plan is not None
    assert tuple(
        (move.predecessor, move.successor, move.insertion_block, move.target.name, move.value.name)
        for move in readiness.plan_result.plan.edge_moves
    ) == (
        ("then", "merge", "then", "x", "a"),
        ("else", "merge", "else", "x", "b"),
    )


def test_ret_only_optimized_function_parses_and_plans():
    readiness = assess_lower_back_readiness(
        "define i32 @collapsed() { ret i32 0 }\n"
    )

    assert readiness.status is LlvmLowerBackReadinessStatus.PLANNED
    assert readiness.parse_result.function is not None
    assert readiness.parse_result.function.name == "collapsed"
    assert readiness.plan_result is not None
    assert readiness.plan_result.plan is not None
    assert readiness.plan_result.plan.block_order == ("entry",)


def test_unreachable_optimized_function_parses_but_fails_closed():
    cases = (
        "define i32 @dead() { unreachable }\n",
        """define i32 @dead() {
entry:
  unreachable
}
""",
    )

    for ir in cases:
        readiness = assess_lower_back_readiness(ir)

        assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED
        assert readiness.parse_result.diagnostics == ()
        assert readiness.parse_result.function is not None
        assert (
            readiness.parse_result.function.blocks[0].terminator.kind
            is LlvmLowerBackTerminatorKind.UNREACHABLE
        )
        assert _unsupported_kinds(readiness) == (
            LlvmLowerBackUnsupportedKind.UNSUPPORTED_CONTROL,
        )


def test_unsupported_return_types_fail_closed():
    cases = (
        "define <4 x i32> @v() { ret <4 x i32> zeroinitializer }\n",
        "define float @f() { ret float 1.0 }\n",
        "define i32 @b() { ret nonsense }\n",
    )

    for ir in cases:
        readiness = assess_lower_back_readiness(ir)

        assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
        assert readiness.plan_result is None
        assert _parse_diag_kinds(readiness) == (
            LlvmLowerBackParseDiagnosticKind.MALFORMED_RETURN,
        )


def test_void_return_parses_and_plans():
    readiness = assess_lower_back_readiness("define void @done() { ret void }\n")

    assert readiness.status is LlvmLowerBackReadinessStatus.PLANNED


def test_multiple_terminators_fail_parse():
    ir = """define i32 @multi_term() {
entry:
  br label %a
  ret i32 0
a:
  ret i32 1
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
    assert readiness.plan_result is None
    assert _parse_diag_kinds(readiness) == (
        LlvmLowerBackParseDiagnosticKind.MULTIPLE_TERMINATORS,
    )


def test_instruction_after_terminator_fails_parse():
    ir = """define i32 @after_term(i32 %x, i32 %y) {
entry:
  br label %a
  %z = add i32 %x, %y
a:
  ret i32 1
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
    assert readiness.plan_result is None
    assert _parse_diag_kinds(readiness) == (
        LlvmLowerBackParseDiagnosticKind.INSTRUCTION_AFTER_TERMINATOR,
    )


def test_critical_edge_phi_fixture_parses_and_plans_bridge():
    ir = """define i32 @critical(i1 %cond, i32 %a, i32 %b) {
entry:
  br i1 %cond, label %merge, label %side
side:
  br label %merge
merge:
  %x = phi i32 [ %a, %entry ], [ %b, %side ]
  ret i32 %x
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PLANNED
    assert readiness.plan_result is not None
    assert readiness.plan_result.plan is not None
    assert tuple(
        (bridge.label, bridge.predecessor, bridge.successor)
        for bridge in readiness.plan_result.plan.bridge_blocks
    ) == (("m3_split__entry__merge", "entry", "merge"),)


def test_unsupported_memory_and_call_from_optimized_ir_fail_closed():
    ir = """define i32 @effects(ptr %p) {
entry:
  %x = load i32, ptr %p, align 4
  %y = call i32 @opaque(i32 %x)
  ret i32 %y
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED
    assert _unsupported_kinds(readiness) == (
        LlvmLowerBackUnsupportedKind.UNSUPPORTED_MEMORY,
        LlvmLowerBackUnsupportedKind.UNSUPPORTED_CALL,
    )


def test_unknown_scalar_opcode_fails_closed():
    ir = """define i32 @bad(i32 %x, i32 %y) {
entry:
  %z = fdiv i32 %x, %y
  ret i32 %z
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED
    assert _unsupported_kinds(readiness) == (
        LlvmLowerBackUnsupportedKind.UNSUPPORTED_INSTRUCTION,
    )


def test_vector_operation_fails_closed():
    ir = """define i32 @vector(<4 x i32> %x, <4 x i32> %y) {
entry:
  %z = add <4 x i32> %x, %y
  ret i32 0
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
    assert readiness.plan_result is None
    assert _parse_diag_kinds(readiness) == (
        LlvmLowerBackParseDiagnosticKind.MALFORMED_INSTRUCTION,
    )


def test_malformed_supported_scalar_body_instructions_fail_parse():
    cases = (
        """define i32 @bad(i32 %x) {
entry:
  %z = add i32 %x
  ret i32 %z
}
""",
        """define i32 @bad(i32 %x, i32 %y, i32 %w) {
entry:
  %z = add i32 %x, %y, %w
  ret i32 %z
}
""",
        """define i1 @bad(i32 %x) {
entry:
  %z = icmp eq i32 %x
  ret i1 %z
}
""",
        """define i32 @bad(i8 %x) {
entry:
  %z = zext i8 %x
  ret i32 %z
}
""",
    )

    for ir in cases:
        readiness = assess_lower_back_readiness(ir)

        assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
        assert readiness.plan_result is None
        assert _parse_diag_kinds(readiness) == (
            LlvmLowerBackParseDiagnosticKind.MALFORMED_INSTRUCTION,
        )


def test_unknown_branch_target_fails_closed_in_planner():
    ir = """define void @bad_branch() {
entry:
  br label %missing
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED
    assert _unsupported_kinds(readiness) == (
        LlvmLowerBackUnsupportedKind.UNKNOWN_BLOCK_TARGET,
    )


def test_malformed_line_is_parse_failure_not_fake_plan():
    ir = """define i32 @malformed() {
entry:
  this is not llvm
  ret i32 0
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
    assert readiness.plan_result is None
    assert tuple(diag.kind for diag in readiness.parse_result.diagnostics) == (
        LlvmLowerBackParseDiagnosticKind.MALFORMED_INSTRUCTION,
    )


def test_missing_phi_incoming_fails_planner():
    ir = """define i32 @bad(i1 %c, i32 %a, i32 %b) {
entry:
  br i1 %c, label %then, label %else
then:
  br label %merge
else:
  br label %merge
merge:
  %x = phi i32 [ %a, %then ]
  ret i32 %x
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.UNSUPPORTED
    assert _unsupported_kinds(readiness) == (
        LlvmLowerBackUnsupportedKind.PHI_PREDECESSOR_MISMATCH,
    )


def test_partially_parsed_phi_incoming_fails_parse():
    ir = """define i32 @bad(i1 %c, i32 %a, i32 %b) {
entry:
  br i1 %c, label %then, label %else
then:
  br label %merge
else:
  br label %merge
merge:
  %x = phi i32 [ %a, %then ], garbage
  ret i32 %x
}
"""

    readiness = assess_lower_back_readiness(ir)

    assert readiness.status is LlvmLowerBackReadinessStatus.PARSE_FAILED
    assert readiness.plan_result is None
    assert _parse_diag_kinds(readiness) == (
        LlvmLowerBackParseDiagnosticKind.MALFORMED_PHI,
    )
