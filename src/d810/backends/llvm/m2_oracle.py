"""IDA-free M2 oracle/drift DTOs and fixture-level checks."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .optimization import normalize_llvm_ir


class LlvmM2OracleStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class LlvmM2DriftCheckResult:
    status: LlvmM2OracleStatus
    oracle_id: str
    subject: str
    reason: str = ""
    expected_signature: tuple[str, ...] = ()
    actual_signature: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status is LlvmM2OracleStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status is LlvmM2OracleStatus.FAILED

    @property
    def unavailable(self) -> bool:
        return self.status is LlvmM2OracleStatus.UNAVAILABLE

    @property
    def not_applicable(self) -> bool:
        return self.status is LlvmM2OracleStatus.NOT_APPLICABLE


_ALIGN_RE = re.compile(r",\s*align\s+\d+\b")


def llvm_m2_fixture_signature(ir_text: str) -> tuple[str, ...]:
    """Return a narrow optimized-function signature for checked-in M0 fixtures."""
    signature: list[str] = []
    in_function = False
    for raw_line in normalize_llvm_ir(ir_text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("define "):
            in_function = True
            continue
        if not in_function:
            continue
        if line == "}":
            break
        signature.append(_canonical_fixture_line(line))
    return tuple(signature)


def check_m2_fixture_oracle(
    *,
    subject: str,
    actual_ir: str,
    expected_ir: str,
    oracle_id: str,
) -> LlvmM2DriftCheckResult:
    """Compare optimized LLVM IR against a checked-in fixture signature.

    This is an M2 optimized-IR artifact check, not a Hex-Rays pseudocode or
    native execution oracle.
    """
    if not expected_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected optimized LLVM fixture unavailable",
        )
    if not actual_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="actual optimized LLVM IR unavailable",
        )

    expected_shape_error = _single_function_shape_error(
        expected_ir,
        description="expected optimized LLVM fixture",
    )
    if expected_shape_error:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason=expected_shape_error,
        )
    actual_shape_error = _single_function_shape_error(
        actual_ir,
        description="actual optimized LLVM IR",
    )
    if actual_shape_error:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason=actual_shape_error,
        )

    expected_signature = llvm_m2_fixture_signature(expected_ir)
    actual_signature = llvm_m2_fixture_signature(actual_ir)
    if not expected_signature:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected optimized LLVM fixture has no supported function body",
        )
    if not actual_signature:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason="actual optimized LLVM IR has no supported function body",
            expected_signature=expected_signature,
            actual_signature=actual_signature,
        )
    if actual_signature != expected_signature:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason="optimized LLVM fixture signature mismatch",
            expected_signature=expected_signature,
            actual_signature=actual_signature,
        )
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.PASSED,
        oracle_id=oracle_id,
        subject=subject,
        expected_signature=expected_signature,
        actual_signature=actual_signature,
    )


def m2_oracle_not_applicable(
    *,
    subject: str,
    reason: str,
    oracle_id: str = "",
) -> LlvmM2DriftCheckResult:
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.NOT_APPLICABLE,
        oracle_id=oracle_id,
        subject=subject,
        reason=reason,
    )


def m2_oracle_unavailable(
    *,
    subject: str,
    reason: str,
    oracle_id: str,
) -> LlvmM2DriftCheckResult:
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.UNAVAILABLE,
        oracle_id=oracle_id,
        subject=subject,
        reason=reason,
    )


def _canonical_fixture_line(line: str) -> str:
    return " ".join(_ALIGN_RE.sub("", line).split())


def _single_function_shape_error(ir_text: str, *, description: str) -> str:
    function_count = sum(
        1
        for raw_line in normalize_llvm_ir(ir_text).splitlines()
        if raw_line.strip().startswith("define ")
    )
    if function_count > 1:
        return (
            f"{description} must contain exactly one function definition; "
            f"found {function_count}"
        )
    return ""
