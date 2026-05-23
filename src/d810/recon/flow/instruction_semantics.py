"""Backend-neutral instruction semantic helpers for recon collectors."""
from __future__ import annotations

from d810.cfg.flowgraph import BranchPredicate, InsnKind


def kind_name(insn: object | None) -> str:
    kind = getattr(insn, "kind", None)
    if isinstance(kind, InsnKind):
        return kind.value
    return str(kind)


def is_kind(insn: object | None, kind: InsnKind, *names: str) -> bool:
    if insn is None:
        return False
    actual = getattr(insn, "kind", None)
    if actual is kind:
        return True
    actual_name = actual.value if isinstance(actual, InsnKind) else str(actual)
    return actual_name in names or actual_name == f"InsnKind.{kind.name}"


def branch_predicate(insn: object | None) -> BranchPredicate | None:
    raw = getattr(insn, "branch_predicate", None)
    if isinstance(raw, BranchPredicate):
        return raw
    if raw is None:
        return None
    try:
        return BranchPredicate(str(raw))
    except ValueError:
        return None


def is_branch(insn: object | None) -> bool:
    return (
        branch_predicate(insn) is not None
        or bool(getattr(insn, "is_conditional_jump", False))
        or is_kind(insn, InsnKind.COND_JUMP, "cond_jump")
        or is_kind(insn, InsnKind.EQUALITY_JUMP, "equality_jump")
    )


def is_goto(insn: object | None) -> bool:
    return bool(getattr(insn, "is_unconditional_jump", False)) or is_kind(
        insn,
        InsnKind.GOTO,
        "goto",
    )


def is_call(insn: object | None) -> bool:
    return bool(getattr(insn, "is_call", False)) or is_kind(
        insn,
        InsnKind.CALL,
        "call",
    )


def comparison_width(insn: object | None) -> int | None:
    try:
        width = int(getattr(insn, "compare_width", 0) or 0)
    except (TypeError, ValueError):
        width = 0
    if width > 0:
        return width
    widths: list[int] = []
    for operand_name in ("l", "r"):
        operand = getattr(insn, operand_name, None)
        try:
            operand_width = int(getattr(operand, "size", 0) or 0)
        except (TypeError, ValueError):
            operand_width = 0
        if operand_width > 0:
            widths.append(operand_width)
    return max(widths) if widths else None


def _mask_for_width(width: int | None) -> int | None:
    if width is None or width <= 0:
        return None
    return (1 << (int(width) * 8)) - 1


def signed_value(value: int, width: int | None) -> int | None:
    mask = _mask_for_width(width)
    if mask is None:
        return None
    bit_count = int(width) * 8
    value &= mask
    sign_bit = 1 << (bit_count - 1)
    return value - (1 << bit_count) if value & sign_bit else value


def evaluate_branch_predicate(
    predicate: BranchPredicate | None,
    left_value: int | None,
    right_value: int | None,
    compare_width: int | None = None,
) -> bool | None:
    if predicate is None:
        return None
    if predicate is BranchPredicate.TRUTHY:
        return None if left_value is None else bool(left_value)
    if left_value is None or right_value is None:
        return None
    left = int(left_value)
    right = int(right_value)
    mask = _mask_for_width(compare_width)
    if predicate is BranchPredicate.EQUAL:
        if mask is not None:
            return (left & mask) == (right & mask)
        return left == right
    if predicate is BranchPredicate.NOT_EQUAL:
        if mask is not None:
            return (left & mask) != (right & mask)
        return left != right
    if mask is None:
        return None
    left_u = left & mask
    right_u = right & mask
    if predicate is BranchPredicate.UNSIGNED_GE:
        return left_u >= right_u
    if predicate is BranchPredicate.UNSIGNED_GT:
        return left_u > right_u
    if predicate is BranchPredicate.UNSIGNED_LE:
        return left_u <= right_u
    if predicate is BranchPredicate.UNSIGNED_LT:
        return left_u < right_u
    left_s = signed_value(left, compare_width)
    right_s = signed_value(right, compare_width)
    if left_s is None or right_s is None:
        return None
    if predicate is BranchPredicate.SIGNED_GE:
        return left_s >= right_s
    if predicate is BranchPredicate.SIGNED_GT:
        return left_s > right_s
    if predicate is BranchPredicate.SIGNED_LE:
        return left_s <= right_s
    if predicate is BranchPredicate.SIGNED_LT:
        return left_s < right_s
    return None


__all__ = [
    "branch_predicate",
    "comparison_width",
    "evaluate_branch_predicate",
    "is_branch",
    "is_call",
    "is_goto",
    "is_kind",
    "kind_name",
    "signed_value",
]
