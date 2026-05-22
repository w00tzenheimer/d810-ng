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
    return branch_predicate(insn) is not None or bool(
        getattr(insn, "is_conditional_jump", False)
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


def signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def evaluate_branch_predicate(
    predicate: BranchPredicate | None,
    left_value: int | None,
    right_value: int | None,
) -> bool | None:
    if predicate is None:
        return None
    if predicate is BranchPredicate.TRUTHY:
        return None if left_value is None else bool(left_value)
    if left_value is None or right_value is None:
        return None
    left = int(left_value)
    right = int(right_value)
    if predicate is BranchPredicate.EQUAL:
        return left == right
    if predicate is BranchPredicate.NOT_EQUAL:
        return left != right
    left_u = left & 0xFFFFFFFFFFFFFFFF
    right_u = right & 0xFFFFFFFFFFFFFFFF
    if predicate is BranchPredicate.UNSIGNED_GE:
        return left_u >= right_u
    if predicate is BranchPredicate.UNSIGNED_GT:
        return left_u > right_u
    if predicate is BranchPredicate.UNSIGNED_LE:
        return left_u <= right_u
    if predicate is BranchPredicate.UNSIGNED_LT:
        return left_u < right_u
    left_s = signed32(left)
    right_s = signed32(right)
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
    "evaluate_branch_predicate",
    "is_branch",
    "is_call",
    "is_goto",
    "is_kind",
    "kind_name",
    "signed32",
]
