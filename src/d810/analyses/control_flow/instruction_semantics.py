"Backend-neutral instruction semantic helpers for preanalysis collectors."

from __future__ import annotations

from collections.abc import Sequence

from d810.ir.flowgraph import PredicateKind, InsnKind
from d810.ir.instructions import Instruction
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import StorageIdentity, storage_identity_from_varnode
from d810.ir.varnode import Space, Varnode


def kind_name(insn: object | None) -> str:
    if isinstance(insn, Instruction):
        return getattr(insn.operation, "value", str(insn.operation))
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


def branch_predicate(insn: object | None) -> PredicateKind | None:
    if isinstance(insn, Instruction):
        control = insn.control
        raw = control.predicate if control is not None else None
        return raw if isinstance(raw, PredicateKind) else None
    raw = getattr(insn, "branch_predicate", None)
    if isinstance(raw, PredicateKind):
        return raw
    if raw is None:
        return None
    try:
        return PredicateKind(str(raw))
    except ValueError:
        return None


def is_branch(insn: object | None) -> bool:
    if isinstance(insn, Instruction):
        control = insn.control
        return (
            control is not None
            and control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
        )
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
    if isinstance(insn, Instruction):
        widths = [int(vn.size) for vn in insn.inputs if int(vn.size) > 0]
        return max(widths) if widths else None
    try:
        width = int(getattr(insn, "compare_width", 0) or 0)
    except (TypeError, ValueError):
        width = 0
    if width > 0:
        return width
    return None


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
    predicate: PredicateKind | None,
    left_value: int | None,
    right_value: int | None,
    compare_width: int | None = None,
) -> bool | None:
    if predicate is None:
        return None
    if predicate is PredicateKind.TRUTHY:
        return None if left_value is None else bool(left_value)
    if left_value is None or right_value is None:
        return None
    left = int(left_value)
    right = int(right_value)
    mask = _mask_for_width(compare_width)
    if predicate is PredicateKind.EQ:
        if mask is not None:
            return (left & mask) == (right & mask)
        return left == right
    if predicate is PredicateKind.NE:
        if mask is not None:
            return (left & mask) != (right & mask)
        return left != right
    if mask is None:
        return None
    left_u = left & mask
    right_u = right & mask
    if predicate is PredicateKind.UGE:
        return left_u >= right_u
    if predicate is PredicateKind.UGT:
        return left_u > right_u
    if predicate is PredicateKind.ULE:
        return left_u <= right_u
    if predicate is PredicateKind.ULT:
        return left_u < right_u
    left_s = signed_value(left, compare_width)
    right_s = signed_value(right, compare_width)
    if left_s is None or right_s is None:
        return None
    if predicate is PredicateKind.SGE:
        return left_s >= right_s
    if predicate is PredicateKind.SGT:
        return left_s > right_s
    if predicate is PredicateKind.SLE:
        return left_s <= right_s
    if predicate is PredicateKind.SLT:
        return left_s < right_s
    return None


def _producer_storage_identities(
    instructions: Sequence[Instruction],
    value: Varnode,
    *,
    before_index: int | None,
    seen: frozenset[Varnode],
) -> frozenset[StorageIdentity]:
    identity = storage_identity_from_varnode(value)
    if identity is not None:
        return frozenset({identity})
    if value.space is not Space.TEMP or value in seen:
        return frozenset()

    search_limit = len(instructions) if before_index is None else int(before_index)
    next_seen = frozenset((*seen, value))
    for index in range(search_limit - 1, -1, -1):
        producer = instructions[index]
        if producer.result != value:
            continue
        identities: set[StorageIdentity] = set()
        for source in producer.inputs:
            identities.update(
                _producer_storage_identities(
                    instructions,
                    source,
                    before_index=index,
                    seen=next_seen,
                )
            )
        return frozenset(identities)
    return frozenset()


def storage_identities_for_instruction_input(
    instructions: Sequence[Instruction],
    value: Varnode,
    *,
    before_index: int | None = None,
) -> frozenset[StorageIdentity]:
    """Resolve canonical input storage identities through local temp producers."""
    return _producer_storage_identities(
        instructions,
        value,
        before_index=before_index,
        seen=frozenset(),
    )


def split_const_storage_identity_from_branch(
    instructions: Sequence[Instruction],
    branch_index: int,
    *,
    min_const: int,
    expected_identity: StorageIdentity | None = None,
) -> tuple[int | None, StorageIdentity | None]:
    """Return the large compared constant and storage identity for a branch.

    The branch itself supplies the compared constant.  The storage identity can
    be a direct branch input or a temp input defined by an earlier canonical
    instruction in the same block.
    """
    if branch_index < 0 or branch_index >= len(instructions):
        return None, None
    branch = instructions[int(branch_index)]
    constants = {
        int(source.offset)
        for source in branch.inputs
        if source.space is Space.CONST and int(source.offset) > int(min_const)
    }
    if len(constants) != 1:
        return None, None
    identities: set[StorageIdentity] = set()
    for source in branch.inputs:
        if source.space is Space.CONST:
            continue
        identities.update(
            storage_identities_for_instruction_input(
                instructions,
                source,
                before_index=int(branch_index),
            )
        )
    const_value = next(iter(constants))
    if expected_identity is not None:
        return (
            const_value,
            expected_identity if expected_identity in identities else None,
        )
    if len(identities) == 1:
        return const_value, next(iter(identities))
    return const_value, None


__all__ = [
    "branch_predicate",
    "comparison_width",
    "split_const_storage_identity_from_branch",
    "storage_identities_for_instruction_input",
    "evaluate_branch_predicate",
    "is_branch",
    "is_call",
    "is_goto",
    "is_kind",
    "kind_name",
    "signed_value",
]
