"""Shared conditional-jump semantics for read-only reconstruction evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.ir.flowgraph import PredicateKind


@dataclass(frozen=True, slots=True)
class ConditionalJumpOutcome:
    """Path-constant outcome for a conditional jump over observed values."""

    always_taken: bool
    always_not_taken: bool


_SHORT_TO_PREDICATE = {
    "jz": PredicateKind.EQ,
    "jnz": PredicateKind.NE,
    "jcnd": PredicateKind.TRUTHY,
    "jae": PredicateKind.UGE,
    "jb": PredicateKind.ULT,
    "ja": PredicateKind.UGT,
    "jbe": PredicateKind.ULE,
    "jg": PredicateKind.SGT,
    "jge": PredicateKind.SGE,
    "jl": PredicateKind.SLT,
    "jle": PredicateKind.SLE,
}

_PREDICATE_TO_SHORT = {
    PredicateKind.EQ: "jz",
    PredicateKind.NE: "jnz",
    PredicateKind.TRUTHY: "jcnd",
    PredicateKind.UGE: "jae",
    PredicateKind.ULT: "jb",
    PredicateKind.UGT: "ja",
    PredicateKind.ULE: "jbe",
    PredicateKind.SGT: "jg",
    PredicateKind.SGE: "jge",
    PredicateKind.SLT: "jl",
    PredicateKind.SLE: "jle",
}

_NUMERIC_JUMP_ALIASES = {
    "op_44": "jz",
    "op_45": "jnz",
    "op_49": "jg",
    "op_50": "jge",
    "op_47": "jl",
    "op_48": "jle",
}


def conditional_operand_size(*mops: object | None) -> int:
    """Return the first concrete operand size, defaulting to dword semantics."""

    for mop in mops:
        size = getattr(mop, "size", None)
        if size is not None:
            try:
                return max(1, int(size))
            except (TypeError, ValueError):
                pass
    return 4


def conditional_jump_opcode_name(
    opcode: object,
    *,
    opcode_names: Mapping[object, object] | None = None,
) -> str | None:
    """Normalize a portable predicate token to a canonical short branch name.

    Backend adapters may pass numeric opcode aliases through ``opcode_names``.
    Portable consumers should pass :class:`PredicateKind` directly.
    """

    if opcode_names is not None and opcode in opcode_names:
        opcode = opcode_names[opcode]
    if isinstance(opcode, PredicateKind):
        return _PREDICATE_TO_SHORT.get(opcode)
    if isinstance(opcode, str):
        token = opcode.lower()
    else:
        try:
            token = f"op_{int(opcode)}"
        except (TypeError, ValueError):
            return None
    if token in _SHORT_TO_PREDICATE:
        return token
    return _NUMERIC_JUMP_ALIASES.get(token)


def conditional_jump_taken(
    opcode: object,
    left_value: int,
    right_value: int = 0,
    *,
    operand_size: int = 4,
    opcode_names: Mapping[object, str] | None = None,
) -> bool | None:
    """Evaluate whether a conditional jump is taken for concrete operands."""

    kind = conditional_jump_opcode_name(opcode, opcode_names=opcode_names)
    if kind is None:
        return None

    left = int(left_value)
    right = int(right_value)
    if kind == "jz":
        return left == right
    if kind == "jnz":
        return left != right
    if kind == "jcnd":
        return left != 0

    mask = _mask_for_size(operand_size)
    left_unsigned = left & mask
    right_unsigned = right & mask

    if kind == "jae":
        return left_unsigned >= right_unsigned
    if kind == "jb":
        return left_unsigned < right_unsigned
    if kind == "ja":
        return left_unsigned > right_unsigned
    if kind == "jbe":
        return left_unsigned <= right_unsigned

    left_signed = _signed(left, operand_size)
    right_signed = _signed(right, operand_size)
    if kind == "jg":
        return left_signed > right_signed
    if kind == "jge":
        return left_signed >= right_signed
    if kind == "jl":
        return left_signed < right_signed
    if kind == "jle":
        return left_signed <= right_signed
    return None


def predicate_jump_taken(
    predicate: PredicateKind | str | None,
    left_value: int,
    right_value: int = 0,
    *,
    operand_size: int = 4,
) -> bool | None:
    """Evaluate whether a portable predicate branch is taken.

    This is the canonical analysis surface. Backend adapters may still
    translate raw jump opcodes into :class:`PredicateKind`, but portable passes
    should not traffic in vendor opcode names.
    """
    if predicate is None:
        return None
    if not isinstance(predicate, PredicateKind):
        try:
            predicate = PredicateKind(str(predicate))
        except ValueError:
            return None

    left = int(left_value)
    right = int(right_value)

    if predicate is PredicateKind.EQ:
        return left == right
    if predicate is PredicateKind.NE:
        return left != right
    if predicate is PredicateKind.TRUTHY:
        return left != 0

    mask = _mask_for_size(operand_size)
    left_unsigned = left & mask
    right_unsigned = right & mask

    if predicate is PredicateKind.UGE:
        return left_unsigned >= right_unsigned
    if predicate is PredicateKind.ULT:
        return left_unsigned < right_unsigned
    if predicate is PredicateKind.UGT:
        return left_unsigned > right_unsigned
    if predicate is PredicateKind.ULE:
        return left_unsigned <= right_unsigned

    left_signed = _signed(left, operand_size)
    right_signed = _signed(right, operand_size)
    if predicate is PredicateKind.SGT:
        return left_signed > right_signed
    if predicate is PredicateKind.SGE:
        return left_signed >= right_signed
    if predicate is PredicateKind.SLT:
        return left_signed < right_signed
    if predicate is PredicateKind.SLE:
        return left_signed <= right_signed
    return None


def conditional_jump_outcome_for_values(
    opcode: object,
    observed_values: Sequence[int],
    compared_value: int,
    *,
    operand_size: int = 4,
    opcode_names: Mapping[object, str] | None = None,
) -> ConditionalJumpOutcome | None:
    """Classify whether every observed value chooses the same branch."""

    if not observed_values:
        return None

    decisions: list[bool] = []
    for value in observed_values:
        taken = conditional_jump_taken(
            opcode,
            int(value),
            int(compared_value),
            operand_size=operand_size,
            opcode_names=opcode_names,
        )
        if taken is None:
            return None
        decisions.append(taken)

    return ConditionalJumpOutcome(
        always_taken=all(decisions),
        always_not_taken=not any(decisions),
    )


def conditional_jump_outcome_for_predicate(
    predicate: PredicateKind | str | None,
    observed_values: Sequence[int],
    compared_value: int,
    *,
    operand_size: int = 4,
) -> ConditionalJumpOutcome | None:
    """Classify whether every observed value chooses the same predicate arm."""
    if not observed_values:
        return None

    decisions: list[bool] = []
    for value in observed_values:
        taken = predicate_jump_taken(
            predicate,
            int(value),
            int(compared_value),
            operand_size=operand_size,
        )
        if taken is None:
            return None
        decisions.append(taken)

    return ConditionalJumpOutcome(
        always_taken=all(decisions),
        always_not_taken=not any(decisions),
    )


def _signed(value: int, size: int) -> int:
    bits = max(1, int(size)) * 8
    mask = (1 << bits) - 1
    value &= mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _mask_for_size(size: int) -> int:
    bits = max(1, int(size)) * 8
    return (1 << bits) - 1


__all__ = [
    "ConditionalJumpOutcome",
    "conditional_jump_opcode_name",
    "conditional_jump_outcome_for_predicate",
    "conditional_jump_outcome_for_values",
    "conditional_jump_taken",
    "conditional_operand_size",
    "predicate_jump_taken",
]
