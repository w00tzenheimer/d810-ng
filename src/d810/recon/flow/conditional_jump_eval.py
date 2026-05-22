"""Shared conditional-jump semantics for read-only reconstruction evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConditionalJumpOutcome:
    """Path-constant outcome for a conditional jump over observed values."""

    always_taken: bool
    always_not_taken: bool


_JUMP_ALIASES = {
    "m_jz": "jz",
    "jz": "jz",
    "op_44": "jz",
    "m_jnz": "jnz",
    "jnz": "jnz",
    "op_45": "jnz",
    "m_jcnd": "jcnd",
    "jcnd": "jcnd",
    "m_jae": "jae",
    "jae": "jae",
    "m_jb": "jb",
    "jb": "jb",
    "m_ja": "ja",
    "ja": "ja",
    "m_jbe": "jbe",
    "jbe": "jbe",
    "m_jg": "jg",
    "jg": "jg",
    "op_49": "jg",
    "m_jge": "jge",
    "jge": "jge",
    "op_50": "jge",
    "m_jl": "jl",
    "jl": "jl",
    "op_47": "jl",
    "m_jle": "jle",
    "jle": "jle",
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
    opcode_names: Mapping[object, str] | None = None,
) -> str | None:
    """Normalize a conditional-jump opcode token to a canonical short name."""

    if opcode_names is not None and opcode in opcode_names:
        opcode = opcode_names[opcode]
    if isinstance(opcode, str):
        token = opcode.lower()
    else:
        try:
            token = f"op_{int(opcode)}"
        except (TypeError, ValueError):
            return None
    return _JUMP_ALIASES.get(token)


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
    "conditional_jump_outcome_for_values",
    "conditional_jump_taken",
    "conditional_operand_size",
]
