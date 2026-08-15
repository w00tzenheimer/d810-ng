"""Strict structural recognition for the 64-bit multiply/shift rotate idiom.

This module deliberately contains no Hex-Rays imports.  The native adapter
converts microcode operands into these small immutable nodes, lets this matcher
prove the exact shared-base shape, and only then lowers the result to a rotate
helper call.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Any, TypeAlias


MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Constant:
    value: int
    width: int
    source: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Variable:
    name: str
    width: int
    source: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Binary:
    op: str
    width: int
    left: "Expression"
    right: "Expression"
    source: Any = field(default=None, compare=False, repr=False)


Expression: TypeAlias = Constant | Variable | Binary


@dataclass(frozen=True)
class RotateIdiomMatch:
    """A fully-checked ``__ROL8__(base, rotation)`` recovery candidate."""

    base: Binary
    rotation: int
    duplicated_value: Expression


def _commuted_mul_constant_and_value(node: Expression) -> tuple[Constant, Expression] | None:
    if not isinstance(node, Binary) or node.op != "mul" or node.width != 64:
        return None
    if isinstance(node.left, Constant) and node.left.width == 64 and node.right.width == 64:
        return node.left, node.right
    if isinstance(node.right, Constant) and node.right.width == 64 and node.left.width == 64:
        return node.right, node.left
    return None


def _match_half(shifted_product: Expression, right_shift: Expression) -> RotateIdiomMatch | None:
    if not isinstance(right_shift, Binary) or right_shift.op != "shr" or right_shift.width != 64:
        return None
    # Hex-Rays represents native shift counts as a one-byte (8-bit) mop.
    # Value-bearing operands remain exactly 64-bit; accepting a 32/64-bit
    # count here would admit a different, verifier-sensitive instruction form.
    if not isinstance(right_shift.right, Constant) or right_shift.right.width != 8:
        return None

    shift = right_shift.right.value
    if not 1 <= shift < 64:
        return None
    rotation = 64 - shift

    shifted = _commuted_mul_constant_and_value(shifted_product)
    base = _commuted_mul_constant_and_value(right_shift.left)
    if shifted is None or base is None:
        return None
    shifted_constant, shifted_value = shifted
    base_constant, base_value = base
    if shifted_value != base_value:
        return None
    if shifted_constant.value != ((base_constant.value << rotation) & MASK64):
        return None

    return RotateIdiomMatch(
        base=Binary("mul", 64, Constant(base_constant.value, 64), base_value, right_shift.left.source),
        rotation=rotation,
        duplicated_value=shifted_value,
    )


def match_rol64_idiom(expression: Expression) -> RotateIdiomMatch | None:
    """Recognize exactly ``mul(C<<r, x) | lshr(mul(C, x), 64-r)``.

    Only commutation of the outer ``or`` and either multiplication is allowed.
    Every value-bearing node is 64-bit; the fixed shift literal is the native
    one-byte microcode count.  Nothing algebraically similar is accepted.
    """

    if not isinstance(expression, Binary) or expression.op != "or" or expression.width != 64:
        return None
    return _match_half(expression.left, expression.right) or _match_half(
        expression.right, expression.left
    )


__all__ = [
    "Binary",
    "Constant",
    "Expression",
    "RotateIdiomMatch",
    "Variable",
    "match_rol64_idiom",
]
