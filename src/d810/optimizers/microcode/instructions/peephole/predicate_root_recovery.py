"""Pure matching for one certified mixed-width opaque predicate family.

This deliberately does not enter the fixed-width MBA/e-graph island.  Its
single byte extraction is part of the semantic identity, and its replacement
is a boolean predicate rather than a same-width arithmetic value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Any, TypeAlias


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
class Unary:
    op: str
    width: int
    operand: "Expression"
    source: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Binary:
    op: str
    width: int
    left: "Expression"
    right: "Expression | None"
    source: Any = field(default=None, compare=False, repr=False)


Expression: TypeAlias = Constant | Variable | Unary | Binary


@dataclass(frozen=True)
class Predicate:
    op: str
    left: Expression
    right: Expression
    width: int
    source: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class NonzeroRoot:
    width: int


@dataclass(frozen=True)
class SingleTypedInput:
    width: int


@dataclass(frozen=True)
class ByteMaskNormalization:
    input_width: int
    byte_width: int


@dataclass(frozen=True)
class PartitionedAffine:
    carrier: str
    max_mask_bits: int


@dataclass(frozen=True)
class BoundedZeroSet:
    max_models: int


@dataclass(frozen=True)
class Z3EquivalentPredicate:
    timeout_ms: int


@dataclass(frozen=True)
class AllNotEqual:
    """The semantic replacement form; values come from ``BoundedZeroSet``."""

    variable_width: int


@dataclass(frozen=True)
class FiniteZeroSetPredicateMatch:
    """Typed facts derived from a bounded partitioned-affine predicate."""

    variable: Variable
    mask: int
    outside_coefficient: int
    masked_coefficient: int
    constant: int
    excluded_values: tuple[int, ...]


class FiniteZeroSetPredicateRule:
    """Declarative contract for a mixed-width finite-zero-set predicate lift.

    Unlike ``VerifiableRule``, this rule's derived fact is a typed finite set,
    not a scalar named in a match dictionary. The native adapter executes the
    contract in order and refuses to lower if any fact cannot be established.
    """

    PATTERN = NonzeroRoot(width=32)
    CONSTRAINTS = (
        SingleTypedInput(width=32),
        ByteMaskNormalization(input_width=32, byte_width=8),
        PartitionedAffine(carrier="bnot(input)", max_mask_bits=3),
        BoundedZeroSet(max_models=4),
        Z3EquivalentPredicate(timeout_ms=100),
    )
    REPLACEMENT = AllNotEqual(variable_width=32)


def _gcd(left: int, right: int) -> int:
    while right:
        left, right = right, left % right
    return abs(left)


def _inverse_modulo(value: int, modulus: int) -> int | None:
    """Return the inverse for coprime positive operands without host imports."""

    old_r, remainder = value, modulus
    old_s, coefficient = 1, 0
    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_s, coefficient = coefficient, old_s - quotient * coefficient
    if old_r != 1:
        return None
    return old_s % modulus


def _masked_values(mask: int) -> tuple[int, ...]:
    """Enumerate exactly the bit-subsets of one small mask."""

    values: list[int] = []
    subset = mask
    while True:
        values.append(subset)
        if subset == 0:
            return tuple(values)
        subset = (subset - 1) & mask


def solve_masked_affine_zeroes(
    *,
    width: int,
    mask: int,
    outside_coefficient: int,
    masked_coefficient: int,
    constant: int,
    max_mask_bits: int,
) -> tuple[int, ...] | None:
    """Completely solve a small-mask modular-affine predicate without Z3.

    Let ``y = ~input`` and split it as ``q | a``, where ``q & mask == 0``
    and ``a`` is a subset of ``mask``.  This solves every solution of

    ``outside_coefficient*q + masked_coefficient*a + constant == 0``

    modulo ``2**width``.  The returned values are the original ``input``
    values, not ``y``.  Enumerating ``a`` is complete because it ranges only
    over the explicitly bounded mask bits; each remaining linear congruence
    is solved exactly by gcd reduction and modular inversion.
    """

    if (
        type(width) is not int
        or width not in {8, 16, 32, 64}
        or type(mask) is not int
        or mask < 0
        or mask >= (1 << width)
        or type(max_mask_bits) is not int
        or max_mask_bits < 0
        or mask.bit_count() > max_mask_bits
        or any(
            type(value) is not int
            for value in (outside_coefficient, masked_coefficient, constant)
        )
    ):
        return None
    modulus = 1 << width
    coefficient = outside_coefficient % modulus
    if coefficient == 0:
        return None
    divisor = _gcd(coefficient, modulus)
    reduced_modulus = modulus // divisor
    inverse = _inverse_modulo((coefficient // divisor) % reduced_modulus, reduced_modulus)
    if inverse is None:
        return None

    solved: set[int] = set()
    for masked in _masked_values(mask):
        rhs = (-constant - masked_coefficient * masked) % modulus
        if rhs % divisor:
            continue
        base = ((rhs // divisor) * inverse) % reduced_modulus
        for lift in range(divisor):
            outside = base + lift * reduced_modulus
            if outside & mask:
                continue
            complemented_input = outside | masked
            solved.add((~complemented_input) & (modulus - 1))
    return tuple(sorted(solved))


def _constant(node: Expression | None, value: int, width: int) -> bool:
    return isinstance(node, Constant) and node.width == width and node.value == value


def _commuted(node: Expression | None, op: str, left: Expression, right: Expression) -> bool:
    return (
        isinstance(node, Binary)
        and node.op == op
        and node.right is not None
        and ((node.left == left and node.right == right) or (node.left == right and node.right == left))
    )


def _variables(node: Expression | None) -> set[Variable]:
    if isinstance(node, Variable):
        return {node}
    if isinstance(node, Unary):
        return _variables(node.operand)
    if isinstance(node, Binary):
        return _variables(node.left) | _variables(node.right)
    return set()


def _split_scale(node: Expression) -> tuple[int, Expression]:
    """Return a signed coefficient and value, accepting commuted ``mul``."""

    if isinstance(node, Binary) and node.op == "mul" and node.right is not None:
        if isinstance(node.left, Constant) and node.left.width == 32:
            return node.left.value, node.right
        if isinstance(node.right, Constant) and node.right.width == 32:
            return node.right.value, node.left
    return 1, node


def _flatten_signed_terms(node: Expression, sign: int, output: list[tuple[int, Expression]]) -> None:
    if isinstance(node, Binary) and node.width == 32 and node.right is not None and node.op in {"add", "sub"}:
        _flatten_signed_terms(node.left, sign, output)
        _flatten_signed_terms(node.right, sign if node.op == "add" else -sign, output)
        return
    coefficient, value = _split_scale(node)
    output.append((sign * coefficient, value))


def _inverted(variable: Variable) -> Unary:
    return Unary("bnot", 32, variable)


def _byte_mask(node: Expression, variable: Variable) -> int | None:
    if not isinstance(node, Binary) or node.op != "zext" or node.width != 32 or node.right is not None:
        return None
    byte_and = node.left
    if not isinstance(byte_and, Binary) or byte_and.op != "and" or byte_and.width != 8 or byte_and.right is None:
        return None
    if not isinstance(byte_and.right, Constant) or byte_and.right.width != 8:
        return None
    byte_not = byte_and.left
    if not isinstance(byte_not, Unary) or byte_not.op != "bnot" or byte_not.width != 8:
        return None
    low = byte_not.operand
    if not isinstance(low, Unary) or low.op != "low8" or low.width != 8 or low.operand != variable:
        return None
    return byte_and.right.value


def _byte_input_mask(node: Expression, variable: Variable) -> int | None:
    """Recognize ``zext(low8(x) & m8)`` as the typed form of ``x & m``."""

    if not isinstance(node, Binary) or node.op != "zext" or node.width != 32 or node.right is not None:
        return None
    byte_and = node.left
    if not isinstance(byte_and, Binary) or byte_and.op != "and" or byte_and.width != 8 or byte_and.right is None:
        return None
    if not isinstance(byte_and.right, Constant) or byte_and.right.width != 8:
        return None
    low = byte_and.left
    if not isinstance(low, Unary) or low.op != "low8" or low.width != 8 or low.operand != variable:
        return None
    return byte_and.right.value


def _mask_candidates(value: Expression, variable: Variable) -> set[int]:
    """Extract explicit masks from the admissible typed vocabulary only."""

    candidates: set[int] = set()
    inverted = _inverted(variable)
    if isinstance(value, Binary) and value.right is not None and value.width == 32:
        for left, right in ((value.left, value.right), (value.right, value.left)):
            if isinstance(right, Constant) and right.width == 32:
                if value.op == "or" and left == inverted:
                    candidates.add(right.value)
                elif value.op == "and" and left == variable:
                    candidates.add(right.value)
    byte = _byte_mask(value, variable)
    if byte is not None:
        candidates.add(byte)
    byte_input = _byte_input_mask(value, variable)
    if byte_input is not None:
        candidates.add(byte_input)
    return candidates


def _basis(value: Expression, variable: Variable, mask: int) -> str | None:
    inverted = _inverted(variable)
    if value == inverted:
        return "inverted"
    if _commuted(value, "or", inverted, Constant(mask, 32)):
        return "or_mask"
    if _commuted(value, "and", variable, Constant(mask, 32)) or _byte_input_mask(value, variable) == mask:
        return "input_mask"
    if _commuted(value, "and", inverted, Constant((~mask) & 0xFFFFFFFF, 32)):
        return "outside_mask"
    if _commuted(value, "and", inverted, Constant(mask, 32)) or _byte_mask(value, variable) == mask:
        return "inside_mask"
    return None


def recover_finite_zero_set_predicate(
    predicate: Predicate,
    *,
    max_mask_bits: int = 3,
    max_models: int = 4,
) -> FiniteZeroSetPredicateMatch | None:
    """Recover ``expression != 0`` for a bounded partitioned-affine family.

    The accepted expression has exactly one 32-bit input and a byte-safe mask
    vocabulary.  After normalizing ``zext(~low8(x) & m)`` to ``~x & m``, all
    terms must belong to the partition ``q = ~x & ~m`` / ``a = ~x & m``.  The
    returned zero set is solved completely; callers still require an
    independent Z3 equivalence proof before a native mutation.
    """

    if (
        not isinstance(predicate, Predicate)
        or predicate.op != "ne"
        or predicate.width != 1
        or predicate.left.width != 32
        or not _constant(predicate.right, 0, 32)
        or not isinstance(max_models, int)
        or max_models < 1
    ):
        return None
    variables = _variables(predicate.left)
    if len(variables) != 1:
        return None
    variable = next(iter(variables))
    if variable.width != 32:
        return None
    terms: list[tuple[int, Expression]] = []
    _flatten_signed_terms(predicate.left, 1, terms)
    masks = {mask for _, value in terms for mask in _mask_candidates(value, variable)}
    if len(masks) != 1:
        return None
    mask = next(iter(masks))
    if mask <= 0 or mask > 0xFF or mask.bit_count() > max_mask_bits:
        return None

    coefficients = {"inverted": 0, "or_mask": 0, "input_mask": 0, "outside_mask": 0, "inside_mask": 0}
    constant = 0
    for coefficient, value in terms:
        if isinstance(value, Constant) and value.width == 32:
            constant += coefficient * value.value
            continue
        basis = _basis(value, variable, mask)
        if basis is None:
            return None
        coefficients[basis] += coefficient
    # These five terms establish the partitioned-affine identity.  Requiring
    # every part makes the initial native rule deliberately narrow.
    if any(coefficients[name] == 0 for name in coefficients):
        return None
    outside = coefficients["inverted"] + coefficients["or_mask"] + coefficients["outside_mask"]
    inside = coefficients["inverted"] - coefficients["input_mask"] + coefficients["inside_mask"]
    normalized_constant = constant + (coefficients["or_mask"] + coefficients["input_mask"]) * mask
    excluded = solve_masked_affine_zeroes(
        width=32,
        mask=mask,
        outside_coefficient=outside,
        masked_coefficient=inside,
        constant=normalized_constant,
        max_mask_bits=max_mask_bits,
    )
    if excluded is None or not excluded or len(excluded) > max_models:
        return None
    return FiniteZeroSetPredicateMatch(
        variable=variable,
        mask=mask,
        outside_coefficient=outside,
        masked_coefficient=inside,
        constant=normalized_constant,
        excluded_values=excluded,
    )


def z3_proves_finite_zero_set_predicate(
    predicate: Predicate,
    match: FiniteZeroSetPredicateMatch,
) -> bool:
    """Prove the original typed predicate equals the recovered exclusion set.

    This is deliberately independent of the modular-affine solver.  Missing
    Z3, an unsupported operation, a second leaf, or ``unknown`` all deny the
    proof so a native caller can abstain safely.
    """

    try:
        import z3

        if (
            not isinstance(predicate, Predicate)
            or predicate.op != "ne"
            or predicate.width != 1
            or predicate.left.width != 32
            or not _constant(predicate.right, 0, 32)
            or match.variable not in _variables(predicate.left)
        ):
            return False
        native_input = z3.BitVec("finite_zero_set_input", 32)

        def lower(node: Expression) -> object:
            if isinstance(node, Constant):
                return z3.BitVecVal(node.value, node.width)
            if isinstance(node, Variable):
                if node != match.variable or node.width != 32:
                    raise ValueError("unexpected variable")
                return native_input
            if isinstance(node, Unary):
                operand = lower(node.operand)
                if node.op == "bnot":
                    return ~operand
                if node.op == "low8" and node.width == 8:
                    return z3.Extract(7, 0, operand)
                raise ValueError("unsupported unary operation")
            if isinstance(node, Binary):
                left = lower(node.left)
                if node.op == "zext" and node.right is None and node.width == 32:
                    if left.size() != 8:
                        raise ValueError("invalid zext width")
                    return z3.ZeroExt(24, left)
                if node.right is None:
                    raise ValueError("missing binary operand")
                right = lower(node.right)
                operations = {
                    "add": lambda: left + right,
                    "sub": lambda: left - right,
                    "mul": lambda: left * right,
                    "and": lambda: left & right,
                    "or": lambda: left | right,
                }
                operation = operations.get(node.op)
                if operation is None or left.size() != node.width or right.size() != node.width:
                    raise ValueError("unsupported binary operation or width")
                return operation()
            raise ValueError("unsupported expression")

        original = lower(predicate.left) != z3.BitVecVal(0, 32)
        replacement = z3.And(
            *(native_input != z3.BitVecVal(value, 32) for value in match.excluded_values)
        )
        solver = z3.Solver()
        solver.set(timeout=FiniteZeroSetPredicateRule.CONSTRAINTS[-1].timeout_ms)
        solver.add(original != replacement)
        return solver.check() == z3.unsat
    except Exception:
        return False


__all__ = [
    "AllNotEqual",
    "Binary",
    "BoundedZeroSet",
    "ByteMaskNormalization",
    "Constant",
    "Expression",
    "FiniteZeroSetPredicateRule",
    "Predicate",
    "FiniteZeroSetPredicateMatch",
    "NonzeroRoot",
    "PartitionedAffine",
    "Unary",
    "Variable",
    "Z3EquivalentPredicate",
    "recover_finite_zero_set_predicate",
    "solve_masked_affine_zeroes",
    "z3_proves_finite_zero_set_predicate",
]
