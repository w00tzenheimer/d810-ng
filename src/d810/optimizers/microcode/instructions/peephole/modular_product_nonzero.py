"""Certified recovery of bounded masked modular-product predicates."""

from __future__ import annotations

from dataclasses import dataclass

from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery import (
    Binary,
    Constant,
    Expression,
    Predicate,
    Unary,
    Variable,
)


_WIDTH = 32
_MASK = (1 << _WIDTH) - 1


@dataclass(frozen=True)
class ModularProductNonzeroMatch:
    """A product's typed factors and its exact 2-adic nonzero budget."""

    variable: Variable
    mask: int
    constant_value: int
    constant_trailing_zeroes: int
    trailing_zero_budget: int
    factors: tuple[Expression, ...]


def _ctz(value: int, width: int = _WIDTH) -> int:
    value &= (1 << width) - 1
    if value == 0:
        return width
    return (value & -value).bit_length() - 1


def _variables(node: Expression | None) -> set[Variable]:
    if isinstance(node, Variable):
        return {node}
    if isinstance(node, Unary):
        return _variables(node.operand)
    if isinstance(node, Binary):
        return _variables(node.left) | _variables(node.right)
    return set()


def _flatten_product(node: Expression, output: list[Expression]) -> None:
    if isinstance(node, Binary) and node.op == "mul" and node.width == _WIDTH and node.right is not None:
        _flatten_product(node.left, output)
        _flatten_product(node.right, output)
        return
    output.append(node)


def _commuted(node: Expression, op: str, left: Expression, right: Expression) -> bool:
    return (
        isinstance(node, Binary)
        and node.op == op
        and node.right is not None
        and ((node.left == left and node.right == right) or (node.left == right and node.right == left))
    )


def _low8_input_mask(node: Expression, variable: Variable) -> int | None:
    if not isinstance(node, Binary) or node.op != "zext" or node.width != _WIDTH or node.right is not None:
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


def _low8_complement_mask(node: Expression, variable: Variable) -> int | None:
    if not isinstance(node, Binary) or node.op != "zext" or node.width != _WIDTH or node.right is not None:
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


def _mask_candidates(factor: Expression, variable: Variable) -> set[int]:
    inverted = Unary("bnot", _WIDTH, variable)
    candidates: set[int] = set()
    if isinstance(factor, Binary) and factor.right is not None and factor.width == _WIDTH:
        for left, right in ((factor.left, factor.right), (factor.right, factor.left)):
            if not isinstance(right, Constant) or right.width != _WIDTH:
                continue
            if factor.op == "or" and left == inverted:
                candidates.add(right.value)
            elif factor.op == "and" and left == variable:
                candidates.add(right.value)
    for candidate in (_low8_input_mask(factor, variable), _low8_complement_mask(factor, variable)):
        if candidate is not None:
            candidates.add(candidate)
    return candidates


def _classify_factor(factor: Expression, variable: Variable, mask: int) -> str | None:
    inverted = Unary("bnot", _WIDTH, variable)
    if factor == inverted:
        return "inverted"
    if _commuted(factor, "or", inverted, Constant(mask, _WIDTH)):
        return "or_mask"
    if _commuted(factor, "and", variable, Constant(mask, _WIDTH)) or _low8_input_mask(factor, variable) == mask:
        return "input_mask"
    if _commuted(factor, "and", inverted, Constant((~mask) & _MASK, _WIDTH)):
        return "outside_mask"
    if _commuted(factor, "and", inverted, Constant(mask, _WIDTH)) or _low8_complement_mask(factor, variable) == mask:
        return "inside_mask"
    return None


def recover_modular_product_nonzero(
    predicate: Predicate,
    *,
    max_mask_bits: int = 3,
) -> ModularProductNonzeroMatch | None:
    """Recover an exact five-factor masked product at a 32-bit nonzero root."""

    if (
        not isinstance(predicate, Predicate)
        or predicate.op != "ne"
        or predicate.width != 1
        or not isinstance(predicate.right, Constant)
        or predicate.right.width != _WIDTH
        or predicate.right.value != 0
        or predicate.left.width != _WIDTH
    ):
        return None
    variables = _variables(predicate.left)
    if len(variables) != 1:
        return None
    variable = next(iter(variables))
    if variable.width != _WIDTH:
        return None
    factors: list[Expression] = []
    _flatten_product(predicate.left, factors)
    symbolic = [factor for factor in factors if not isinstance(factor, Constant)]
    masks = {mask for factor in symbolic for mask in _mask_candidates(factor, variable)}
    if len(masks) != 1:
        return None
    mask = next(iter(masks))
    if mask <= 0 or mask > 0xFF or mask.bit_count() > max_mask_bits:
        return None

    constant_value = 1
    by_kind: dict[str, Expression] = {}
    for factor in factors:
        if isinstance(factor, Constant):
            if factor.width != _WIDTH:
                return None
            constant_value = (constant_value * factor.value) & _MASK
            continue
        kind = _classify_factor(factor, variable, mask)
        if kind is None or kind in by_kind:
            return None
        by_kind[kind] = factor
    if set(by_kind) != {"inverted", "or_mask", "input_mask", "outside_mask", "inside_mask"}:
        return None
    constant_trailing_zeroes = _ctz(constant_value)
    if constant_trailing_zeroes >= _WIDTH:
        return None
    return ModularProductNonzeroMatch(
        variable=variable,
        mask=mask,
        constant_value=constant_value,
        constant_trailing_zeroes=constant_trailing_zeroes,
        trailing_zero_budget=_WIDTH - constant_trailing_zeroes,
        factors=tuple(by_kind[name] for name in ("inverted", "or_mask", "input_mask", "outside_mask", "inside_mask")),
    )


def evaluate_modular_product_nonzero(match: ModularProductNonzeroMatch, input_value: int) -> bool:
    """Evaluate the recovered semantic condition for a concrete 32-bit input."""

    input_value &= _MASK
    inverted = (~input_value) & _MASK
    factors = (
        inverted,
        inverted | match.mask,
        input_value & match.mask,
        inverted & (~match.mask & _MASK),
        inverted & match.mask,
    )
    return all(factor != 0 for factor in factors) and sum(_ctz(factor) for factor in factors) < match.trailing_zero_budget


def z3_proves_modular_product_nonzero(
    predicate: Predicate,
    match: ModularProductNonzeroMatch,
) -> bool:
    """Independently prove the product/nonzero valuation equivalence with Z3."""

    try:
        import z3

        input_value = z3.BitVec("modular_product_input", _WIDTH)

        def lower(node: Expression):
            if isinstance(node, Constant):
                return z3.BitVecVal(node.value, node.width)
            if isinstance(node, Variable):
                if node != match.variable or node.width != _WIDTH:
                    raise ValueError("unexpected variable")
                return input_value
            if isinstance(node, Unary):
                operand = lower(node.operand)
                if node.op == "bnot":
                    return ~operand
                if node.op == "low8" and node.width == 8:
                    return z3.Extract(7, 0, operand)
                raise ValueError("unsupported unary operation")
            if isinstance(node, Binary):
                left = lower(node.left)
                if node.op == "zext" and node.right is None and node.width == _WIDTH:
                    return z3.ZeroExt(24, left)
                if node.right is None:
                    raise ValueError("missing binary operand")
                right = lower(node.right)
                operations = {
                    "mul": lambda: left * right,
                    "and": lambda: left & right,
                    "or": lambda: left | right,
                }
                operation = operations.get(node.op)
                if operation is None or left.size() != node.width or right.size() != node.width:
                    raise ValueError("unsupported binary operation")
                return operation()
            raise ValueError("unsupported expression")

        def ctz(value):
            result = z3.IntVal(_WIDTH)
            for bit in range(_WIDTH - 1, -1, -1):
                result = z3.If(
                    (value & z3.BitVecVal(1 << bit, _WIDTH)) != 0,
                    z3.IntVal(bit),
                    result,
                )
            return result

        original = lower(predicate.left) != z3.BitVecVal(0, _WIDTH)
        lifted_factors = tuple(lower(factor) for factor in match.factors)
        replacement = z3.And(
            *(factor != 0 for factor in lifted_factors),
            sum(ctz(factor) for factor in lifted_factors) < match.trailing_zero_budget,
        )
        solver = z3.Solver()
        solver.set(timeout=250)
        solver.add(original != replacement)
        return solver.check() == z3.unsat
    except Exception:
        return False


__all__ = [
    "ModularProductNonzeroMatch",
    "evaluate_modular_product_nonzero",
    "recover_modular_product_nonzero",
    "z3_proves_modular_product_nonzero",
]
