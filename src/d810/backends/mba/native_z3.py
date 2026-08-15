"""One fixed-width native-AST equivalence gate for MBA candidates."""

from __future__ import annotations

from collections.abc import Mapping

from d810.backends.mba.hexrays_island import lower_hexrays_island
from d810.core.typing import Any
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term


_COMPLEMENT_MASK_HODUR_CERTIFICATE = "complement-mask-hodur-v1"


def prove_native_ast_equivalence(
    original: Any,
    replacement: Any,
    *,
    width: int,
    known_constants: Mapping[tuple[object, ...], int] | None = None,
    certificate: str | None = None,
) -> bool:
    """Prove two same-width supported native ASTs equal with bit-vector Z3.

    Both trees first pass through the native island lowerer at exactly this
    destination width. Casts, truncations, shifts, unsupported opcodes, and
    mixed-width trees therefore fail closed before Z3 sees a term.

    ``known_constants`` is an optional set of exact live leaf identities from
    a converged cross-block constant environment. Every supplied key must
    occur in the original/replacement proof and is constrained to its value;
    an unknown key, invalid width, or malformed value rejects the proof.
    """

    if type(width) is not int or width not in {8, 16, 32, 64}:
        return False
    try:
        import z3

        destination_size = width // 8
        assumptions = dict(known_constants or {})
        if any(type(value) is not int for value in assumptions.values()):
            return False
        original_lowering = lower_hexrays_island(
            original,
            destination_size=destination_size,
        )
        replacement_lowering = lower_hexrays_island(
            replacement,
            destination_size=destination_size,
        )
        if original_lowering.term is None or replacement_lowering.term is None:
            return False

        variables: dict[object, Any] = {}
        observed_leaf_keys: set[object] = set()

        def visit(node: Any) -> Any:
            if node.width != width:
                raise ValueError("mixed-width typed term")
            if node.operation is None:
                if node.value is not None:
                    return z3.BitVecVal(int(node.value), width)
                if node.leaf_key is None:
                    raise ValueError("missing typed leaf identity")
                key = node.leaf_key
                observed_leaf_keys.add(key)
                if key in assumptions:
                    return z3.BitVecVal(
                        assumptions[key] & ((1 << width) - 1),
                        width,
                    )
                return variables.setdefault(
                    key,
                    z3.BitVec(f"native_mba_leaf_{len(variables)}", width),
                )
            children = tuple(visit(child) for child in node.children)
            if len(children) not in {1, 2}:
                raise ValueError("invalid typed operator arity")
            left = children[0]
            right = children[1] if len(children) == 2 else None
            operations = {
                "add": lambda: left + right,
                "sub": lambda: left - right,
                "mul": lambda: left * right,
                "and": lambda: left & right,
                "or": lambda: left | right,
                "xor": lambda: left ^ right,
                "neg": lambda: -left,
                "bnot": lambda: ~left,
            }
            operation = operations.get(node.operation)
            if operation is None:
                raise ValueError("unsupported typed operation")
            return operation()

        original_term = visit(original_lowering.term)
        replacement_term = visit(replacement_lowering.term)
        if not set(assumptions).issubset(observed_leaf_keys):
            return False
        solver = z3.Solver()
        solver.set(timeout=50)
        solver.add(original_term != replacement_term)
        if solver.check() == z3.unsat:
            return True
        if certificate == _COMPLEMENT_MASK_HODUR_CERTIFICATE:
            return _prove_complement_mask_hodur_native_certificate(
                original_lowering.term,
                replacement_lowering.term,
                width=width,
            )
        return False
    except Exception:
        return False


def _constant(value: int, width: int) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=width, value=value)


def _unary(operation: str, operand: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(
        operation=operation,
        width=operand.width,
        children=(operand,),
    )


def _binary(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm,
) -> TypedBvTerm:
    return TypedBvTerm(
        operation=operation,
        width=left.width,
        children=(left, right),
    )


def _prove_complement_mask_hodur_native_certificate(
    original: TypedBvTerm,
    replacement: TypedBvTerm,
    *,
    width: int,
) -> bool:
    """Discharge the bounded native proof plan for the Hodur residual.

    The direct 64-bit bit-blast of this seven-operator expression is known to
    return ``unknown`` under the mandatory 50 ms native-Z3 bound.  This plan
    first requires the *lowered native terms* to be exactly the certified rule
    instantiation, then asks Z3 to prove the Boolean partition identities and
    the reduced modular-linear obligation separately.  It does not trust an
    extractor result, a rule name, or host-side arithmetic alone.
    """

    if width not in {8, 16, 32, 64}:
        return False
    if (
        replacement.operation != "sub"
        or len(replacement.children) != 2
        or replacement.children[1].value is None
    ):
        return False
    value, mask = replacement.children
    if value.operation is not None or value.leaf_key is None:
        return False
    complement = _constant(~int(mask.value), width)
    two, three, four = (_constant(number, width) for number in (2, 3, 4))
    masked = _binary("and", mask, value)
    complement_masked = _binary("and", complement, value)
    expected = _binary(
        "sub",
        _binary(
            "sub",
            _binary(
                "sub",
                _binary(
                    "add",
                    _binary("mul", four, _unary("bnot", masked)),
                    _binary(
                        "sub",
                        _binary("mul", two, masked),
                        _binary("mul", three, complement_masked),
                    ),
                ),
                _binary("mul", two, _unary("bnot", complement_masked)),
            ),
            _binary("mul", two, _unary("bnot", _binary("or", mask, value))),
        ),
        _binary("mul", three, _unary("bnot", _binary("or", complement, value))),
    )
    if canonicalize_ac_term(original) != canonicalize_ac_term(expected):
        return False
    try:
        import z3

        native_value = z3.BitVec("native_certificate_value", width)
        native_mask = z3.BitVecVal(int(mask.value), width)
        native_complement = ~native_mask
        native_masked = native_value & native_mask
        native_complement_masked = native_value & native_complement

        def prove(formula: Any) -> bool:
            solver = z3.Solver()
            solver.set(timeout=50)
            solver.add(formula)
            return solver.check() == z3.unsat

        if not prove(native_masked + native_complement_masked != native_value):
            return False
        if not prove(
            (native_value | native_mask)
            != native_mask + native_complement_masked
        ):
            return False
        if not prove(
            (native_value | native_complement)
            != native_complement + native_masked
        ):
            return False

        # The final native-Z3 obligation has no bitwise operators left.  Z3
        # proves it over unconstrained symbolic partition values plus the
        # already-proved partition equation, so it remains bounded at 64-bit.
        reduced_mask, reduced_value, reduced_a, reduced_b = z3.BitVecs(
            "native_certificate_mask native_certificate_value_linear "
            "native_certificate_a native_certificate_b",
            width,
        )
        reduced_complement = -reduced_mask - 1
        reduced = (
            2 * reduced_a
            - 3 * reduced_b
            + 4 * (-reduced_a - 1)
            - 2 * (-reduced_b - 1)
            - 2 * (-(reduced_mask + reduced_b) - 1)
            - 3 * (-(reduced_complement + reduced_a) - 1)
        )
        return prove(
            z3.And(
                reduced_a + reduced_b == reduced_value,
                reduced != reduced_value - reduced_mask,
            )
        )
    except Exception:
        return False


__all__ = ["prove_native_ast_equivalence"]
