"""Pure, fixed-width semantic canonicalization for portable MBA terms."""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass

from d810.mba.typed_term import (
    AC_OPERATIONS,
    TypedBvTerm,
    _term_sort_key,
    term_cost,
    term_fingerprint,
)


CANONICALIZER_SCHEMA_VERSION = 1


class CanonicalizationKind(str, enum.Enum):
    """A deterministic local transformation made by the canonicalizer."""

    NEGATE_CONSTANT = "negate_constant"
    DOUBLE_NEGATION = "double_negation"
    NEGATIVE_COEFFICIENT = "negative_coefficient"
    ADD_NEG_TO_SUB = "add_neg_to_sub"
    SUB_NEG_TO_ADD = "sub_neg_to_add"
    AC_REORDER = "ac_reorder"


@dataclass(frozen=True, slots=True)
class CanonicalizationStep:
    """One observed rewrite, represented only by stable term fingerprints."""

    kind: CanonicalizationKind
    source_fingerprint: str
    result_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CanonicalizationKind):
            try:
                object.__setattr__(self, "kind", CanonicalizationKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise ValueError("kind must be a CanonicalizationKind") from exc
        for field_name in ("source_fingerprint", "result_fingerprint"):
            value = getattr(self, field_name)
            if type(value) is not str or not value:
                raise ValueError(f"{field_name} must be a non-empty string")

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "source_fingerprint": self.source_fingerprint,
            "result_fingerprint": self.result_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class CanonicalMbaTermView:
    """The untouched source term and its deterministic canonical companion."""

    raw_term: TypedBvTerm
    canonical_term: TypedBvTerm
    raw_cost: tuple[int, int]
    canonical_cost: tuple[int, int]
    steps: tuple[CanonicalizationStep, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.raw_term, TypedBvTerm):
            raise TypeError("raw_term must be a TypedBvTerm")
        if not isinstance(self.canonical_term, TypedBvTerm):
            raise TypeError("canonical_term must be a TypedBvTerm")
        if self.raw_term.width != self.canonical_term.width:
            raise ValueError("raw and canonical terms must have the same width")
        for field_name in ("raw_cost", "canonical_cost"):
            cost = getattr(self, field_name)
            if (
                type(cost) is not tuple
                or len(cost) != 2
                or any(type(value) is not int or value < 0 for value in cost)
            ):
                raise ValueError(f"{field_name} must be a pair of non-negative integers")
        object.__setattr__(self, "steps", tuple(self.steps))
        if any(not isinstance(step, CanonicalizationStep) for step in self.steps):
            raise TypeError("steps must contain CanonicalizationStep values")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CANONICALIZER_SCHEMA_VERSION,
            "raw_fingerprint": term_fingerprint(self.raw_term),
            "canonical_fingerprint": term_fingerprint(self.canonical_term),
            "raw_cost": list(self.raw_cost),
            "canonical_cost": list(self.canonical_cost),
            "steps": [step.to_dict() for step in self.steps],
        }


def _associative_identity(
    term: TypedBvTerm,
    memo: dict[int, tuple[object, ...]],
) -> tuple[object, ...]:
    """Return an AC-insensitive structural key without rebuilding a tree."""

    cached = memo.get(id(term))
    if cached is not None:
        return cached
    if term.operation is None:
        key = _term_sort_key(term)
    elif term.operation in AC_OPERATIONS:
        operands: list[tuple[object, ...]] = []

        def collect(child: TypedBvTerm) -> None:
            if child.operation == term.operation and child.width == term.width:
                for grandchild in child.children:
                    collect(grandchild)
            else:
                operands.append(_associative_identity(child, memo))

        for child in term.children:
            collect(child)
        key = ("node", term.operation, term.width, tuple(sorted(operands)))
    else:
        key = (
            "node",
            term.operation,
            term.width,
            term.shift_count,
            tuple(_associative_identity(child, memo) for child in term.children),
        )
    memo[id(term)] = key
    return key


def _signed_value(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def _negative_coefficient(term: TypedBvTerm) -> TypedBvTerm | None:
    if term.operation != "mul":
        return None
    constants = [child for child in term.children if child.value is not None]
    others = [child for child in term.children if child.value is None]
    if len(constants) != 1 or len(others) != 1:
        return None
    signed = _signed_value(constants[0].value, term.width)
    if signed >= 0 or signed == -(1 << (term.width - 1)):
        return None
    positive = TypedBvTerm(None, term.width, value=-signed)
    product = TypedBvTerm("mul", term.width, children=(positive, others[0]))
    return TypedBvTerm("neg", term.width, children=(product,))


def _record(
    steps: list[CanonicalizationStep],
    kind: CanonicalizationKind,
    source: TypedBvTerm,
    result: TypedBvTerm,
) -> None:
    if source != result:
        steps.append(
            CanonicalizationStep(
                kind=kind,
                source_fingerprint=term_fingerprint(source),
                result_fingerprint=term_fingerprint(result),
            )
        )


def _canonicalize_children(
    term: TypedBvTerm, steps: list[CanonicalizationStep]
) -> TypedBvTerm:
    if term.operation is None:
        return term
    return TypedBvTerm(
        operation=term.operation,
        width=term.width,
        children=tuple(
            _canonicalize_children(child, steps) for child in term.children
        ),
        shift_count=term.shift_count,
    )


def _flatten_ac_operands(
    term: TypedBvTerm, operation: str
) -> list[TypedBvTerm]:
    if term.operation != operation:
        return [term]
    flattened: list[TypedBvTerm] = []
    for child in term.children:
        if child.operation == operation and child.width == term.width:
            flattened.extend(_flatten_ac_operands(child, operation))
        else:
            flattened.append(child)
    return flattened


def _rebuild_ac(
    operation: str, width: int, operands: list[TypedBvTerm]
) -> TypedBvTerm:
    if not operands:
        raise ValueError("an AC term requires at least one operand")
    if len(operands) == 1:
        return operands[0]
    rebuilt = operands[0]
    for operand in operands[1:]:
        rebuilt = TypedBvTerm(operation, width, children=(rebuilt, operand))
    return rebuilt


def _rewrite_add(
    term: TypedBvTerm, steps: list[CanonicalizationStep]
) -> TypedBvTerm:
    operands = _flatten_ac_operands(term, "add")
    positive: list[TypedBvTerm] = []
    negative: list[TypedBvTerm] = []
    for operand in operands:
        if operand.operation == "neg":
            negative.append(operand.children[0])
        else:
            positive.append(operand)
    if not positive or not negative:
        return term

    positive.sort(key=_term_sort_key)
    negative.sort(key=_term_sort_key)
    result = _rebuild_ac("add", term.width, positive)
    for operand in negative:
        result = TypedBvTerm("sub", term.width, children=(result, operand))
    _record(steps, CanonicalizationKind.ADD_NEG_TO_SUB, term, result)
    return result


def _rewrite_local(
    term: TypedBvTerm, steps: list[CanonicalizationStep]
) -> TypedBvTerm:
    if term.operation == "neg":
        child = term.children[0]
        if child.value is not None:
            result = TypedBvTerm(None, term.width, value=-child.value)
            _record(steps, CanonicalizationKind.NEGATE_CONSTANT, term, result)
            return result
        if child.operation == "neg":
            result = child.children[0]
            _record(steps, CanonicalizationKind.DOUBLE_NEGATION, term, result)
            return result

    if term.operation == "mul":
        result = _negative_coefficient(term)
        if result is not None:
            _record(steps, CanonicalizationKind.NEGATIVE_COEFFICIENT, term, result)
            return result

    if term.operation == "add":
        return _rewrite_add(term, steps)

    if term.operation == "sub" and term.children[1].operation == "neg":
        result = TypedBvTerm(
            "add", term.width, children=(term.children[0], term.children[1].children[0])
        )
        _record(steps, CanonicalizationKind.SUB_NEG_TO_ADD, term, result)
        return result

    return term


def _rewrite_add_forest(
    term: TypedBvTerm, steps: list[CanonicalizationStep]
) -> TypedBvTerm:
    """Normalize every operand before orienting one homogeneous add forest."""

    operands: list[TypedBvTerm] = []

    def collect(node: TypedBvTerm) -> None:
        if node.operation == "add" and node.width == term.width:
            for child in node.children:
                collect(child)
            return

        normalized = _rewrite_once(node, steps)
        if normalized.operation == "add" and normalized.width == term.width:
            collect(normalized)
        else:
            operands.append(normalized)

    collect(term)
    flattened = _rebuild_ac("add", term.width, operands)
    return _rewrite_add(flattened, steps)


def _rewrite_once(
    term: TypedBvTerm, steps: list[CanonicalizationStep]
) -> TypedBvTerm:
    if term.operation is None:
        return term
    if term.operation == "add":
        return _rewrite_add_forest(term, steps)
    normalized = TypedBvTerm(
        operation=term.operation,
        width=term.width,
        children=tuple(_rewrite_once(child, steps) for child in term.children),
        shift_count=term.shift_count,
    )
    return _rewrite_local(normalized, steps)


def _canonicalize_ac_with_trace(
    term: TypedBvTerm,
    steps: list[CanonicalizationStep],
    repeated_operator_fingerprints: set[str] | None = None,
    identity_memo: dict[int, tuple[object, ...]] | None = None,
) -> TypedBvTerm:
    if term.operation is None:
        return term
    if identity_memo is None:
        identity_memo = {}
    if repeated_operator_fingerprints is None:
        occurrences: Counter[str] = Counter()

        def count_operator_subterms(node: TypedBvTerm) -> None:
            if node.operation is not None:
                occurrences[str(_associative_identity(node, identity_memo))] += 1
            for child in node.children:
                count_operator_subterms(child)

        count_operator_subterms(term)
        repeated_operator_fingerprints = {
            fingerprint
            for fingerprint, count in occurrences.items()
            if count > 1
        }

    normalized_children = tuple(
        _canonicalize_ac_with_trace(
            child, steps, repeated_operator_fingerprints, identity_memo
        )
        for child in term.children
    )
    normalized = TypedBvTerm(
        operation=term.operation,
        width=term.width,
        children=normalized_children,
        shift_count=term.shift_count,
    )
    if normalized.operation not in AC_OPERATIONS:
        return normalized

    operands: list[TypedBvTerm] = []

    def collect(child: TypedBvTerm) -> None:
        # Keep repeated operator subterms structurally visible for downstream
        # atomization.  Flattening a repeated mask such as ``x & (y & K)``
        # destroys the only portable evidence that the same subterm recurs in
        # the residual, while unique associative nodes remain normalized.
        repeated_subterm = (
            child.operation is not None
            and str(_associative_identity(child, identity_memo)) in repeated_operator_fingerprints
        )
        if (
            child.operation == normalized.operation
            and child.width == normalized.width
            and not repeated_subterm
        ):
            for grandchild in child.children:
                collect(grandchild)
        else:
            operands.append(child)

    for child in normalized.children:
        collect(child)
    operands.sort(key=_term_sort_key)
    result = _rebuild_ac(normalized.operation, normalized.width, operands)
    _record(steps, CanonicalizationKind.AC_REORDER, normalized, result)
    return result


def canonicalize_mba_term(term: TypedBvTerm) -> CanonicalMbaTermView:
    """Return a pure, deterministic canonical view of one typed MBA term."""

    if not isinstance(term, TypedBvTerm):
        raise TypeError("term must be a TypedBvTerm")

    raw_cost = term_cost(term)
    steps: list[CanonicalizationStep] = []
    current = _canonicalize_children(term, steps)
    limit = 4 * raw_cost[1] + 16
    for _ in range(limit):
        rewritten = _rewrite_once(current, steps)
        rewritten = _canonicalize_ac_with_trace(rewritten, steps)
        if rewritten == current:
            return CanonicalMbaTermView(
                raw_term=term,
                canonical_term=current,
                raw_cost=raw_cost,
                canonical_cost=term_cost(current),
                steps=tuple(steps),
            )
        current = rewritten
    raise RuntimeError("MBA canonicalizer did not reach a fixed point")


__all__ = [
    "CANONICALIZER_SCHEMA_VERSION",
    "CanonicalizationKind",
    "CanonicalizationStep",
    "CanonicalMbaTermView",
    "canonicalize_mba_term",
]
