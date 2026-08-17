"""Portable fixed-width term vocabulary for local MBA simplification."""

from __future__ import annotations

import json
from dataclasses import dataclass


AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
UNARY_OPERATIONS = frozenset({"bnot", "neg"})
BINARY_OPERATIONS = frozenset({"add", "and", "mul", "or", "sub", "xor"})
FIXED_SHIFT_OPERATIONS = frozenset({"shl", "lshr", "rol", "ror"})
SUPPORTED_OPERATIONS = UNARY_OPERATIONS | BINARY_OPERATIONS | FIXED_SHIFT_OPERATIONS
_ROTATE_WIDTHS = frozenset({8, 16, 32, 64})


@dataclass(frozen=True)
class TypedBvTerm:
    """A fixed-width bit-vector term with constants or preserved live leaves."""

    operation: str | None
    width: int
    value: int | None = None
    leaf_key: tuple[object, ...] | None = None
    children: tuple[TypedBvTerm, ...] = ()
    shift_count: int | None = None

    def __post_init__(self) -> None:
        if type(self.width) is not int or self.width <= 0:
            raise ValueError("width must be a positive integer")
        object.__setattr__(self, "children", tuple(self.children))
        if self.leaf_key is not None:
            object.__setattr__(self, "leaf_key", tuple(self.leaf_key))

        if self.operation not in FIXED_SHIFT_OPERATIONS and self.shift_count is not None:
            raise ValueError("only fixed shifts and rotates accept shift_count")

        if self.operation is None:
            if self.children:
                raise ValueError("leaf and constant terms cannot have children")
            if (self.value is None) == (self.leaf_key is None):
                raise ValueError(
                    "a terminal term must have exactly one of value or leaf_key"
                )
            if self.value is not None:
                if type(self.value) is not int:
                    raise ValueError("constant value must be an integer")
                object.__setattr__(self, "value", self.value & ((1 << self.width) - 1))
            else:
                if not self.leaf_key:
                    raise ValueError("leaf_key must not be empty")
                try:
                    hash(self.leaf_key)
                except TypeError as exc:
                    raise ValueError("leaf_key must be hashable") from exc
                try:
                    _leaf_key_fingerprint(self.leaf_key)
                except ValueError as exc:
                    raise ValueError(
                        "leaf_key parts must be canonically representable"
                    ) from exc
            return

        if self.operation not in SUPPORTED_OPERATIONS:
            raise ValueError(f"unsupported operation: {self.operation}")
        if self.value is not None or self.leaf_key is not None:
            raise ValueError("operator terms cannot carry a value or leaf_key")
        if self.operation in FIXED_SHIFT_OPERATIONS:
            if len(self.children) != 1:
                raise ValueError(f"{self.operation} requires exactly one child")
            if type(self.shift_count) is not int or not 0 <= self.shift_count < self.width:
                raise ValueError("shift_count must be an integer in [0, width)")
            if self.operation in {"rol", "ror"} and self.width not in _ROTATE_WIDTHS:
                raise ValueError("rotate operations require a supported rotate width")
        expected_arity = (
            1
            if self.operation in UNARY_OPERATIONS or self.operation in FIXED_SHIFT_OPERATIONS
            else 2
        )
        if len(self.children) != expected_arity:
            raise ValueError(
                f"{self.operation} requires exactly {expected_arity} children"
            )
        if any(child.width != self.width for child in self.children):
            raise ValueError("operator children must have the same width")


def fixed_shift_term(
    operation: str,
    width: int,
    operand: TypedBvTerm,
    count: int,
) -> TypedBvTerm:
    """Construct one validated literal-count shift or rotate term."""

    if not isinstance(operand, TypedBvTerm):
        raise TypeError("operand must be a TypedBvTerm")
    return TypedBvTerm(
        operation=operation,
        width=width,
        children=(operand,),
        shift_count=count,
    )


def _leaf_key_part_fingerprint(value: object) -> tuple[object, ...]:
    """Return a totally ordered representation for stable live-leaf key parts."""

    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", int(value))
    if type(value) is int:
        return ("int", value)
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value.hex())
    if type(value) is tuple:
        return (
            "tuple",
            tuple(_leaf_key_part_fingerprint(item) for item in value),
        )
    raise ValueError(f"unsupported leaf-key part type: {type(value).__qualname__}")


def _leaf_key_fingerprint(
    leaf_key: tuple[object, ...],
) -> tuple[tuple[object, ...], ...]:
    return tuple(_leaf_key_part_fingerprint(part) for part in leaf_key)


def _term_sort_key(term: TypedBvTerm) -> tuple[object, ...]:
    if term.operation is None and term.value is not None:
        return ("constant", term.width, term.value)
    if term.operation is None:
        assert term.leaf_key is not None
        return ("leaf", term.width, _leaf_key_fingerprint(term.leaf_key))
    key: tuple[object, ...] = (
        "node",
        term.operation,
        term.width,
    )
    if term.operation in FIXED_SHIFT_OPERATIONS:
        key += ("shift_count", term.shift_count)
    return key + (tuple(_term_sort_key(child) for child in term.children),)


def term_fingerprint(term: TypedBvTerm) -> str:
    """Return a stable persisted fingerprint that never uses ``hash()``."""

    return json.dumps(
        _term_sort_key(term),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def canonicalize_ac_term(term: TypedBvTerm) -> TypedBvTerm:
    """Canonicalize only homogeneous, same-width AC operator trees."""

    if term.operation is None:
        return term

    normalized_children = tuple(canonicalize_ac_term(child) for child in term.children)
    if term.operation not in AC_OPERATIONS:
        return TypedBvTerm(
            operation=term.operation,
            width=term.width,
            children=normalized_children,
            shift_count=term.shift_count,
        )

    flattened: list[TypedBvTerm] = []

    def collect(child: TypedBvTerm) -> None:
        if child.operation == term.operation and child.width == term.width:
            for grandchild in child.children:
                collect(grandchild)
        else:
            flattened.append(child)

    for child in normalized_children:
        collect(child)
    flattened.sort(key=_term_sort_key)

    rebuilt = flattened[0]
    for child in flattened[1:]:
        rebuilt = TypedBvTerm(
            operation=term.operation,
            width=term.width,
            children=(rebuilt, child),
            shift_count=term.shift_count,
        )
    return rebuilt


def term_cost(term: TypedBvTerm) -> tuple[int, int]:
    """Return deterministic ``(operator_nodes, total_nodes)`` semantic cost."""

    if term.operation is None:
        return (0, 1)
    child_costs = tuple(term_cost(child) for child in term.children)
    return (
        1 + sum(cost[0] for cost in child_costs),
        1 + sum(cost[1] for cost in child_costs),
    )


__all__ = [
    "AC_OPERATIONS",
    "BINARY_OPERATIONS",
    "FIXED_SHIFT_OPERATIONS",
    "SUPPORTED_OPERATIONS",
    "UNARY_OPERATIONS",
    "TypedBvTerm",
    "canonicalize_ac_term",
    "fixed_shift_term",
    "term_cost",
    "term_fingerprint",
]
