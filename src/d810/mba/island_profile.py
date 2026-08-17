"""Pure routing facts for a fixed-width local MBA island."""

from __future__ import annotations

import enum
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    TypedBvTerm,
    canonicalize_ac_term,
    term_cost,
    term_fingerprint,
)


class MbaIslandClass(enum.StrEnum):
    NOT_MBA = "not_mba"
    LINEAR_MBA = "linear_mba"
    NONLINEAR_MBA = "nonlinear_mba"
    UNSUPPORTED = "unsupported"


class IslandBlocker(enum.StrEnum):
    MIXED_WIDTH = "mixed_width"
    CAST = "cast"
    LOAD = "load"
    CALL = "call"
    AMBIGUOUS_SHIFT = "ambiguous_shift"
    PREDICATE = "predicate"
    UNSUPPORTED_OPCODE = "unsupported_opcode"


@dataclass(frozen=True)
class MbaIslandProfile:
    width_bits: int
    operator_count: int
    total_node_count: int
    distinct_leaf_count: int
    constant_count: int
    operations: tuple[tuple[str, int], ...]
    has_boolean: bool
    has_arithmetic: bool
    nonlinear_product_count: int
    island_class: MbaIslandClass
    blockers: tuple[IslandBlocker, ...]
    fingerprint: str


_BOOLEAN_OPERATIONS = frozenset({"and", "bnot", "or", "xor"}) | FIXED_SHIFT_OPERATIONS
_ARITHMETIC_OPERATIONS = frozenset({"add", "mul", "neg", "sub"})


def _classify(
    *,
    has_boolean: bool,
    has_arithmetic: bool,
    nonlinear_product_count: int,
    blockers: tuple[IslandBlocker, ...],
) -> MbaIslandClass:
    if blockers:
        return MbaIslandClass.UNSUPPORTED
    if nonlinear_product_count:
        return MbaIslandClass.NONLINEAR_MBA
    if has_boolean and has_arithmetic:
        return MbaIslandClass.LINEAR_MBA
    return MbaIslandClass.NOT_MBA


def profile_typed_term(
    term: TypedBvTerm,
    *,
    blockers: Iterable[IslandBlocker] = (),
) -> MbaIslandProfile:
    """Classify a portable term without importing native or provider objects.

    Operator and node counts are measured from the exact term supplied by the
    caller.  Only the persisted fingerprint uses the existing homogeneous-AC
    normalization; callers that have a separate semantic canonical term must
    pass that term explicitly when they need its fingerprint.
    """

    normalized_blockers = tuple(sorted(set(blockers), key=str))
    if any(not isinstance(blocker, IslandBlocker) for blocker in normalized_blockers):
        raise ValueError("blockers must be IslandBlocker values")

    operations: Counter[str] = Counter()
    leafs: set[tuple[object, ...]] = set()
    constant_count = 0
    nonlinear_product_count = 0

    def has_symbolic_leaf(node: TypedBvTerm) -> bool:
        if node.operation is None:
            return node.leaf_key is not None
        return any(has_symbolic_leaf(child) for child in node.children)

    def visit(node: TypedBvTerm) -> None:
        nonlocal constant_count, nonlinear_product_count
        if node.operation is None:
            if node.leaf_key is not None:
                leafs.add(node.leaf_key)
            else:
                constant_count += 1
            return
        operations[node.operation] += 1
        if node.operation == "mul" and all(has_symbolic_leaf(child) for child in node.children):
            nonlinear_product_count += 1
        for child in node.children:
            visit(child)

    visit(term)
    has_boolean = any(operation in _BOOLEAN_OPERATIONS for operation in operations)
    has_arithmetic = any(operation in _ARITHMETIC_OPERATIONS for operation in operations)
    operator_count, total_node_count = term_cost(term)
    sorted_operations = tuple(sorted(operations.items()))
    island_class = _classify(
        has_boolean=has_boolean,
        has_arithmetic=has_arithmetic,
        nonlinear_product_count=nonlinear_product_count,
        blockers=normalized_blockers,
    )
    return MbaIslandProfile(
        width_bits=term.width,
        operator_count=operator_count,
        total_node_count=total_node_count,
        distinct_leaf_count=len(leafs),
        constant_count=constant_count,
        operations=sorted_operations,
        has_boolean=has_boolean,
        has_arithmetic=has_arithmetic,
        nonlinear_product_count=nonlinear_product_count,
        island_class=island_class,
        blockers=normalized_blockers,
        fingerprint=term_fingerprint(canonicalize_ac_term(term)),
    )


def profile_to_dict(profile: MbaIslandProfile) -> dict[str, object]:
    """Encode one profile using the portable provider metadata wire shape."""

    return {
        "width_bits": profile.width_bits,
        "operator_count": profile.operator_count,
        "total_node_count": profile.total_node_count,
        "distinct_leaf_count": profile.distinct_leaf_count,
        "constant_count": profile.constant_count,
        "operations": [list(item) for item in profile.operations],
        "has_boolean": profile.has_boolean,
        "has_arithmetic": profile.has_arithmetic,
        "nonlinear_product_count": profile.nonlinear_product_count,
        "island_class": profile.island_class.value,
        "blockers": [item.value for item in profile.blockers],
        "fingerprint": profile.fingerprint,
    }


def profile_from_dict(data: Mapping[str, object]) -> MbaIslandProfile:
    """Strictly decode the portable provider metadata wire shape."""

    try:
        operations = tuple(
            (str(item[0]), int(item[1]))
            for item in data["operations"]  # type: ignore[index,union-attr]
        )
        blockers = tuple(
            IslandBlocker(str(item))
            for item in data["blockers"]  # type: ignore[index,union-attr]
        )
        return MbaIslandProfile(
            width_bits=int(data["width_bits"]),
            operator_count=int(data["operator_count"]),
            total_node_count=int(data["total_node_count"]),
            distinct_leaf_count=int(data["distinct_leaf_count"]),
            constant_count=int(data["constant_count"]),
            operations=operations,
            has_boolean=bool(data["has_boolean"]),
            has_arithmetic=bool(data["has_arithmetic"]),
            nonlinear_product_count=int(data["nonlinear_product_count"]),
            island_class=MbaIslandClass(str(data["island_class"])),
            blockers=blockers,
            fingerprint=str(data["fingerprint"]),
        )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ValueError(f"invalid MBA island profile: {exc}") from exc


__all__ = [
    "IslandBlocker",
    "MbaIslandClass",
    "MbaIslandProfile",
    "profile_from_dict",
    "profile_to_dict",
    "profile_typed_term",
]
