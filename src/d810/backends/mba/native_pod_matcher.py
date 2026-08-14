"""Packed, callback-local representation for native MBA pattern matching.

The portable adapter is deliberately the oracle for the future Cython matcher:
it packs only already-validated :class:`NativeMbaTermView` values, retains live
identity in a separate sidecar, and delegates semantic matching to the existing
immutable compiled catalogue.  It neither reads Hex-Rays objects nor changes
constraint or replacement materialization semantics.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.core.cymode import CythonMode
from d810.core.typing import Any


_OPERATION_CODES = {
    "add": 1,
    "and": 2,
    "bnot": 3,
    "mul": 4,
    "neg": 5,
    "or": 6,
    "sub": 7,
    "xor": 8,
}

OP_ADD = _OPERATION_CODES["add"]
_KIND_CONSTANT = 1
_KIND_LEAF = 2
_KIND_OPERATOR = 3
_MISSING_INDEX = -1

if CythonMode().is_enabled():
    try:
        from d810.speedups.mba.c_native_pod_matcher import (  # type: ignore[import-not-found]
            match_pod_pattern as _match_pod_pattern,
        )
    except ImportError:
        _match_pod_pattern = None
else:
    _match_pod_pattern = None


@dataclass(frozen=True)
class PackedPodNode:
    """One numeric native-view node; no live object is stored here."""

    kind: int
    operation: int
    width: int
    left_index: int
    right_index: int
    literal_u64: int
    sidecar_index: int


@dataclass(frozen=True)
class PackedNativeMbaTerm:
    """A post-order numeric term plus callback-local live identity sidecar."""

    nodes: tuple[PackedPodNode, ...]
    root_index: int
    sidecar: tuple[NativeMbaTermView | None, ...]

    def numeric_rows(self) -> tuple[tuple[int, ...], ...]:
        """Return POD rows with a structural identity for repeated bindings."""

        identity_by_key: dict[tuple[object, ...], int] = {}
        match_ids: list[int] = []
        for view in self.sidecar:
            key = _view_match_key(view)
            match_ids.append(identity_by_key.setdefault(key, len(identity_by_key)))
        return tuple(
            (
                node.kind,
                node.operation,
                node.width,
                node.left_index,
                node.right_index,
                node.literal_u64,
                node.sidecar_index,
                match_ids[index],
            )
            for index, node in enumerate(self.nodes)
        )

    @classmethod
    def from_view(cls, view: NativeMbaTermView) -> PackedNativeMbaTerm:
        nodes: list[PackedPodNode] = []
        sidecar: list[NativeMbaTermView | None] = []

        def append(current: NativeMbaTermView) -> int:
            if current.operation is None:
                index = len(nodes)
                is_constant = current.constant_value is not None
                literal = (
                    0
                    if not is_constant
                    else _masked_u64(
                        current.constant_value,
                        current.width,
                    )
                )
                nodes.append(
                    PackedPodNode(
                        kind=_KIND_CONSTANT if is_constant else _KIND_LEAF,
                        operation=0,
                        width=current.width,
                        left_index=_MISSING_INDEX,
                        right_index=_MISSING_INDEX,
                        literal_u64=literal,
                        sidecar_index=index if current.leaf_key is not None else -1,
                    )
                )
                sidecar.append(current)
                return index
            children = (
                current.canonical_children()
                if current.operation in {"add", "and", "mul", "or", "xor"}
                else current.children
            )
            if len(children) > 2:
                raise ValueError("POD packing does not encode associative chains")
            left_index = append(children[0])
            right_index = _MISSING_INDEX if len(children) == 1 else append(children[1])
            operation = _OPERATION_CODES.get(current.operation)
            if operation is None:
                raise ValueError("native POD packing requires a supported operation")
            index = len(nodes)
            nodes.append(
                PackedPodNode(
                    kind=_KIND_OPERATOR,
                    operation=operation,
                    width=current.width,
                    left_index=left_index,
                    right_index=right_index,
                    literal_u64=0,
                    sidecar_index=_MISSING_INDEX,
                )
            )
            sidecar.append(current)
            return index

        root_index = append(view)
        return cls(tuple(nodes), root_index, tuple(sidecar))


def match_root_pod(
    catalogue: Any,
    view: NativeMbaTermView,
    *,
    comparison_budget: int = 64,
) -> Any:
    """Return the portable catalogue result after validating POD packability.

    This intentionally delegates matching until the Cython backend exists.  It
    gives both implementations one packing contract and preserves the current
    result type exactly.
    """

    if _has_associative_chain(view):
        return catalogue.match_root(view, comparison_budget=comparison_budget)
    packed = PackedNativeMbaTerm.from_view(view)
    if _match_pod_pattern is not None:
        accelerated = _match_cython_catalogue(
            catalogue,
            packed,
            comparison_budget=comparison_budget,
        )
        if accelerated is not None:
            return accelerated
    return catalogue.match_root(view, comparison_budget=comparison_budget)


def matcher_backend() -> str:
    """Name the available numeric matcher backend."""

    return "cython" if _match_pod_pattern is not None else "python"


def _masked_u64(value: int, width: int) -> int:
    if type(value) is not int or type(width) is not int or not 1 <= width <= 64:
        raise ValueError("native POD literals require an integer width from 1 to 64")
    return value & ((1 << width) - 1)


def _view_match_key(view: NativeMbaTermView | None) -> tuple[object, ...]:
    if view is None:
        return ("operator",)
    if view.operation is None:
        if view.constant_value is not None:
            return ("constant", view.width, view.constant_value)
        return ("leaf", view.width, view.leaf_key)
    return (
        "node",
        view.operation,
        view.width,
        tuple(_view_match_key(child) for child in view.children),
    )


def _match_cython_catalogue(
    catalogue: Any, packed: PackedNativeMbaTerm, *, comparison_budget: int
) -> Any | None:
    """Adapt Cython's numeric bindings into the existing immutable result.

    Associative chains retain the portable matcher for now: their canonical
    n-ary rollback is a distinct parity case, never an approximation.
    """

    from d810.backends.mba.compiled_pattern_catalogue import (
        FixedBindings,
        NativePatternMatch,
        NativePatternMatchResult,
    )
    from d810.backends.mba.egglog_add_rule_compiler import _constraints_match_term
    from d810.mba.typed_term import term_fingerprint

    root = packed.sidecar[packed.root_index]
    assert root is not None
    matches: list[Any] = []
    comparisons = 0
    lazy_swaps = 0
    for compiled in catalogue.root_width_buckets.get((root.operation, root.width), ()):
        encoded = _encode_pattern(compiled.rule.pattern)
        if encoded is None:
            return None
        pattern_rows, names = encoded
        bindings_rows, used, swaps, exceeded = _match_pod_pattern(
            pattern_rows,
            packed.numeric_rows(),
            packed.root_index,
            len(names),
            comparison_budget - comparisons,
        )
        comparisons += int(used)
        lazy_swaps += int(swaps)
        if exceeded:
            return NativePatternMatchResult((), comparisons, lazy_swaps, True)
        seen: set[str] = set()
        for indices in bindings_rows:
            native = {
                name: packed.sidecar[index] for name, index in zip(names, indices)
            }
            if any(value is None for value in native.values()):
                return None
            term_bindings = {
                name: value.to_typed_term() for name, value in native.items()
            }
            if not _constraints_match_term(
                compiled.rule, term_bindings, width=root.width
            ):
                continue
            fixed = FixedBindings(native=native, terms=term_bindings, width=root.width)
            try:
                fingerprint = term_fingerprint(
                    fixed.materialize_replacement(compiled.rule)
                )
            except (TypeError, ValueError):
                continue
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            matches.append(
                NativePatternMatch(compiled.rule, fixed, compiled.catalogue_index)
            )
    return NativePatternMatchResult(tuple(matches), comparisons, lazy_swaps)


def _encode_pattern(
    expression: Any,
) -> tuple[tuple[tuple[int, ...], ...], tuple[str, ...]] | None:
    rows: list[tuple[int, ...]] = []
    names: list[str] = []
    slot_by_name: dict[str, int] = {}

    def encode(current: Any) -> int | None:
        if current.operation is None:
            if current.value is not None and not bool(
                getattr(current, "is_pattern_constant", False)
            ):
                rows.append(
                    (
                        _KIND_CONSTANT,
                        0,
                        -1,
                        int(current.value) & ((1 << 64) - 1),
                        0,
                        -1,
                        -1,
                    )
                )
                return len(rows) - 1
            name = current.name
            if not name:
                rows.append(
                    (
                        _KIND_LEAF,
                        0,
                        -1,
                        0,
                        int(bool(getattr(current, "is_pattern_constant", False))),
                        -1,
                        -1,
                    )
                )
                return len(rows) - 1
            slot = slot_by_name.setdefault(name, len(names))
            if slot == len(names):
                names.append(name)
            rows.append(
                (
                    _KIND_LEAF,
                    0,
                    slot,
                    0,
                    int(bool(getattr(current, "is_pattern_constant", False))),
                    -1,
                    -1,
                )
            )
            return len(rows) - 1
        if _has_associative_chain_expression(current):
            return None
        operation = _OPERATION_CODES.get(current.operation)
        if operation is None or current.left is None:
            return None
        left = encode(current.left)
        right = -1 if current.right is None else encode(current.right)
        if left is None or right is None:
            return None
        rows.append((_KIND_OPERATOR, operation, -1, 0, 0, left, right))
        return len(rows) - 1

    return None if encode(expression) is None else (tuple(rows), tuple(names))


def _has_associative_chain(view: NativeMbaTermView) -> bool:
    if view.operation is None:
        return False
    if view.operation in _OPERATION_CODES and view.operation in {
        "add",
        "and",
        "mul",
        "or",
        "xor",
    }:
        if any(child.operation == view.operation for child in view.children):
            return True
    return any(_has_associative_chain(child) for child in view.children)


def _has_associative_chain_expression(expression: Any) -> bool:
    if expression.operation is None:
        return False
    if expression.operation in {"add", "and", "mul", "or", "xor"}:
        if (
            expression.left is not None
            and expression.left.operation == expression.operation
        ):
            return True
        if (
            expression.right is not None
            and expression.right.operation == expression.operation
        ):
            return True
    return any(
        _has_associative_chain_expression(child)
        for child in (expression.left, expression.right)
        if child is not None
    )


__all__ = [
    "OP_ADD",
    "PackedNativeMbaTerm",
    "PackedPodNode",
    "match_root_pod",
    "matcher_backend",
]
