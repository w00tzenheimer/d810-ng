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
                sidecar.append(current if current.leaf_key is not None else None)
                return index
            left_index = append(current.children[0])
            right_index = (
                _MISSING_INDEX
                if len(current.children) == 1
                else append(current.children[1])
            )
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
            sidecar.append(None)
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

    PackedNativeMbaTerm.from_view(view)
    return catalogue.match_root(view, comparison_budget=comparison_budget)


def matcher_backend() -> str:
    """Name the backend selected by this pre-Cython compatibility adapter."""

    return "python"


def _masked_u64(value: int, width: int) -> int:
    if type(value) is not int or type(width) is not int or not 1 <= width <= 64:
        raise ValueError("native POD literals require an integer width from 1 to 64")
    return value & ((1 << width) - 1)


__all__ = [
    "OP_ADD",
    "PackedNativeMbaTerm",
    "PackedPodNode",
    "match_root_pod",
    "matcher_backend",
]
