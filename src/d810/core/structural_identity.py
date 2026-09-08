"""Exact owner-local structural values; equality conveys no permission.

Only exact immutable scalars and previously admitted child handles enter a
node. Family adapters own capture and schema validation; this module never
admits arbitrary records or borrows mutable descendants.
"""

from __future__ import annotations

from enum import IntEnum
from d810.core.typing import NamedTuple


class StructuralIdentityError(ValueError):
    """The structural owner cannot resolve or publish the requested value."""


class StructuralNodeKind(IntEnum):
    """Closed vocabulary for explicit family adapters."""

    VALUE = 1
    SEQUENCE = 2
    MAPPING = 3
    ENUM = 4
    NATIVE_KEY = 5
    NATIVE_BLOCK = 6
    LOGICAL_BLOCK = 7
    PLAN_BLOCK = 8
    OPERAND = 9
    INSTRUCTION = 10
    BLOCK = 11
    GRAPH = 12
    SUBJECT = 13
    CORRIDOR_PATH = 14
    PATCH_STEP = 15
    ROUTE_PROOF = 16
    ROUTE_GROUP = 17


class StructuralRef(NamedTuple):
    """An opaque registered handle, meaningful only to its open table."""

    kind: StructuralNodeKind
    ordinal: int
    owner: object


class StructuralNode(NamedTuple):
    """An immutable owned term; children are already admitted handles."""

    kind: StructuralNodeKind
    width: int | None
    payload: tuple[object, ...]
    children: tuple[StructuralRef, ...]


class StructuralTable:
    """Intern exact terms within one existing runtime arena's lifetime."""

    __slots__ = ("_owner", "_nodes", "_refs", "_buckets", "_closed", "_published")

    def __init__(self) -> None:
        self._owner = object()
        self._nodes: list[StructuralNode] = []
        self._refs: list[StructuralRef] = []
        self._buckets: dict[int, list[tuple[tuple, StructuralRef]]] = {}
        self._closed = False
        self._published = False

    @staticmethod
    def _key_hash(key: tuple) -> int:
        return hash(key)

    def _require_open(self) -> None:
        if self._closed:
            raise StructuralIdentityError("structural table is closed")

    def intern(
        self,
        kind: StructuralNodeKind,
        width: int | None,
        payload: tuple[object, ...],
        children: tuple[StructuralRef, ...],
    ) -> StructuralRef:
        """Admit a detached term without recursive child hashing or walking."""
        self._require_open()
        if self._published:
            raise StructuralIdentityError("structural table is published")
        if type(kind) is not StructuralNodeKind:
            raise TypeError("structural kind must be exact")
        if width is not None and (type(width) is not int or width < 1):
            raise TypeError("structural width must be a positive exact int")
        if type(payload) is not tuple or type(children) is not tuple:
            raise TypeError("structural payload and children require exact tuples")
        if any(
            type(value) not in (type(None), bool, int, str, bytes) for value in payload
        ):
            raise TypeError("unsupported structural scalar descendant")
        for child in children:
            if type(child) is not StructuralRef:
                raise TypeError("structural child must be an admitted handle")
            self.resolve(child, child.kind)
        key = (
            kind,
            width,
            tuple((type(v), v) for v in payload),
            tuple(child.ordinal for child in children),
        )
        bucket = self._buckets.setdefault(self._key_hash(key), [])
        for existing, ref in bucket:
            if existing == key:
                return ref
        ref = StructuralRef(kind, len(self._refs) + 1, self._owner)
        self._nodes.append(StructuralNode(kind, width, payload, children))
        self._refs.append(ref)
        bucket.append((key, ref))
        return ref

    def resolve(
        self, ref: StructuralRef, expected_kind: StructuralNodeKind
    ) -> StructuralNode:
        """Reject even an equal caller-constructed copy of an issued handle."""
        self._require_open()
        if (
            type(ref) is not StructuralRef
            or type(expected_kind) is not StructuralNodeKind
        ):
            raise TypeError("structural resolution requires exact ref and kind")
        if (
            ref.owner is not self._owner
            or ref.kind is not expected_kind
            or type(ref.ordinal) is not int
            or not 1 <= ref.ordinal <= len(self._refs)
            or self._refs[ref.ordinal - 1] is not ref
        ):
            raise StructuralIdentityError(
                "foreign, forged or mismatched structural handle"
            )
        return self._nodes[ref.ordinal - 1]

    def publish(self) -> None:
        """Make this partition read-only for the remainder of its lifetime."""
        self._require_open()
        self._published = True

    def close(self) -> None:
        """Release all values when the owning runtime arena closes."""
        self._closed = True
        self._nodes.clear()
        self._refs.clear()
        self._buckets.clear()

    def __len__(self) -> int:
        return len(self._nodes)


def compare_values(
    left_table: StructuralTable,
    left: StructuralRef,
    right_table: StructuralTable,
    right: StructuralRef,
) -> bool:
    """Compare values across partitions explicitly, without transferring authority."""
    pending = [(left, right)]
    visited: set[tuple[int, int]] = set()
    while pending:
        a, b = pending.pop()
        a_node = left_table.resolve(a, a.kind)
        b_node = right_table.resolve(b, b.kind)
        pair = (a.ordinal, b.ordinal)
        if pair in visited:
            continue
        visited.add(pair)
        if (
            a_node.kind is not b_node.kind
            or a_node.width != b_node.width
            or tuple((type(v), v) for v in a_node.payload)
            != tuple((type(v), v) for v in b_node.payload)
            or len(a_node.children) != len(b_node.children)
        ):
            return False
        pending.extend(zip(a_node.children, b_node.children))
    return True
