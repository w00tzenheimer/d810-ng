"""Sorted interval map for recovered BST dispatchers.

Converts a BST comparison tree into a sorted table of disjoint half-open
intervals [lo, hi) -> target, queryable with binary search.
Pure Python — no IDA imports.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from enum import Enum, auto
from d810.core.typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

U32_MIN: int = 0
U32_MAX_EXCL: int = 1 << 32


# ---------------------------------------------------------------------------
# Interval
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Interval:
    """Half-open integer interval [lo, hi).

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
    """

    lo: int
    hi: int

    def empty(self) -> bool:
        """Return True if the interval contains no points."""
        return self.lo >= self.hi

    def contains(self, x: int) -> bool:
        """Return True if *x* is inside the interval.

        Args:
            x: Integer point to test.
        """
        return self.lo <= x < self.hi

    def intersect(self, other: Interval) -> Interval | None:
        """Return the intersection with *other*, or None if disjoint.

        Args:
            other: Interval to intersect with.
        """
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if lo >= hi:
            return None
        return Interval(lo, hi)

    def subtract_point(self, x: int) -> list[Interval]:
        """Return the interval(s) obtained by removing the single point *x*.

        Args:
            x: Integer point to remove.

        Returns:
            0, 1, or 2 non-empty intervals covering [lo, hi) \\ {x}.
        """
        if not self.contains(x):
            return [self]
        result: list[Interval] = []
        left = Interval(self.lo, x)
        if not left.empty():
            result.append(left)
        right = Interval(x + 1, self.hi)
        if not right.empty():
            result.append(right)
        return result


# ---------------------------------------------------------------------------
# BST node types
# ---------------------------------------------------------------------------


class NodeKind(Enum):
    """Kind of node in the recovered BST comparison tree."""

    JBE = auto()     # unsigned <=  (yes branch taken when state <= imm)
    JA = auto()      # unsigned >   (yes branch taken when state >  imm)
    JB = auto()      # unsigned <   (yes branch taken when state <  imm)
    JAE = auto()     # unsigned >=  (yes branch taken when state >= imm)
    JZ = auto()      # equals       (yes branch when state == imm; target on equality)
    JNZ = auto()     # not-equals   (yes branch when state != imm; target on equality)
    TARGET = auto()  # leaf node carrying a handler target


@dataclass
class Node:
    """Node in the recovered BST comparison tree.

    Args:
        kind: Classification of this comparison node.
        imm: Immediate comparison value (None for TARGET nodes).
        yes: Sub-tree for the "taken" branch.
        no: Sub-tree for the "not-taken" branch.
        target: Handler target for TARGET / JZ / JNZ equality matches.
        block_serial: IDA block serial this node was recovered from.
    """

    kind: NodeKind
    imm: int | None = None
    yes: Node | None = None
    no: Node | None = None
    target: Any = None
    block_serial: int = -1


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------


@dataclass
class EmittedRange:
    """A single interval->target mapping produced by DFS tree traversal.

    Args:
        interval: The half-open interval [lo, hi).
        target: Handler block serial or any target payload.
        reason: Human-readable provenance string for debugging.
    """

    interval: Interval
    target: Any
    reason: str = ""


@dataclass(frozen=True, order=True)
class IntervalRow:
    """A row in the final sorted interval dispatch table.

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
        target: Handler block serial or target payload.
    """

    lo: int
    hi: int
    target: Any = field(compare=False)


# ---------------------------------------------------------------------------
# Core DFS emitter
# ---------------------------------------------------------------------------

_DOMAIN = Interval(U32_MIN, U32_MAX_EXCL)


def emit_dispatch_intervals(
    root: Node,
    domain: Interval = _DOMAIN,
) -> list[EmittedRange]:
    """Convert a BST Node tree into a flat list of disjoint EmittedRange entries.

    The DFS carries a ``feasible`` set of intervals representing which state
    values are still reachable on the current path.  Each comparison node
    splits the feasible set and recurses into yes/no children.

    Range split semantics (all unsigned 32-bit)::

        JBE(k): yes=[0, k+1), no=[k+1, 2^32)
        JA(k):  yes=[k+1, 2^32), no=[0, k+1)
        JB(k):  yes=[0, k),   no=[k, 2^32)
        JAE(k): yes=[k, 2^32), no=[0, k)

    Args:
        root: Root of the recovered BST comparison tree.
        domain: Universe interval for feasibility (default: full u32).

    Returns:
        Sorted, coalesced list of EmittedRange objects.
    """
    out: list[EmittedRange] = []

    def _dfs(node: Node, feasible: list[Interval]) -> None:
        if not feasible:
            return

        match node.kind:
            case NodeKind.TARGET:
                for iv in feasible:
                    out.append(EmittedRange(iv, node.target, "TARGET"))

            case NodeKind.JBE:
                assert node.imm is not None
                k = node.imm
                yes_mask = Interval(U32_MIN, k + 1)
                no_mask = Interval(k + 1, U32_MAX_EXCL)
                _recurse_child(node.yes, feasible, yes_mask, "JBE/yes")
                _recurse_child(node.no, feasible, no_mask, "JBE/no")

            case NodeKind.JA:
                assert node.imm is not None
                k = node.imm
                yes_mask = Interval(k + 1, U32_MAX_EXCL)
                no_mask = Interval(U32_MIN, k + 1)
                _recurse_child(node.yes, feasible, yes_mask, "JA/yes")
                _recurse_child(node.no, feasible, no_mask, "JA/no")

            case NodeKind.JB:
                assert node.imm is not None
                k = node.imm
                yes_mask = Interval(U32_MIN, k)
                no_mask = Interval(k, U32_MAX_EXCL)
                _recurse_child(node.yes, feasible, yes_mask, "JB/yes")
                _recurse_child(node.no, feasible, no_mask, "JB/no")

            case NodeKind.JAE:
                assert node.imm is not None
                k = node.imm
                yes_mask = Interval(k, U32_MAX_EXCL)
                no_mask = Interval(U32_MIN, k)
                _recurse_child(node.yes, feasible, yes_mask, "JAE/yes")
                _recurse_child(node.no, feasible, no_mask, "JAE/no")

            case NodeKind.JNZ:
                # Equality match → emit point interval; inequality → yes child
                assert node.imm is not None
                k = node.imm
                point = Interval(k, k + 1)
                for iv in feasible:
                    pt = iv.intersect(point)
                    if pt is not None:
                        out.append(EmittedRange(pt, node.target, "JNZ/eq"))
                remainder: list[Interval] = []
                for iv in feasible:
                    remainder.extend(iv.subtract_point(k))
                if node.yes is not None:
                    _dfs(node.yes, remainder)

            case NodeKind.JZ:
                # Equality match → emit point interval; inequality → no child
                assert node.imm is not None
                k = node.imm
                point = Interval(k, k + 1)
                for iv in feasible:
                    pt = iv.intersect(point)
                    if pt is not None:
                        out.append(EmittedRange(pt, node.target, "JZ/eq"))
                remainder2: list[Interval] = []
                for iv in feasible:
                    remainder2.extend(iv.subtract_point(k))
                if node.no is not None:
                    _dfs(node.no, remainder2)

    def _recurse_child(
        child: Node | None,
        feasible: list[Interval],
        mask: Interval,
        label: str,
    ) -> None:
        if child is None:
            return
        clipped = [iv.intersect(mask) for iv in feasible]
        valid = [iv for iv in clipped if iv is not None]
        if valid:
            _dfs(child, valid)

    initial = [domain]
    _dfs(root, initial)
    return coalesce_same_target(sort_and_validate(out))


# ---------------------------------------------------------------------------
# Post-processing helpers
# ---------------------------------------------------------------------------


def sort_and_validate(items: list[EmittedRange]) -> list[EmittedRange]:
    """Sort *items* by interval start, then validate no overlaps.

    Args:
        items: Raw list of EmittedRange objects from DFS traversal.

    Returns:
        Sorted list; raises AssertionError if any two intervals overlap.

    Raises:
        AssertionError: If two intervals overlap.
    """
    sorted_items = sorted(items, key=lambda e: (e.interval.lo, e.interval.hi))
    for i in range(len(sorted_items) - 1):
        a = sorted_items[i].interval
        b = sorted_items[i + 1].interval
        assert a.hi <= b.lo, (
            f"Overlapping intervals detected: {a} vs {b}"
        )
    return sorted_items


def coalesce_same_target(items: list[EmittedRange]) -> list[EmittedRange]:
    """Merge adjacent EmittedRange entries that share the same target.

    Assumes *items* is already sorted and non-overlapping (i.e. the output
    of :func:`sort_and_validate`).

    Args:
        items: Sorted, validated list of EmittedRange objects.

    Returns:
        New list with adjacent same-target intervals merged.
    """
    if not items:
        return []
    result: list[EmittedRange] = [items[0]]
    for cur in items[1:]:
        prev = result[-1]
        if prev.target == cur.target and prev.interval.hi == cur.interval.lo:
            result[-1] = EmittedRange(
                Interval(prev.interval.lo, cur.interval.hi),
                prev.target,
                prev.reason,
            )
        else:
            result.append(cur)
    return result


def compute_gaps(
    items: list[EmittedRange],
    domain: Interval = _DOMAIN,
) -> list[Interval]:
    """Return intervals in *domain* not covered by any entry in *items*.

    Args:
        items: Sorted, validated list of EmittedRange objects.
        domain: Universe interval to check coverage against.

    Returns:
        List of uncovered Interval objects, sorted by lo.
    """
    gaps: list[Interval] = []
    cursor = domain.lo
    for entry in items:
        iv = entry.interval
        if iv.lo > cursor:
            gaps.append(Interval(cursor, iv.lo))
        cursor = max(cursor, iv.hi)
    if cursor < domain.hi:
        gaps.append(Interval(cursor, domain.hi))
    return gaps


# ---------------------------------------------------------------------------
# IntervalDispatcher
# ---------------------------------------------------------------------------


class IntervalDispatcher:
    """Binary-search dispatcher table built from a recovered BST.

    Provides O(log n) lookup of the handler target for a given 32-bit state
    value.

    Args:
        rows: Pre-built list of IntervalRow objects.
    """

    __slots__ = ("_rows", "_starts")

    def __init__(self, rows: list[IntervalRow]) -> None:
        self._rows: list[IntervalRow] = sorted(rows)
        # Validate no overlaps
        for i in range(len(self._rows) - 1):
            a = self._rows[i]
            b = self._rows[i + 1]
            assert a.hi <= b.lo, (
                f"IntervalDispatcher: overlapping rows {a} and {b}"
            )
        self._starts: list[int] = [r.lo for r in self._rows]

    def __len__(self) -> int:
        """Return the number of rows in the table."""
        return len(self._rows)

    def __bool__(self) -> bool:
        """Return True if the table is non-empty."""
        return bool(self._rows)

    def lookup(self, state: int) -> Any | None:
        """Return the target for *state*, or None if no interval covers it.

        Args:
            state: 32-bit unsigned state value.

        Returns:
            Target payload or None.
        """
        row = self.lookup_row(state)
        return row.target if row is not None else None

    def lookup_row(self, state: int) -> IntervalRow | None:
        """Return the IntervalRow covering *state*, or None.

        Args:
            state: 32-bit unsigned state value.

        Returns:
            Matching IntervalRow or None.
        """
        idx = bisect_right(self._starts, state) - 1
        if idx < 0:
            return None
        row = self._rows[idx]
        if row.lo <= state < row.hi:
            return row
        return None

    def lookup_range(self, lo: int, hi: int) -> Any | None:
        """Return the target if ALL intervals overlapping [lo, hi] share the same target.

        Returns None if no intervals overlap or if multiple targets are found.
        """
        if not self._rows:
            return None
        # Convert to half-open [lo, hi_open) for comparison
        hi_open = hi + 1
        target: Any | None = None
        for row in self._rows:
            # row uses half-open [row.lo, row.hi)
            if row.hi <= lo:
                continue  # row ends before our range starts
            if row.lo >= hi_open:
                break  # row starts after our range ends (sorted)
            # Overlap
            if target is None:
                target = row.target
            elif row.target != target:
                return None  # Multiple targets
        return target

    @classmethod
    def from_emitted(cls, emitted: list[EmittedRange]) -> IntervalDispatcher:
        """Build an IntervalDispatcher from DFS output, skipping None targets.

        Args:
            emitted: Output of :func:`emit_dispatch_intervals`.

        Returns:
            New IntervalDispatcher instance.
        """
        rows = [
            IntervalRow(e.interval.lo, e.interval.hi, e.target)
            for e in emitted
            if e.target is not None
        ]
        return cls(rows)

    def to_handler_state_map(self) -> dict[int, int]:
        """Return a mapping of exact state value → target for width-1 intervals.

        Only intervals where ``hi - lo == 1`` are included (point intervals).

        Returns:
            Dict mapping exact state int to target int.
        """
        return {
            row.lo: row.target
            for row in self._rows
            if row.hi - row.lo == 1
        }

    def to_handler_range_map(
        self,
    ) -> dict[int, tuple[int | None, int | None]]:
        """Return a mapping of target → (lo_inclusive, hi_inclusive) range.

        All intervals are included.  ``hi`` is returned as inclusive
        (``row.hi - 1``).  When multiple intervals share the same target the
        last one written wins; callers that need all ranges should iterate
        :attr:`_rows` directly.

        Returns:
            Dict mapping target to (lo, hi_inclusive) tuple.
        """
        result: dict[int, tuple[int | None, int | None]] = {}
        for row in self._rows:
            hi_incl = row.hi - 1 if row.hi > row.lo else None
            result[row.target] = (row.lo, hi_incl)
        return result

    def all_targets(self) -> set[int]:
        """Return the set of all unique targets in the table.

        Returns:
            Set of target values.
        """
        return {row.target for row in self._rows}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "U32_MIN",
    "U32_MAX_EXCL",
    "Interval",
    "NodeKind",
    "Node",
    "EmittedRange",
    "IntervalRow",
    "emit_dispatch_intervals",
    "sort_and_validate",
    "coalesce_same_target",
    "compute_gaps",
    "IntervalDispatcher",
]
