"""Range-partitioned decision-DAG route oracle for dispatcher BSTs (portable).

Given a dispatcher's binary-search-tree of state-variable comparisons, this
resolves which handler a concrete state routes to (:meth:`DecisionDag.route`) AND
partitions the entire state space into ``(domain, path, target)`` triples
(:meth:`DecisionDag.resolve_paths`) -- a sound/complete ``RoutePredicateEvaluator``.
:meth:`DecisionDag.sibling_arms` exposes, for each block, the *other* arm(s) of
the comparison that reaches it, which lets a caller prune an infeasible sibling
edge (the ``blk35 -> blk56`` case: ``0x7FDCE054`` routes to ``57`` past
``!= 0x7D9C16EC``; ``56`` is only reached by ``state == 0x7D9C16EC``).

It operates over a CANONICAL UNSIGNED state space ``[0, 2**width)`` represented as
an exact disjoint union of integer intervals (:class:`IntervalSet`). A single
wrapped interval (:class:`d810.analyses.abstract_domains.wrapped_interval.WrappedInterval`,
the modular single-interval cousin) cannot represent the holes a chain of ``!=`` /
range tests carves out, and intersection is not closed over single wrapped
intervals, so the partition needs the set extension.

SIGNEDNESS is per-comparison, encoded in the opcode (``ja/jb/jae/jbe`` unsigned,
``jg/jl/jge/jle`` signed, ``jz/jnz`` equality) -- NOT a single global flag (which
silently drops ``0xFFFFFFFF`` on an unsigned ``> 0x7FFFFFFF``). A signed test is
translated into its equivalent unsigned interval set via the sign-bit-XOR
reduction (``s <_signed c  <=>  (s ^ 2**(w-1)) <_unsigned (c ^ 2**(w-1))``), so
signed and unsigned comparisons in the same BST compose soundly.

Pure: no IDA. Extraction of the BST node shape from live microcode lives in
``backends/hexrays/evidence/bst_analysis``; this module only consumes the
``BstComparison`` records.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable, Mapping, Optional, Tuple

__all__ = [
    "Interval",
    "IntervalSet",
    "satisfying_set",
    "BstComparison",
    "ResolvedPath",
    "DecisionDag",
    "UNSIGNED_OPS",
    "SIGNED_OPS",
    "EQUALITY_OPS",
]

# Microcode conditional-jump mnemonics this oracle understands (the comparison is
# TRUE => control takes the jump target; else the fallthrough).
UNSIGNED_OPS = frozenset({"ja", "jb", "jae", "jbe"})
SIGNED_OPS = frozenset({"jg", "jl", "jge", "jle"})
EQUALITY_OPS = frozenset({"jz", "jnz"})


@dataclass(frozen=True)
class Interval:
    """A closed integer interval ``[low, high]`` (both inclusive)."""

    low: int
    high: int

    def contains(self, value: int) -> bool:
        return self.low <= value <= self.high


class IntervalSet:
    """Exact disjoint union of intervals over the unsigned space ``[0, 2**width)``.

    Canonicalised (sorted, merged, adjacency-collapsed since the domain is
    integers) and clamped to the bitwidth on construction, so equal sets have
    equal :attr:`intervals`. All set ops return a fresh :class:`IntervalSet`.
    """

    __slots__ = ("width", "mod", "intervals")

    def __init__(self, width: int, intervals: Iterable[Interval] = ()):
        self.width = int(width)
        self.mod = 1 << self.width
        self.intervals = self._canonicalise(intervals)

    def _canonicalise(self, intervals: Iterable[Interval]) -> Tuple[Interval, ...]:
        clamped = []
        for iv in intervals:
            low = max(0, int(iv.low))
            high = min(self.mod - 1, int(iv.high))
            if low <= high:
                clamped.append(Interval(low, high))
        clamped.sort(key=lambda i: (i.low, i.high))
        merged: list[Interval] = []
        for cur in clamped:
            if merged and cur.low <= merged[-1].high + 1:
                merged[-1] = Interval(merged[-1].low, max(merged[-1].high, cur.high))
            else:
                merged.append(cur)
        return tuple(merged)

    @classmethod
    def universe(cls, width: int) -> "IntervalSet":
        return cls(width, [Interval(0, (1 << width) - 1)])

    @classmethod
    def empty(cls, width: int) -> "IntervalSet":
        return cls(width, [])

    def is_empty(self) -> bool:
        return not self.intervals

    def contains(self, value: int) -> bool:
        v = int(value) & (self.mod - 1)
        return any(iv.contains(v) for iv in self.intervals)

    def intersect(self, other: "IntervalSet") -> "IntervalSet":
        out = []
        for a in self.intervals:
            for b in other.intervals:
                low = max(a.low, b.low)
                high = min(a.high, b.high)
                if low <= high:
                    out.append(Interval(low, high))
        return IntervalSet(self.width, out)

    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.width, list(self.intervals) + list(other.intervals))

    def complement(self) -> "IntervalSet":
        out = []
        cursor = 0
        for iv in self.intervals:
            if iv.low > cursor:
                out.append(Interval(cursor, iv.low - 1))
            cursor = iv.high + 1
        if cursor <= self.mod - 1:
            out.append(Interval(cursor, self.mod - 1))
        return IntervalSet(self.width, out)

    def difference(self, other: "IntervalSet") -> "IntervalSet":
        return self.intersect(other.complement())

    def _xor_high_bit(self) -> "IntervalSet":
        """Remap every element ``x -> x ^ 2**(width-1)`` (splits at the sign bit).

        XOR by the high bit swaps the lower half ``[0, sb)`` with the upper half
        ``[sb, mod)`` (order-preserving within each half), so each interval is
        split at ``sb`` and each piece shifted by ``+sb`` / ``-sb``. This realises
        the signed<->unsigned reduction at the set level.
        """
        sb = self.mod >> 1
        out = []
        for iv in self.intervals:
            if iv.low <= sb - 1:  # lower-half piece -> +sb
                lo, hi = iv.low, min(iv.high, sb - 1)
                out.append(Interval(lo + sb, hi + sb))
            if iv.high >= sb:  # upper-half piece -> -sb
                lo, hi = max(iv.low, sb), iv.high
                out.append(Interval(lo - sb, hi - sb))
        return IntervalSet(self.width, out)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, IntervalSet)
            and self.width == other.width
            and self.intervals == other.intervals
        )

    def __hash__(self) -> int:
        return hash((self.width, self.intervals))

    def __repr__(self) -> str:
        if self.is_empty():
            return "{}"
        return " U ".join(f"[{i.low:#x},{i.high:#x}]" for i in self.intervals)


def _unsigned_true_set(width: int, op: str, const: int) -> IntervalSet:
    """Satisfying set of an UNSIGNED comparison ``state OP const`` (true => jump)."""
    mod = 1 << width
    c = int(const) & (mod - 1)
    if op == "ja":  # state > c
        return IntervalSet(width, [Interval(c + 1, mod - 1)])
    if op == "jae":  # state >= c
        return IntervalSet(width, [Interval(c, mod - 1)])
    if op == "jb":  # state < c
        return IntervalSet(width, [Interval(0, c - 1)])
    if op == "jbe":  # state <= c
        return IntervalSet(width, [Interval(0, c)])
    raise ValueError(f"not an unsigned op: {op}")


def satisfying_set(width: int, op: str, const: int) -> IntervalSet:
    """The set of states for which conditional jump ``op`` (vs ``const``) is TRUE.

    Returns the canonical-unsigned :class:`IntervalSet` of states that TAKE the
    jump. Signed ops are translated via the sign-bit-XOR reduction; equality ops
    are signedness-independent.
    """
    mod = 1 << width
    c = int(const) & (mod - 1)
    if op == "jz":
        return IntervalSet(width, [Interval(c, c)])
    if op == "jnz":
        return IntervalSet(width, [Interval(c, c)]).complement()
    if op in UNSIGNED_OPS:
        return _unsigned_true_set(width, op, c)
    if op in SIGNED_OPS:
        # signed(state) OP signed(const)  <=>  (state ^ sb) OP_unsigned (const ^ sb)
        sb = mod >> 1
        unsigned_equiv = {"jg": "ja", "jge": "jae", "jl": "jb", "jle": "jbe"}[op]
        return _unsigned_true_set(width, unsigned_equiv, c ^ sb)._xor_high_bit()
    raise ValueError(f"unknown comparison op: {op}")


def _evaluate(op: str, state: int, const: int, width: int) -> bool:
    """Concretely evaluate ``state OP const`` (matches :func:`satisfying_set`)."""
    mod = 1 << width
    s = int(state) & (mod - 1)
    c = int(const) & (mod - 1)
    if op == "jz":
        return s == c
    if op == "jnz":
        return s != c
    if op == "ja":
        return s > c
    if op == "jae":
        return s >= c
    if op == "jb":
        return s < c
    if op == "jbe":
        return s <= c
    sb = mod >> 1
    ss = s - mod if s >= sb else s
    cc = c - mod if c >= sb else c
    if op == "jg":
        return ss > cc
    if op == "jge":
        return ss >= cc
    if op == "jl":
        return ss < cc
    if op == "jle":
        return ss <= cc
    raise ValueError(f"unknown comparison op: {op}")


@dataclass(frozen=True)
class BstComparison:
    """One BST decision node: ``state OP const`` -> *true_target* else *false_target*.

    ``true_target`` is the block taken when the comparison holds (the ``@N`` jump
    in the microcode); ``false_target`` is the fallthrough. A block serial that is
    not a key in :attr:`DecisionDag.nodes` is a leaf (a handler).
    """

    serial: int
    op: str
    const: int
    true_target: int
    false_target: int


@dataclass(frozen=True)
class ResolvedPath:
    """A partition cell: every state in *domain* reaches *target* via *path*."""

    domain: IntervalSet
    target: int
    path: Tuple[int, ...]


class DecisionDag:
    """A dispatcher BST over a ``width``-bit state variable.

    *nodes* maps a comparison block serial to its :class:`BstComparison`; any
    serial referenced as a target but absent from *nodes* is a leaf handler.
    """

    def __init__(self, width: int, nodes: Mapping[int, BstComparison], root: int):
        self.width = int(width)
        self.nodes: dict[int, BstComparison] = dict(nodes)
        self.root = int(root)

    def route(self, state: int) -> int:
        """Follow the single feasible branch for a concrete *state* to its leaf."""
        cur = self.root
        seen: set[int] = set()
        while cur in self.nodes and cur not in seen:
            seen.add(cur)
            node = self.nodes[cur]
            took = _evaluate(node.op, state, node.const, self.width)
            cur = node.true_target if took else node.false_target
        return cur

    def resolve_paths(self) -> Tuple[ResolvedPath, ...]:
        """Partition the whole state space into ``(domain, path, target)`` cells.

        Sound (cells are pairwise disjoint) and complete (their union is the
        universe) by construction: each node splits its incoming domain into the
        true set and its exact complement.
        """
        out: list[ResolvedPath] = []
        stack = [(self.root, IntervalSet.universe(self.width), (), frozenset())]
        while stack:
            cur, dom, path, seen = stack.pop()
            if cur not in self.nodes or cur in seen:
                out.append(ResolvedPath(dom, cur, path))
                continue
            node = self.nodes[cur]
            true_set = satisfying_set(self.width, node.op, node.const)
            true_dom = dom.intersect(true_set)
            false_dom = dom.difference(true_set)
            nxt_path = path + (cur,)
            nxt_seen = seen | {cur}
            if not true_dom.is_empty():
                stack.append((node.true_target, true_dom, nxt_path, nxt_seen))
            if not false_dom.is_empty():
                stack.append((node.false_target, false_dom, nxt_path, nxt_seen))
        return tuple(out)

    def sibling_arms(self) -> Mapping[int, "frozenset[int]"]:
        """Map each arm target to the *other* arm(s) of comparisons reaching it.

        ``56`` and ``57`` are the two arms of ``blk55``, so each is the other's
        sibling: a block whose routed state takes one arm must not also carry an
        edge to the sibling arm. (Mutual, so callers can ask "is *D* a sibling of
        my routed target *T*?".)
        """
        sib: dict[int, set[int]] = {}
        for node in self.nodes.values():
            a, b = node.true_target, node.false_target
            if a != b:
                sib.setdefault(a, set()).add(b)
                sib.setdefault(b, set()).add(a)
        return {k: frozenset(v) for k, v in sib.items()}

    def leaves(self) -> "frozenset[int]":
        """All leaf (handler) targets -- referenced as a target but not a node."""
        targets: set[int] = set()
        for node in self.nodes.values():
            targets.add(node.true_target)
            targets.add(node.false_target)
        return frozenset(t for t in targets if t not in self.nodes)
