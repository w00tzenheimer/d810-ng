"""DEFFAI k-switch context sensitivity: the last-k dispatcher case selections.

DEFFAI's context is **the last-k dispatcher case values** (Baek & Lee, IEEE TSE
52(3) 2026; the call-strings-style encoding for switch-flattened CFFs).  Two
executions that reach the dispatcher with different recent-case histories keep
*separate* abstract stores, so the dispatcher-merge join never collapses
unrelated executions to ``top`` -- this is the precision the shallow (k=1)
predecessor-partitioned baseline lacks.

* ``k >= 2`` minimum (a single switch level).
* ``k = 6`` for 3-layer nested CFF (escalation, Step 9 -- out of P3 core scope).

Portable-core: no IDA imports.  :class:`KContext` is frozen + hashable so it keys
the per-context fixpoint state and the CCM / CTG maps.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["KContext", "ContextPolicy"]

_U32_MASK = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class KContext:
    """The last-k dispatcher case values, oldest -> newest.

    ``cases`` is a sliding window of routed state constants (each the case taken
    at a dispatcher routing edge).  ``()`` is the empty / entry context.

    The context **indexes** the abstract state ``S# : KContext -> BB ->
    PowersetStore``.  The CTG forks natively: ``<1,2> -> {<2,3>, <2,4>}`` is
    ``KContext((1, 2)).extend(3, k)`` and ``.extend(4, k)`` (DEFFAI's
    ``POSSIBLE_SUCCESSORS``).

    Frozen + hashable (a ``tuple[int, ...]``), so it keys the fixpoint maps.
    Case values are masked to u32 -- dispatcher state constants are 32-bit in the
    targeted corpus, and masking keeps two contexts that differ only by an upper
    sign-extension equal.
    """

    cases: tuple[int, ...] = ()

    @staticmethod
    def empty() -> "KContext":
        """The entry context ``()`` (no case history yet)."""
        return KContext(())

    def extend(self, case: int, k: int) -> "KContext":
        """Append ``case`` and truncate to the last ``k`` (sliding window).

        While ``len(self.cases) < k`` the window *grows* (more precision); once
        full it *slides* (drops the oldest).  This is the finiteness bound: a
        context is a k-tuple over the finite state-const set, so
        ``|contexts| <= |states|^k``.

        ``k <= 0`` collapses every context to ``()`` -- the sound k=0 baseline
        (all executions share one store), used by the soundness argument that
        context sensitivity is a *refinement* of the context-free analysis.
        """
        if k <= 0:
            return KContext(())
        new = (*self.cases, int(case) & _U32_MASK)
        return KContext(new[-k:])

    def is_full(self, k: int) -> bool:
        """``True`` iff the window has reached its k-length cap."""
        return len(self.cases) >= k

    @property
    def depth(self) -> int:
        """The current window length (``<= k``)."""
        return len(self.cases)

    @property
    def last(self) -> int | None:
        """The most-recent case value, or ``None`` for the empty context."""
        return self.cases[-1] if self.cases else None

    def __repr__(self) -> str:
        if not self.cases:
            return "<>"
        return "<" + ",".join(hex(c) for c in self.cases) + ">"


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    """k value + hard caps for the context-sensitive analysis (cost control).

    ``k`` starts at 2 (the design's adaptive "start small, escalate on nesting /
    top-density").  ``max_contexts`` is the hard cap on distinct reachable
    contexts -- past it the analysis degrades (a pathological function is bounded
    rather than allowed to explode; design risk 1).
    """

    k: int = 2
    max_contexts: int = 4096

    def __post_init__(self) -> None:
        if self.k < 0:
            raise ValueError(f"ContextPolicy: k must be >= 0, got {self.k}")
        if self.max_contexts <= 0:
            raise ValueError(
                f"ContextPolicy: max_contexts must be > 0, got {self.max_contexts}"
            )
