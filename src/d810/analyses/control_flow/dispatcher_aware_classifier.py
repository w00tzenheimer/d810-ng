"""Dispatcher-aware back-edge classifier (Piece 4 of uee-32r3).

Generalizes :mod:`d810.analyses.control_flow.backedge_classifier` (Piece 2) with the
context needed to make it useful at LOCOPT/CALLS as well as GLBOPT1/2.
At early maturities the dispatcher is alive: handler tails write the
state variable and goto the dispatcher, the dispatcher reads the state
variable and conditionally jumps to the next handler. The basic
classifier sees this as ``REAL_LOOP`` (handler writes ``%state_var``
which dispatcher reads) — wrong. With the dispatcher region known, we
distinguish:

- ``DISPATCHER_ROUND_TRIP`` — back-edge whose target is in the
  dispatcher region (root or condition-chain cascade). Always actionable as a
  redirect-to-handler when paired with reaching-def + condition-chain resolution.
- ``REAL_LOOP`` — carrier overlap exists *outside* the state-var
  exclusion set. Genuine algorithmic iteration.
- ``SPURIOUS`` — no carrier overlap and target is not dispatcher.
  Harder to act on (needs forward-target resolution); subset of edges
  Piece 3a's planner already addresses.
- ``UNKNOWN`` — target has no readable tail predicate (register-only
  operands, empty predicate, etc.). Same gap as Piece 2.

Strictly observability-only at this layer — no redirect emission. The
classifier is pure-Python, namespace-agnostic (caller chooses
``%var_HEX`` / stkoff hex / register names). The Hodur observability
strategy that consumes it lives in ``hodur.strategies.backedge_audit``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable, Mapping

logger = getLogger(__name__)


class DispatcherAwareEdgeClass(str, Enum):
    """Four-way classification of a back-edge inside a cyclic SCC."""

    DISPATCHER_ROUND_TRIP = "DISPATCHER_ROUND_TRIP"
    REAL_LOOP = "REAL_LOOP"
    SPURIOUS = "SPURIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class DispatcherContext:
    """Inputs that make the classifier dispatcher-aware.

    All fields are optional / can be empty:

    Parameters
    ----------
    dispatcher_blocks : frozenset[int]
        Block serials that belong to the dispatcher region (root +
        condition-chain cascade). Edges with target in this set are classified as
        ``DISPATCHER_ROUND_TRIP``.
    excluded_carriers : frozenset[str]
        Variable tokens (e.g. ``%var_3C``) that should NOT count toward
        ``REAL_LOOP`` overlap because they are dispatcher state machine
        mechanism, not iteration carriers.
    """

    dispatcher_blocks: frozenset[int] = frozenset()
    excluded_carriers: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class DispatcherAwareClassification:
    """One classified back-edge with full evidence trail."""

    src_serial: int
    tgt_serial: int
    classification: DispatcherAwareEdgeClass
    src_writes: frozenset[str]
    tgt_predicate_reads: frozenset[str]
    overlap: frozenset[str]
    state_var_overlap: frozenset[str]
    reason: str

    @property
    def is_dispatcher_round_trip(self) -> bool:
        return self.classification is DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP

    @property
    def is_real_loop(self) -> bool:
        return self.classification is DispatcherAwareEdgeClass.REAL_LOOP

    @property
    def is_spurious(self) -> bool:
        return self.classification is DispatcherAwareEdgeClass.SPURIOUS


@dataclass(frozen=True, slots=True)
class DispatcherAwareSummary:
    """Aggregate counts across many classifications."""

    dispatcher_round_trip: int = 0
    real_loop: int = 0
    spurious: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return (
            self.dispatcher_round_trip
            + self.real_loop
            + self.spurious
            + self.unknown
        )


def classify_backedge_dispatcher_aware(
    *,
    src_serial: int,
    tgt_serial: int,
    src_writes: frozenset[str],
    tgt_predicate_reads: frozenset[str],
    context: DispatcherContext,
) -> DispatcherAwareClassification:
    """Classify a single back-edge with dispatcher awareness.

    Order of decision:

    1. ``tgt_serial`` ∈ ``dispatcher_blocks`` → DISPATCHER_ROUND_TRIP.
    2. ``tgt_predicate_reads`` empty → UNKNOWN.
    3. ``src_writes ∩ tgt_predicate_reads`` minus excluded carriers
       non-empty → REAL_LOOP.
    4. Otherwise → SPURIOUS.
    """
    src_writes = frozenset(src_writes)
    tgt_predicate_reads = frozenset(tgt_predicate_reads)
    excluded = frozenset(context.excluded_carriers)

    if int(tgt_serial) in context.dispatcher_blocks:
        return DispatcherAwareClassification(
            src_serial=int(src_serial),
            tgt_serial=int(tgt_serial),
            classification=DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP,
            src_writes=src_writes,
            tgt_predicate_reads=tgt_predicate_reads,
            overlap=frozenset(),
            state_var_overlap=frozenset(),
            reason=(
                f"blk[{tgt_serial}] is in dispatcher region "
                f"({len(context.dispatcher_blocks)} blocks)"
            ),
        )

    if not tgt_predicate_reads:
        return DispatcherAwareClassification(
            src_serial=int(src_serial),
            tgt_serial=int(tgt_serial),
            classification=DispatcherAwareEdgeClass.UNKNOWN,
            src_writes=src_writes,
            tgt_predicate_reads=tgt_predicate_reads,
            overlap=frozenset(),
            state_var_overlap=frozenset(),
            reason=f"blk[{tgt_serial}] has no readable tail predicate",
        )

    raw_overlap = src_writes & tgt_predicate_reads
    state_var_overlap = raw_overlap & excluded
    real_overlap = raw_overlap - excluded

    if real_overlap:
        return DispatcherAwareClassification(
            src_serial=int(src_serial),
            tgt_serial=int(tgt_serial),
            classification=DispatcherAwareEdgeClass.REAL_LOOP,
            src_writes=src_writes,
            tgt_predicate_reads=tgt_predicate_reads,
            overlap=raw_overlap,
            state_var_overlap=state_var_overlap,
            reason=(
                f"blk[{src_serial}] writes carrier {sorted(real_overlap)} "
                f"which blk[{tgt_serial}]'s predicate reads"
            ),
        )

    return DispatcherAwareClassification(
        src_serial=int(src_serial),
        tgt_serial=int(tgt_serial),
        classification=DispatcherAwareEdgeClass.SPURIOUS,
        src_writes=src_writes,
        tgt_predicate_reads=tgt_predicate_reads,
        overlap=raw_overlap,
        state_var_overlap=state_var_overlap,
        reason=(
            f"blk[{src_serial}] does not write any non-state var read by "
            f"blk[{tgt_serial}]'s predicate"
        ),
    )


def classify_backedges_dispatcher_aware(
    edges: Iterable[tuple[int, int]],
    *,
    block_writes: Mapping[int, frozenset[str]],
    block_predicate_reads: Mapping[int, frozenset[str]],
    context: DispatcherContext,
) -> tuple[DispatcherAwareClassification, ...]:
    """Classify many back-edges; preserves input order."""
    out: list[DispatcherAwareClassification] = []
    empty: frozenset[str] = frozenset()
    for src, tgt in edges:
        out.append(
            classify_backedge_dispatcher_aware(
                src_serial=int(src),
                tgt_serial=int(tgt),
                src_writes=block_writes.get(int(src), empty),
                tgt_predicate_reads=block_predicate_reads.get(int(tgt), empty),
                context=context,
            )
        )
    return tuple(out)


def summarize(
    classifications: Iterable[DispatcherAwareClassification],
) -> DispatcherAwareSummary:
    """Bucket classifications into the 4-class summary."""
    rt = rl = sp = un = 0
    for c in classifications:
        cls = c.classification
        if cls is DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP:
            rt += 1
        elif cls is DispatcherAwareEdgeClass.REAL_LOOP:
            rl += 1
        elif cls is DispatcherAwareEdgeClass.SPURIOUS:
            sp += 1
        else:
            un += 1
    return DispatcherAwareSummary(
        dispatcher_round_trip=rt,
        real_loop=rl,
        spurious=sp,
        unknown=un,
    )


def log_summary(
    summary: DispatcherAwareSummary,
    *,
    label: str = "",
) -> None:
    """One INFO line with the four counts."""
    prefix = f"{label}: " if label else ""
    logger.info(
        "%sback-edges total=%d dispatcher_round_trip=%d real_loop=%d "
        "spurious=%d unknown=%d",
        prefix,
        summary.total,
        summary.dispatcher_round_trip,
        summary.real_loop,
        summary.spurious,
        summary.unknown,
    )


__all__ = [
    "DispatcherAwareClassification",
    "DispatcherAwareEdgeClass",
    "DispatcherAwareSummary",
    "DispatcherContext",
    "classify_backedge_dispatcher_aware",
    "classify_backedges_dispatcher_aware",
    "log_summary",
    "summarize",
]
