"""Terminal, per-candidate unflatten outcome records (ticket d81-rhu6).

The unflattener ends an attempt at several unrelated sites, and three of them
used to leave nothing behind: a maturity that received no Hex-Rays block
callback, a CFG transaction poisoned after earlier batches already committed,
and a clean bail whose only trace was a log line.  This module owns the one
authoritative record that closes every one of those paths.

The counters quoted by a record are collected here as they are computed
elsewhere in the run.  They are **diagnostic only** and never a decision
input: nothing in this module is consulted by an optimizer, and a missing
counter renders as ``?`` instead of changing an outcome.

Facts stay append-only.  The record names the ``plan_id`` of the corridor
coverage summary it closes; readers join on it rather than back-filling
``application_status`` on the summary row.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.core.maturity_labels import (
    IDA_MATURITY_NAMES,
    WITH_ZERO_MATURITY_NAMES,
    MaturityNumbering,
    mmat_name,
)
from d810.core.observability import emit, get_active_diag_path
from d810.core.observability_events import (
    UNFLATTEN_CANDIDATE_DISPOSITIONS,
    UnflattenCandidateOutcomeObserved,
)

logger = logging.getLogger("d810.unflat.outcome")

#: Re-exported so emit sites name a disposition without importing the event.
UNFLAT_OUTCOME_DISPOSITIONS = UNFLATTEN_CANDIDATE_DISPOSITIONS

#: Bound on the per-function counter table so a long headless batch cannot
#: grow it without limit.  Diagnostics must never become a memory leak.
_MAX_TRACKED_FUNCTIONS = 64

_UNFLAT_WHY_COMMAND = "python -m d810.diagnostics unflat-why"
_NO_ACTIVE_CAPTURE = "<diag-db>"


@dataclass(slots=True)
class UnflattenOutcomeCounters:
    """Counters a terminal record quotes.  Never a decision input."""

    handlers_recovered: int | None = None
    handlers_total: int | None = None
    dag_nodes: int | None = None
    dag_edges: int | None = None
    coverage_covered: int | None = None
    coverage_residual: int | None = None
    plan_id: str | None = None
    committed_batches: int = 0
    unresolved_anchors: tuple[tuple[int, int], ...] = ()


_COUNTER_FIELDS = frozenset(
    {
        "handlers_recovered",
        "handlers_total",
        "dag_nodes",
        "dag_edges",
        "coverage_covered",
        "coverage_residual",
        "plan_id",
    }
)

_COUNTERS: dict[int, UnflattenOutcomeCounters] = {}


def _slot(func_ea: int) -> UnflattenOutcomeCounters:
    key = int(func_ea)
    existing = _COUNTERS.get(key)
    if existing is not None:
        return existing
    if len(_COUNTERS) >= _MAX_TRACKED_FUNCTIONS:
        # Insertion-ordered dict: drop the least recently started function.
        _COUNTERS.pop(next(iter(_COUNTERS)))
    created = UnflattenOutcomeCounters()
    _COUNTERS[key] = created
    return created


def note_unflat_counters(func_ea: int, **fields: object) -> UnflattenOutcomeCounters:
    """Record counters for ``func_ea``; ``None`` values keep the prior value."""
    unknown = set(fields) - _COUNTER_FIELDS
    if unknown:
        raise ValueError(f"unknown unflatten counter(s): {sorted(unknown)}")
    slot = _slot(func_ea)
    for name, value in fields.items():
        if value is None:
            continue
        setattr(slot, name, value if name == "plan_id" else int(value))
    return slot


def note_unresolved_state_write(func_ea: int, block_serial: int, ea: int) -> None:
    """Record one state write the recovery could not resolve."""
    slot = _slot(func_ea)
    anchor = (int(block_serial), int(ea))
    if anchor in slot.unresolved_anchors:
        return
    slot.unresolved_anchors = tuple(sorted(set(slot.unresolved_anchors) | {anchor}))


def note_committed_batch(func_ea: int) -> int:
    """Count one committed CFG transaction and return the running total."""
    slot = _slot(func_ea)
    slot.committed_batches += 1
    return slot.committed_batches


def unflat_counters(func_ea: int) -> UnflattenOutcomeCounters:
    """Return the counters observed for ``func_ea`` so far."""
    return _COUNTERS.get(int(func_ea), UnflattenOutcomeCounters())


def has_unflat_counters(func_ea: int) -> bool:
    """Whether any unflatten work has been observed for ``func_ea``."""
    return int(func_ea) in _COUNTERS


def reset_unflat_counters(func_ea: int | None = None) -> None:
    """Drop counters for one function, or for every function."""
    if func_ea is None:
        _COUNTERS.clear()
        return
    _COUNTERS.pop(int(func_ea), None)


def derive_bail_reason(counters: UnflattenOutcomeCounters) -> str:
    """Name why a candidate ended without submitting or applying a plan."""
    residual = counters.coverage_residual
    if residual:
        return "residual_dispatcher_corridor"
    if residual is None and counters.coverage_covered is None:
        return "no_plan_submitted"
    return "clean_noop_no_progress"


def skipped_maturities(
    previous: int | None,
    current: int,
    *,
    numbering: MaturityNumbering = MaturityNumbering.WITH_ZERO,
) -> tuple[str, ...]:
    """Provider maturities crossed without a single block callback.

    Entering a maturity requires a callback, so any maturity strictly between
    the previously observed one and the current one received none at all.

    The default numbering is ``WITH_ZERO``: the live ``ida_hexrays.MMAT_*``
    constants start at ``MMAT_ZERO = 0``, so reading a raw ``mba.maturity``
    under ``IDA`` numbering names every maturity one step too late.
    """
    if previous is None:
        return ()
    try:
        low = int(previous)
        high = int(current)
    except (TypeError, ValueError):
        return ()
    if high <= low + 1:
        return ()
    names = (
        WITH_ZERO_MATURITY_NAMES
        if numbering is MaturityNumbering.WITH_ZERO
        else IDA_MATURITY_NAMES
    )
    return tuple(
        mmat_name(value, numbering=numbering)
        for value in range(low + 1, high)
        if 0 <= value < len(names)
    )


def unflat_why_hint(func_ea: int, db_path: str | None) -> str:
    """The exact command an operator runs next to expand this record."""
    database = db_path if db_path else _NO_ACTIVE_CAPTURE
    return f"{_UNFLAT_WHY_COMMAND} --db {database} --func 0x{int(func_ea):x}"


def _pair(left: int | None, right: int | None) -> str:
    return f"{'?' if left is None else left}/{'?' if right is None else right}"


def format_unflat_outcome(record: UnflattenCandidateOutcomeObserved) -> str:
    """Render one dense, anchored INFO line for ``record``."""
    maturity = record.maturity
    if maturity.startswith("MMAT_"):
        maturity = maturity[len("MMAT_") :]
    unresolved = (
        ",".join(f"blk{serial}@0x{ea:X}" for serial, ea in record.unresolved_anchors)
        or "none"
    )
    return (
        f"UNFLAT_OUTCOME func=0x{record.func_ea:x} maturity={maturity} "
        f"disposition={record.disposition} reason={record.reason} "
        f"handlers={_pair(record.handlers_recovered, record.handlers_total)} "
        f"dag={_pair(record.dag_nodes, record.dag_edges)} "
        f"coverage={_pair(record.coverage_covered, record.coverage_residual)} "
        f"unresolved={unresolved} "
        f'next="{record.next_hint}"'
    )


def build_unflat_candidate_outcome(
    *,
    session_id: str,
    func_ea: int,
    maturity: str,
    graph_fingerprint: str,
    candidate_identity: str,
    attempt: int,
    disposition: str,
    reason: str | None = None,
    plan_id: str | None = None,
    committed_batches_before: int | None = None,
    db_path: str | None = None,
) -> UnflattenCandidateOutcomeObserved:
    """Build the terminal record from the counters observed for ``func_ea``."""
    counters = unflat_counters(func_ea)
    return UnflattenCandidateOutcomeObserved(
        session_id=session_id,
        func_ea=int(func_ea),
        maturity=str(maturity),
        graph_fingerprint=str(graph_fingerprint),
        candidate_identity=str(candidate_identity),
        attempt=int(attempt),
        disposition=str(disposition),
        reason=reason if reason else derive_bail_reason(counters),
        plan_id=plan_id if plan_id is not None else counters.plan_id,
        handlers_recovered=counters.handlers_recovered,
        handlers_total=counters.handlers_total,
        dag_nodes=counters.dag_nodes,
        dag_edges=counters.dag_edges,
        coverage_covered=counters.coverage_covered,
        coverage_residual=counters.coverage_residual,
        unresolved_anchors=counters.unresolved_anchors,
        committed_batches_before=(
            counters.committed_batches
            if committed_batches_before is None
            else int(committed_batches_before)
        ),
        next_hint=unflat_why_hint(func_ea, db_path),
    )


def observe_unflat_candidate_outcome(
    *,
    session_id: str,
    func_ea: int,
    maturity: str,
    graph_fingerprint: str,
    candidate_identity: str,
    attempt: int,
    disposition: str,
    reason: str | None = None,
    plan_id: str | None = None,
    committed_batches_before: int | None = None,
) -> UnflattenCandidateOutcomeObserved | None:
    """Log and publish one terminal unflatten outcome.

    Never raises for a diagnostic reason: an invalid *disposition* is a wiring
    bug and does raise, but a failure to resolve the active capture path only
    degrades the ``next`` hint.
    """
    if disposition not in UNFLAT_OUTCOME_DISPOSITIONS:
        raise ValueError(f"unknown unflatten disposition: {disposition!r}")
    try:
        db_path = get_active_diag_path()
    except Exception:
        db_path = None
    record = build_unflat_candidate_outcome(
        session_id=session_id,
        func_ea=func_ea,
        maturity=maturity,
        graph_fingerprint=graph_fingerprint,
        candidate_identity=candidate_identity,
        attempt=attempt,
        disposition=disposition,
        reason=reason,
        plan_id=plan_id,
        committed_batches_before=committed_batches_before,
        db_path=db_path,
    )
    logger.info("%s", format_unflat_outcome(record))
    emit(record)
    return record


__all__ = [
    "UNFLAT_OUTCOME_DISPOSITIONS",
    "UnflattenOutcomeCounters",
    "build_unflat_candidate_outcome",
    "derive_bail_reason",
    "format_unflat_outcome",
    "has_unflat_counters",
    "note_committed_batch",
    "note_unflat_counters",
    "note_unresolved_state_write",
    "observe_unflat_candidate_outcome",
    "reset_unflat_counters",
    "skipped_maturities",
    "unflat_counters",
    "unflat_why_hint",
]
