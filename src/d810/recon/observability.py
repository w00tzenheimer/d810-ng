"""Recon-domain diagnostic capture facade and event API.

This module hosts two layered surfaces:

1. **Event-based observability API** (the long-term boundary). Runtime
   recon code constructs ``*Observed`` events (frozen dataclasses) and
   calls ``observe_*`` helpers that publish them on the
   :mod:`d810.core.observability` bus. The diag sink subscribes in
   :mod:`d810.core.diag.event_handlers`; recon never touches
   :mod:`d810.core.diag`.

   Event names follow the past-tense ``<thing>Observed`` convention.
   Emit helpers follow the ``observe_<thing>`` convention.

2. **Legacy capture re-exports** (back-compat). The pre-event
   facade re-exported ``snapshot_*`` writers under ``record_*``
   names. These are still here so existing call sites compile during
   the Phase 5 per-subsystem migration; Phase 6 removes them once
   every call site is on the event API.

Read-side queries that drive runtime behaviour go through the
explicitly-documented behaviour bridge in
:mod:`d810.recon.flow.selected_alternate_edge_override`, not through
this module.

See:
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    has_subscribers as _has_subscribers,
)
from d810.core.typing import Any
from d810.core.observability_models import (
    DagEdge as DagEdge,
    DagNode as DagNode,
    Modification as Modification,
    dag_node_diagnostic_state as dag_node_diagnostic_state,
)

# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DagObserved:
    """Recon observed a DAG (state-graph) snapshot."""

    snapshot: SnapshotRef
    nodes: tuple[DagNode, ...]
    edges: tuple[DagEdge, ...]


@dataclass(frozen=True)
class DagLocalFactsObserved:
    """Recon observed node-local DAG facts for a LinearizedStateDag.

    ``dag`` is duck-typed: it must expose the attributes consumed by
    :func:`d810.core.diag.snapshot.snapshot_dag_local_facts` (``nodes``,
    each with ``owned_blocks``/``exclusive_blocks``/
    ``shared_suffix_blocks`` etc.).
    """

    snapshot: SnapshotRef
    dag: Any


@dataclass(frozen=True)
class FactObservationsObserved:
    """Recon observed a batch of fact observations for a function/snapshot."""

    snapshot: SnapshotRef
    func_ea: int
    observations: tuple[Any, ...]


@dataclass(frozen=True)
class FactMappingsObserved:
    """Recon observed a batch of fact mappings."""

    snapshot: SnapshotRef
    func_ea: int
    mappings: tuple[Any, ...]


@dataclass(frozen=True)
class FactConsumersObserved:
    """Recon observed a batch of fact-consumer records."""

    snapshot: SnapshotRef
    func_ea: int
    consumers: tuple[Any, ...]


@dataclass(frozen=True)
class FactConflictsObserved:
    """Recon observed a batch of fact conflicts."""

    snapshot: SnapshotRef
    func_ea: int
    conflicts: tuple[Any, ...]


@dataclass(frozen=True)
class ModificationsObserved:
    """Recon observed a batch of reconstruction modifications."""

    snapshot: SnapshotRef
    modifications: tuple[Modification, ...]


@dataclass(frozen=True)
class RenderedProgramObserved:
    """Recon observed a rendered linearized program.

    ``program`` is duck-typed: it must expose the attributes consumed
    by :func:`d810.core.diag.snapshot.snapshot_rendered_program`.
    """

    snapshot: SnapshotRef
    program: Any


@dataclass(frozen=True)
class ReachabilityObserved:
    """Recon observed block reachability/classification for a snapshot."""

    snapshot: SnapshotRef
    all_serials: frozenset[int]
    reachable: frozenset[int] = field(default_factory=frozenset)
    bst_serials: frozenset[int] = field(default_factory=frozenset)
    gutted: frozenset[int] = field(default_factory=frozenset)
    claimed_sources: frozenset[int] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Emit helpers
#
# Every helper is a fire-and-forget publish onto the diagnostic bus. The
# bus catches subscriber exceptions and never propagates them, so these
# helpers are safe to call from the optimizer hot path.
# ---------------------------------------------------------------------------


def observe_dag(
    snapshot: SnapshotRef,
    nodes,
    edges,
) -> None:
    """Publish a :class:`DagObserved` event."""
    _emit(DagObserved(
        snapshot=snapshot,
        nodes=tuple(nodes),
        edges=tuple(edges),
    ))


def observe_dag_local_facts(snapshot: SnapshotRef, dag: Any) -> None:
    """Publish a :class:`DagLocalFactsObserved` event."""
    _emit(DagLocalFactsObserved(snapshot=snapshot, dag=dag))


def observe_fact_observation(
    snapshot: SnapshotRef,
    func_ea: int,
    observations,
) -> None:
    """Publish a :class:`FactObservationsObserved` event."""
    _emit(FactObservationsObserved(
        snapshot=snapshot,
        func_ea=int(func_ea),
        observations=tuple(observations),
    ))


def observe_fact_mapping(
    snapshot: SnapshotRef,
    func_ea: int,
    mappings,
) -> None:
    """Publish a :class:`FactMappingsObserved` event."""
    _emit(FactMappingsObserved(
        snapshot=snapshot,
        func_ea=int(func_ea),
        mappings=tuple(mappings),
    ))


def observe_fact_consumer(
    snapshot: SnapshotRef,
    func_ea: int,
    consumers,
) -> None:
    """Publish a :class:`FactConsumersObserved` event."""
    _emit(FactConsumersObserved(
        snapshot=snapshot,
        func_ea=int(func_ea),
        consumers=tuple(consumers),
    ))


def observe_fact_conflict(
    snapshot: SnapshotRef,
    func_ea: int,
    conflicts,
) -> None:
    """Publish a :class:`FactConflictsObserved` event."""
    _emit(FactConflictsObserved(
        snapshot=snapshot,
        func_ea=int(func_ea),
        conflicts=tuple(conflicts),
    ))


def observe_modifications(
    snapshot: SnapshotRef,
    modifications,
) -> None:
    """Publish a :class:`ModificationsObserved` event."""
    _emit(ModificationsObserved(
        snapshot=snapshot,
        modifications=tuple(modifications),
    ))


def observe_rendered_program(snapshot: SnapshotRef, program: Any) -> None:
    """Publish a :class:`RenderedProgramObserved` event."""
    _emit(RenderedProgramObserved(snapshot=snapshot, program=program))


def observe_reachability(
    snapshot: SnapshotRef,
    *,
    all_serials,
    reachable=(),
    bst_serials=(),
    gutted=(),
    claimed_sources=(),
) -> None:
    """Publish a :class:`ReachabilityObserved` event."""
    _emit(ReachabilityObserved(
        snapshot=snapshot,
        all_serials=frozenset(all_serials),
        reachable=frozenset(reachable),
        bst_serials=frozenset(bst_serials),
        gutted=frozenset(gutted),
        claimed_sources=frozenset(claimed_sources),
    ))


def diagnostics_enabled() -> bool:
    """Cheap predicate: is any recon-event subscriber installed?

    Useful for callers that want to skip expensive payload construction
    when no diag subscriber is present. The bus catches subscriber
    exceptions either way, so calling :func:`observe_*` without a
    subscriber is a no-op, just slightly wasteful.
    """
    return any(
        _has_subscribers(t)
        for t in (
            DagObserved,
            DagLocalFactsObserved,
            FactObservationsObserved,
            FactMappingsObserved,
            FactConsumersObserved,
            FactConflictsObserved,
            ModificationsObserved,
            RenderedProgramObserved,
            ReachabilityObserved,
        )
    )


# ---------------------------------------------------------------------------
# Legacy capture re-exports (back-compat for Phase 5 migration)
#
# These keep existing call sites compiling while each subsystem is
# migrated to the event API. Phase 6 removes them.
# ---------------------------------------------------------------------------

from d810.core.diag import (
    close_diag_session as close_capture_session,
    get_diag_db as get_diag_db,
    open_diag_session as open_capture_session,
)
from d810.core.diag.snapshot import (
    snapshot_dag as record_dag,
    snapshot_dag_local_facts as record_dag_local_facts,
    snapshot_fact_conflicts as record_fact_conflict,
    snapshot_fact_consumers as record_fact_consumer,
    snapshot_fact_mappings as record_fact_mapping,
    snapshot_fact_observations as record_fact_observation,
    snapshot_mba as record_mba_snapshot,
    snapshot_modifications as record_modifications,
    snapshot_reachability as record_reachability,
    snapshot_rendered_program as record_rendered_program,
)


__all__ = [
    # Event dataclasses
    "DagLocalFactsObserved",
    "DagObserved",
    "FactConflictsObserved",
    "FactConsumersObserved",
    "FactMappingsObserved",
    "FactObservationsObserved",
    "ModificationsObserved",
    "ReachabilityObserved",
    "RenderedProgramObserved",
    # Neutral model types (kept here for backward compatibility)
    "DagEdge",
    "DagNode",
    "Modification",
    "dag_node_diagnostic_state",
    # Emit helpers
    "diagnostics_enabled",
    "observe_dag",
    "observe_dag_local_facts",
    "observe_fact_conflict",
    "observe_fact_consumer",
    "observe_fact_mapping",
    "observe_fact_observation",
    "observe_modifications",
    "observe_reachability",
    "observe_rendered_program",
    # Legacy re-exports (deprecated; removed in Phase 6)
    "close_capture_session",
    "get_diag_db",
    "open_capture_session",
    "record_dag",
    "record_dag_local_facts",
    "record_fact_conflict",
    "record_fact_consumer",
    "record_fact_mapping",
    "record_fact_observation",
    "record_mba_snapshot",
    "record_modifications",
    "record_reachability",
    "record_rendered_program",
]
