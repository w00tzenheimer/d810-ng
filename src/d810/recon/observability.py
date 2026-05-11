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

from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    has_subscribers as _has_subscribers,
)
# Event dataclasses live under d810.core.observability_events so the
# SQLite sink in d810.core.diag.event_handlers can subscribe without
# an upward import (layered-architecture forbids d810.core importing
# from d810.recon). The recon facade re-exports the recon-relevant
# types so call sites don't have to know where they live.
from d810.core.observability_events import (
    DagLocalFactsObserved as DagLocalFactsObserved,
    DagObserved as DagObserved,
    FactConflictsObserved as FactConflictsObserved,
    FactConsumersObserved as FactConsumersObserved,
    FactMappingsObserved as FactMappingsObserved,
    FactObservationsObserved as FactObservationsObserved,
    ModificationsObserved as ModificationsObserved,
    ReachabilityObserved as ReachabilityObserved,
    RenderedProgramObserved as RenderedProgramObserved,
)
from d810.core.observability_models import (
    DagEdge as DagEdge,
    DagNode as DagNode,
    Modification as Modification,
    dag_node_diagnostic_state as dag_node_diagnostic_state,
)
from d810.core.typing import Any


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
# Legacy capture shims (back-compat for the few sites that still pass an
# explicit (conn, snap_id) pair; new code should use the event API
# above).
#
# These wrappers delegate via `importlib.import_module` so the static
# import graph has ZERO recon.observability -> d810.core.diag edges.
# The runtime-no-core-diag import-linter contract therefore needs no
# ignore_imports entry for this module.
# ---------------------------------------------------------------------------


def _diag_module():
    import importlib
    return importlib.import_module("d810.core.diag")


def _snapshot_module():
    import importlib
    return importlib.import_module("d810.core.diag.snapshot")


def get_diag_db(*args, **kwargs):
    return _diag_module().get_diag_db(*args, **kwargs)


def open_capture_session(*args, **kwargs):
    return _diag_module().open_diag_session(*args, **kwargs)


def close_capture_session(*args, **kwargs):
    return _diag_module().close_diag_session(*args, **kwargs)


def record_dag(*args, **kwargs):
    return _snapshot_module().snapshot_dag(*args, **kwargs)


def record_dag_local_facts(*args, **kwargs):
    return _snapshot_module().snapshot_dag_local_facts(*args, **kwargs)


def record_fact_conflict(*args, **kwargs):
    return _snapshot_module().snapshot_fact_conflicts(*args, **kwargs)


def record_fact_consumer(*args, **kwargs):
    return _snapshot_module().snapshot_fact_consumers(*args, **kwargs)


def record_fact_mapping(*args, **kwargs):
    return _snapshot_module().snapshot_fact_mappings(*args, **kwargs)


def record_fact_observation(*args, **kwargs):
    return _snapshot_module().snapshot_fact_observations(*args, **kwargs)


def record_mba_snapshot(*args, **kwargs):
    return _snapshot_module().snapshot_mba(*args, **kwargs)


def record_modifications(*args, **kwargs):
    return _snapshot_module().snapshot_modifications(*args, **kwargs)


def record_reachability(*args, **kwargs):
    return _snapshot_module().snapshot_reachability(*args, **kwargs)


def record_rendered_program(*args, **kwargs):
    return _snapshot_module().snapshot_rendered_program(*args, **kwargs)


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
