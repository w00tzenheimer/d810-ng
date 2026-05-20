"""Recon-domain diagnostic capture facade and event API.

Runtime recon code constructs ``*Observed`` events (frozen dataclasses)
and calls ``observe_*`` helpers that publish them on the
:mod:`d810.core.observability` bus. A backend subscriber listens via
the abstract observability interface; recon never imports the backend.

Event names follow the past-tense ``<thing>Observed`` convention.
Emit helpers follow the ``observe_<thing>`` convention.

Read-side queries that drive runtime behaviour should consume
in-memory fact views or runtime evidence directly, not diagnostic
subscribers or SQLite sinks.

See:
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    has_subscribers as _has_subscribers,
)
# Event dataclasses live under d810.core.observability_events so a
# backend subscriber can listen without an upward import
# (layered-architecture forbids d810.core importing from d810.recon).
# The recon facade re-exports the recon-relevant types so call sites
# don't have to know where they live.
from d810.core.observability_events import (
    BranchOwnershipProofsObserved as BranchOwnershipProofsObserved,
    BstIntervalDispatcherObserved as BstIntervalDispatcherObserved,
    DagFrontierClosureDiagnosticsObserved as DagFrontierClosureDiagnosticsObserved,
    DagLocalFactsObserved as DagLocalFactsObserved,
    DagObserved as DagObserved,
    FactConflictsObserved as FactConflictsObserved,
    FactConsumersObserved as FactConsumersObserved,
    FactMappingsObserved as FactMappingsObserved,
    FactObservationsObserved as FactObservationsObserved,
    ModificationsObserved as ModificationsObserved,
    ReachabilityObserved as ReachabilityObserved,
    RenderedProgramObserved as RenderedProgramObserved,
    StateDispatcherRowsObserved as StateDispatcherRowsObserved,
    StateTransitionDispatchResolutionsObserved as StateTransitionDispatchResolutionsObserved,
    SwitchCaseTransitionFactsObserved as SwitchCaseTransitionFactsObserved,
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


def observe_dag_frontier_closure_diagnostics(
    snapshot: SnapshotRef,
    rows,
) -> None:
    """Publish DAG-frontier closure verifier diagnostics."""
    _emit(DagFrontierClosureDiagnosticsObserved(
        snapshot=snapshot,
        rows=tuple(rows),
    ))


def observe_bst_interval_dispatcher(
    *,
    func_ea: int,
    maturity: str,
    dispatcher_entry_block: int | None,
    rows,
) -> None:
    """Publish recovered BST interval-dispatcher rows."""
    _emit(BstIntervalDispatcherObserved(
        func_ea=int(func_ea),
        maturity=str(maturity),
        dispatcher_entry_block=(
            int(dispatcher_entry_block)
            if dispatcher_entry_block is not None else None
        ),
        rows=tuple(rows),
    ))


def observe_state_dispatcher_rows(
    *,
    func_ea: int,
    maturity: str,
    dispatcher_entry_block: int | None,
    dispatcher_kind: str,
    rows,
) -> None:
    """Publish exact state-dispatcher rows."""
    _emit(StateDispatcherRowsObserved(
        func_ea=int(func_ea),
        maturity=str(maturity),
        dispatcher_entry_block=(
            int(dispatcher_entry_block)
            if dispatcher_entry_block is not None else None
        ),
        dispatcher_kind=str(dispatcher_kind),
        rows=tuple(rows),
    ))


def observe_state_transition_dispatch_resolutions(
    snapshot: SnapshotRef,
    rows,
) -> None:
    """Publish exact state-dispatcher transition resolution rows."""
    _emit(StateTransitionDispatchResolutionsObserved(
        snapshot=snapshot,
        rows=tuple(rows),
    ))


def observe_switch_case_transition_facts(
    snapshot: SnapshotRef,
    rows,
) -> None:
    """Publish switch-table case transition facts."""
    _emit(SwitchCaseTransitionFactsObserved(
        snapshot=snapshot,
        rows=tuple(rows),
    ))


def observe_branch_ownership_proofs(
    snapshot: SnapshotRef,
    rows,
) -> None:
    """Publish conditional branch ownership proof rows."""
    _emit(BranchOwnershipProofsObserved(
        snapshot=snapshot,
        rows=tuple(rows),
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
            BstIntervalDispatcherObserved,
            DagFrontierClosureDiagnosticsObserved,
            DagLocalFactsObserved,
            FactObservationsObserved,
            FactMappingsObserved,
            FactConsumersObserved,
            FactConflictsObserved,
            ModificationsObserved,
            RenderedProgramObserved,
            ReachabilityObserved,
            StateDispatcherRowsObserved,
            StateTransitionDispatchResolutionsObserved,
            SwitchCaseTransitionFactsObserved,
            BranchOwnershipProofsObserved,
        )
    )


__all__ = [
    # Event dataclasses
    "BstIntervalDispatcherObserved",
    "BranchOwnershipProofsObserved",
    "DagFrontierClosureDiagnosticsObserved",
    "DagLocalFactsObserved",
    "DagObserved",
    "FactConflictsObserved",
    "FactConsumersObserved",
    "FactMappingsObserved",
    "FactObservationsObserved",
    "ModificationsObserved",
    "ReachabilityObserved",
    "RenderedProgramObserved",
    "StateDispatcherRowsObserved",
    "StateTransitionDispatchResolutionsObserved",
    "SwitchCaseTransitionFactsObserved",
    # Neutral model types (kept here for backward compatibility)
    "DagEdge",
    "DagNode",
    "Modification",
    "dag_node_diagnostic_state",
    # Emit helpers
    "diagnostics_enabled",
    "observe_dag",
    "observe_bst_interval_dispatcher",
    "observe_state_dispatcher_rows",
    "observe_state_transition_dispatch_resolutions",
    "observe_switch_case_transition_facts",
    "observe_branch_ownership_proofs",
    "observe_dag_frontier_closure_diagnostics",
    "observe_dag_local_facts",
    "observe_fact_conflict",
    "observe_fact_consumer",
    "observe_fact_mapping",
    "observe_fact_observation",
    "observe_modifications",
    "observe_reachability",
    "observe_rendered_program",
]
