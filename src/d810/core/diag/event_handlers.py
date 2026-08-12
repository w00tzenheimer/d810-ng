"""SQLite event handlers that persist diagnostic observations.

Subscribes to the observation events declared in
:mod:`d810.core.observability_recon`, :mod:`d810.core.observability_cfg`, and
:mod:`d810.hexrays.observability`. When the manager boots a diag
session, :func:`install_diag_event_handlers` registers these handlers
on the :mod:`d810.core.observability` bus; runtime producers then
publish events that the handlers persist into the active diag DB.

Architecture
------------

- Producers carry a :class:`SnapshotRef`. The
  :class:`CaptureMbaSnapshotRequested` handler inserts a row in
  ``snapshots`` and stores
  ``SnapshotRef.key`` -> ``snapshots.id`` in a per-session mapping.
- Follow-on events (``DagObserved``, ``ModificationsObserved`` ...)
  resolve their ``snapshot.key`` to the int id and call the matching
  ``snapshot_*`` writer.
- A missing mapping is a soft warning that no-ops the handler; the
  event bus also swallows handler exceptions, so a stale event can
  never break the optimizer.

Handler installation is idempotent: calling
:func:`install_diag_event_handlers` twice is safe; the second call
unsubscribes any previously installed handlers first so we never
double-persist.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Mapping

from d810._vendor.peewee import fn
from d810.core import logging as _d810_logging
from d810.core.diag import active_diag_db, diag_models_on, get_diag_conn
from d810.core.diag.deobfuscation_case import materialize_closed_deobfuscation_case
from d810.core.diag.models import CfgProvenance, FactConsumer, Snapshot
from d810.core.diag.lifecycle import (
    persist_cfg_transaction_attempt,
    persist_diagnostic_session_transition,
    persist_evidence_generation,
    persist_frontend_normalization_plan_intent,
    persist_identity_decision,
    persist_lifecycle_event,
    persist_mutation_plan,
    persist_mutation_receipt,
    persist_pass_contract_evidence,
    persist_semantic_fragment_route_oracle,
    persist_semantic_output_verified,
)
from d810.core.formatting import format_block_id
from d810.core.diag.snapshot import (
    _dual,
    snapshot_branch_witness_decisions,
    snapshot_branch_ownership_proofs,
    snapshot_condition_chain_interval_dispatcher_rows,
    snapshot_exit_path_shortcut_decisions,
    snapshot_dag_frontier_closure_diagnostics,
    snapshot_dag,
    snapshot_dag_local_facts,
    snapshot_fact_conflicts,
    snapshot_fact_consumers,
    snapshot_fact_mappings,
    snapshot_fact_observations,
    snapshot_mba,
    snapshot_modifications,
    snapshot_reachability,
    snapshot_rendered_program,
    snapshot_state_dispatcher_rows,
    snapshot_state_transition_dispatch_resolutions,
    snapshot_switch_case_transition_facts,
    snapshot_watch_transition,
)
from d810.core.observability import (
    SnapshotRef,
    register_snapshot_id_resolver,
    subscribe,
    unsubscribe,
)
from d810.core.observability_events import (
    BranchOwnershipProofsObserved,
    BranchWitnessDecisionsObserved,
    ConditionChainIntervalDispatcherObserved,
    CaptureMbaSnapshotRequested,
    CfgTransactionAttemptObserved,
    CfgProvenanceForLatestSnapshot,
    CfgProvenanceObserved,
    ExitPathShortcutDecisionsObserved,
    DagFrontierClosureDiagnosticsObserved,
    DagLocalFactsObserved,
    DagObserved,
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    FrontendNormalizationPlanIntentObserved,
    FactConflictsObserved,
    FactConsumersForLatestSnapshot,
    FactConsumersObserved,
    FactMappingsObserved,
    FactObservationsObserved,
    ModificationsObserved,
    LifecycleEventObserved,
    IdentityDecisionObserved,
    InputIdentityResolutionObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
    OptblockCallbackExceptionObserved,
    PassContractEvidencePublished,
    SemanticFragmentRouteOracleComparedObserved,
    SemanticOutputVerifiedObserved,
    ReachabilityObserved,
    RenderedProgramObserved,
    StateDispatcherRowsObserved,
    StateTransitionDispatchResolutionsObserved,
    SwitchCaseTransitionFactsObserved,
    UnflattenDispatcherCorridorCoverageObserved,
    WatchBlockTransitionObserved,
)

_logger = _d810_logging.getLogger("d810.diag.event_handlers")


def _report_diag_persistence_failure(where: str) -> None:
    """Best-effort visibility for a subscriber that cannot persist evidence."""
    try:
        _logger.exception("diagnostic persistence failed in %s", where)
    except BaseException:
        # Observability must never become a second callback failure.
        return


# ---------------------------------------------------------------------------
# SnapshotRef -> SQLite snapshots.id mapping
# ---------------------------------------------------------------------------

# Lives in module scope, gated by a lock. One process can have at most
# one active diag session at a time (open_diag_session / close_diag_session
# in d810.core.diag), so a single dict is sufficient.

_map_lock = threading.Lock()
_snapshot_id_by_ref_key: dict[str, int] = {}

# Per-session buffer of CFG provenance events. The diag schema persists
# these under the next snapshots row, so we accumulate observations
# between MBA captures and flush them during snapshot_mba.
_provenance_lock = threading.Lock()
_pending_provenance: list[CfgProvenanceObserved] = []

_condition_chain_interval_lock = threading.Lock()
_pending_condition_chain_intervals: list[ConditionChainIntervalDispatcherObserved] = []

_state_dispatcher_lock = threading.Lock()
_pending_state_dispatcher_rows: list[StateDispatcherRowsObserved] = []
_unflatten_dispatcher_corridor_lock = threading.Lock()
_pending_unflatten_dispatcher_corridor_coverage: list[
    UnflattenDispatcherCorridorCoverageObserved
] = []
_branch_witness_lock = threading.Lock()
_pending_branch_witness_decisions: list[BranchWitnessDecisionsObserved] = []
_exit_path_shortcut_lock = threading.Lock()
_pending_exit_path_shortcut_decisions: list[ExitPathShortcutDecisionsObserved] = []


def _resolve_snapshot_id(snap: SnapshotRef) -> int | None:
    """Return the SQLite id bound to ``snap.key``, or ``None``."""
    with _map_lock:
        return _snapshot_id_by_ref_key.get(snap.key)


def _bind_snapshot_id(snap: SnapshotRef, snap_id: int) -> None:
    with _map_lock:
        _snapshot_id_by_ref_key[snap.key] = int(snap_id)


def _clear_snapshot_mapping() -> None:
    with _map_lock:
        _snapshot_id_by_ref_key.clear()


def _conn_for(snap: SnapshotRef) -> sqlite3.Connection | None:
    """Acquire the function-scoped diag connection, or ``None``."""
    try:
        return get_diag_conn(int(snap.func_ea))
    except Exception:
        _logger.exception("get_diag_db failed for func_ea=0x%x", snap.func_ea)
        return None


def _func_hex(func_ea: int) -> str:
    """Canonical persisted spelling of a function EA (matches the writers)."""
    return f"0x{int(func_ea) & 0xFFFFFFFFFFFFFFFF:016x}"


def _latest_snapshot_id_for_func(func_ea: int) -> int | None:
    """Return the id of the newest ``snapshots`` row for ``func_ea`` (ORM).

    Callers reach here only after :func:`_conn_for` / ``get_diag_conn`` has
    resolved the active capture db, so ``active_diag_db()`` is the same db the
    raw connection wraps. We bind the Models to it with ``diag_models_on``
    (``bind_ctx``) for the read, never the mutable process-global bind.
    """
    db = active_diag_db()
    if db is None:
        return None
    with diag_models_on(db):
        row = (
            Snapshot.select(Snapshot.id)
            .where(Snapshot.func_ea_hex == _func_hex(func_ea))
            .order_by(Snapshot.id.desc())
            .first()
        )
        return int(row.id) if row is not None else None


# ---------------------------------------------------------------------------
# Handler bodies
# ---------------------------------------------------------------------------


def _handle_capture_mba(ev: CaptureMbaSnapshotRequested) -> None:
    snap = ev.snapshot
    conn = _conn_for(snap)
    if conn is None:
        return
    snap_id = snapshot_mba(
        conn,
        list(ev.blocks),
        label=snap.label,
        func_ea=snap.func_ea,
        maturity=snap.maturity,
        phase=snap.phase,
        maturity_json=snap.maturity_json,
    )
    _bind_snapshot_id(snap, snap_id)
    # Flush any CfgProvenanceObserved events that arrived between the
    # last snapshot and this one. They share the "next snapshot"
    # attribution semantics with the legacy IoC drain.
    _flush_pending_provenance(conn, snap_id)
    _flush_pending_condition_chain_intervals(conn, snap_id, snap.func_ea)
    _flush_pending_state_dispatcher_rows(conn, snap_id, snap.func_ea)
    _flush_pending_unflatten_dispatcher_corridor_coverage(
        conn, snap_id, snap.func_ea
    )
    _flush_pending_branch_witness_decisions(conn, snap_id, snap.func_ea)
    _flush_pending_exit_path_shortcut_decisions(conn, snap_id, snap.func_ea)
    # Block-lineage drain is fired by snapshot_mba via
    # BlockLineageDrainRequested(conn, snap_id); cfg.block_lineage's
    # subscriber writes the rows. No explicit invocation here.


def _handle_diagnostic_session(ev: DiagnosticSessionObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        transitioned = persist_diagnostic_session_transition(conn, ev)
        if transitioned and ev.status in {"finished", "failed"}:
            with conn:
                materialize_closed_deobfuscation_case(conn, ev.session_id)


def _handle_input_identity_resolution(ev: InputIdentityResolutionObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=ev.session_id,
            func_ea=int(ev.func_ea),
            event_kind="input_identity_resolution",
            summary=f"input identity {ev.status}",
            payload={
                "status": ev.status,
                "provenance": ev.provenance,
                "mismatch_field": ev.mismatch_field,
                "external_evidence_allowed": ev.external_evidence_allowed,
                "database_uuid": ev.database_uuid,
            },
            timestamp=ev.timestamp,
        ),
        snapshot_id=None,
    )


def _handle_lifecycle_event(ev: LifecycleEventObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    snapshot_id = None if ev.snapshot is None else _resolve_snapshot_id(ev.snapshot)
    persist_lifecycle_event(conn, ev, snapshot_id=snapshot_id)


def _handle_evidence_generation(ev: EvidenceGenerationObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    snapshot_id = None if ev.snapshot is None else _resolve_snapshot_id(ev.snapshot)
    persist_evidence_generation(conn, ev, snapshot_id=snapshot_id)


def _handle_identity_decision(ev: IdentityDecisionObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    snapshot_id = None if ev.snapshot is None else _resolve_snapshot_id(ev.snapshot)
    persist_identity_decision(conn, ev, snapshot_id=snapshot_id)


def _handle_frontend_normalization_plan_intent(
    ev: FrontendNormalizationPlanIntentObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_frontend_normalization_plan_intent(conn, ev)


def _handle_semantic_output_verified(ev: SemanticOutputVerifiedObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_semantic_output_verified(conn, ev)


def _handle_pass_contract_evidence(ev: PassContractEvidencePublished) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_pass_contract_evidence(conn, ev)


def _handle_mutation_plan(ev: MutationPlanObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_mutation_plan(conn, ev)


def _handle_mutation_receipt(ev: MutationReceiptObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_mutation_receipt(conn, ev)


def _handle_cfg_transaction_attempt(ev: CfgTransactionAttemptObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_cfg_transaction_attempt(conn, ev)


def _handle_semantic_fragment_route_oracle(
    ev: SemanticFragmentRouteOracleComparedObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is not None:
        with conn:
            persist_semantic_fragment_route_oracle(conn, ev)


def _handle_dag(ev: DagObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        _logger.debug(
            "DagObserved without resolved snapshot mapping (key=%s)",
            ev.snapshot.key,
        )
        return
    snapshot_dag(conn, snap_id, list(ev.nodes), list(ev.edges))


def _handle_dag_frontier_closure_diagnostics(
    ev: DagFrontierClosureDiagnosticsObserved,
) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_dag_frontier_closure_diagnostics(conn, snap_id, ev.rows)


def _handle_condition_chain_interval_dispatcher(
    ev: ConditionChainIntervalDispatcherObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.rows:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        _buffer_condition_chain_interval_dispatcher(ev)
        return
    snapshot_condition_chain_interval_dispatcher_rows(
        conn,
        snap_id,
        ev.rows,
        dispatcher_entry_block=ev.dispatcher_entry_block,
        maturity=ev.maturity,
    )


def _buffer_condition_chain_interval_dispatcher(
    ev: ConditionChainIntervalDispatcherObserved,
) -> None:
    with _condition_chain_interval_lock:
        _pending_condition_chain_intervals.append(ev)


def _flush_pending_condition_chain_intervals(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
) -> None:
    with _condition_chain_interval_lock:
        matching = [
            ev
            for ev in _pending_condition_chain_intervals
            if int(ev.func_ea) == int(func_ea)
        ]
        if matching:
            _pending_condition_chain_intervals[:] = [
                ev
                for ev in _pending_condition_chain_intervals
                if int(ev.func_ea) != int(func_ea)
            ]
    for ev in matching:
        snapshot_condition_chain_interval_dispatcher_rows(
            conn,
            int(snap_id),
            ev.rows,
            dispatcher_entry_block=ev.dispatcher_entry_block,
            maturity=ev.maturity,
        )


def _handle_state_dispatcher_rows(
    ev: StateDispatcherRowsObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.rows:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        _buffer_state_dispatcher_rows(ev)
        return
    snapshot_state_dispatcher_rows(
        conn,
        snap_id,
        ev.rows,
        dispatcher_entry_block=ev.dispatcher_entry_block,
        dispatcher_kind=ev.dispatcher_kind,
        maturity=ev.maturity,
    )


def _buffer_state_dispatcher_rows(
    ev: StateDispatcherRowsObserved,
) -> None:
    with _state_dispatcher_lock:
        _pending_state_dispatcher_rows.append(ev)


def _flush_pending_state_dispatcher_rows(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
) -> None:
    with _state_dispatcher_lock:
        matching = [
            ev
            for ev in _pending_state_dispatcher_rows
            if int(ev.func_ea) == int(func_ea)
        ]
        if matching:
            _pending_state_dispatcher_rows[:] = [
                ev
                for ev in _pending_state_dispatcher_rows
                if int(ev.func_ea) != int(func_ea)
            ]
    for ev in matching:
        snapshot_state_dispatcher_rows(
            conn,
            int(snap_id),
            ev.rows,
            dispatcher_entry_block=ev.dispatcher_entry_block,
            dispatcher_kind=ev.dispatcher_kind,
            maturity=ev.maturity,
        )


def _handle_unflatten_dispatcher_corridor_coverage(
    ev: UnflattenDispatcherCorridorCoverageObserved,
) -> None:
    """Persist typed lowerer coverage facts at the current/next capture.

    A final transaction outcome has to remain inspectable even when the
    transaction does not cause a later MBA capture (for example, a clean
    preflight rejection).  In that narrow case the diagnostic subscriber owns
    a zero-block outcome snapshot, flushes the pending planned facts into it,
    and persists the final outcome beside them.  Producers still emit only
    structured observations and never access SQLite themselves.
    """
    try:
        conn = get_diag_conn(int(ev.func_ea))
        if conn is None or not ev.observations:
            return
        # A closed sqlite connection can survive a stale subscriber lifecycle.
        # Probe it here so the loss becomes a logged diagnostic failure rather
        # than an event-bus no-op hidden behind a later write exception.
        conn.execute("SELECT 1")
        snap_id = _latest_snapshot_id_for_func(ev.func_ea)
        application_status = _terminal_unflatten_dispatcher_outcome_status(ev)
        if snap_id is None:
            if application_status is None:
                _buffer_unflatten_dispatcher_corridor_coverage(ev)
                return
            snap_id = _snapshot_unflatten_dispatcher_terminal_outcome(
                conn,
                ev,
                application_status=application_status,
            )
        if application_status is not None:
            _flush_pending_unflatten_dispatcher_corridor_coverage(
                conn,
                int(snap_id),
                ev.func_ea,
                plan_id=_unflatten_dispatcher_plan_id(ev),
            )
        snapshot_fact_observations(conn, snap_id, ev.func_ea, ev.observations)
    except Exception:
        _report_diag_persistence_failure("unflatten_dispatcher_corridor_coverage")
        return


def _handle_optblock_callback_exception(
    ev: OptblockCallbackExceptionObserved,
) -> None:
    """Persist a SWIG-boundary callback failure as one anchored fact."""
    try:
        conn = get_diag_conn(int(ev.func_ea))
        if conn is None:
            return
        conn.execute("SELECT 1")
        snap_id = _latest_snapshot_id_for_func(ev.func_ea)
        if snap_id is None:
            snap_id = snapshot_mba(
                conn,
                [],
                label="optblock_callback_exception",
                func_ea=int(ev.func_ea),
                maturity=str(ev.maturity),
                phase="post_d810",
            )
        block_anchor = (
            f"blk{int(ev.block_serial)}@0x{int(ev.block_ea):x}"
            if ev.block_serial is not None and ev.block_ea is not None
            else "unknown"
        )
        func_ea = int(ev.func_ea)
        fact_id = (
            "optblock-callback-exception:"
            f"func=0x{func_ea:x}:maturity={ev.maturity}:"
            f"{block_anchor}:{ev.error_type}:occurrence={ev.occurrence_id}"
        )
        snapshot_fact_observations(
            conn,
            int(snap_id),
            func_ea,
            (
                {
                    "fact_id": fact_id,
                    "kind": "OptblockCallbackException",
                    "semantic_key": (
                        f"optblock_callback_exception:{block_anchor}:{ev.error_type}"
                    ),
                    "maturity": str(ev.maturity),
                    "phase": "optblock_callback",
                    "confidence": 1.0,
                    "source_block": ev.block_serial,
                    "source_ea": ev.block_ea,
                    "payload": {
                        "func_ea": f"0x{func_ea:x}",
                        "maturity": str(ev.maturity),
                        "block_anchor": block_anchor,
                        "block_serial": ev.block_serial,
                        "block_ea": (
                            f"0x{int(ev.block_ea):x}"
                            if ev.block_ea is not None
                            else None
                        ),
                        "error_type": str(ev.error_type),
                        "error_message": str(ev.error_message),
                        "traceback_text": str(ev.traceback_text),
                        "occurrence_id": str(ev.occurrence_id),
                    },
                    "evidence": (block_anchor, "optblock_callback_exception"),
                },
            ),
        )
    except Exception:
        _report_diag_persistence_failure("optblock_callback_exception")
        return


def _observation_field(observation: object, field_name: str, default: object) -> object:
    if isinstance(observation, Mapping):
        return observation.get(field_name, default)
    return getattr(observation, field_name, default)


def _terminal_unflatten_dispatcher_outcome_status(
    ev: UnflattenDispatcherCorridorCoverageObserved,
) -> str | None:
    """Return one terminal status only when every observation agrees."""
    statuses: set[str] = set()
    for observation in ev.observations:
        payload = _observation_field(observation, "payload", {})
        if not isinstance(payload, Mapping):
            return None
        status = payload.get("application_status")
        if status is None:
            return None
        statuses.add(str(status))
    if len(statuses) != 1:
        return None
    status = statuses.pop()
    if (
        status == "applied"
        or status.startswith("rejected_")
        or status == "poisoned_restart_required"
    ):
        return status
    return None


def _snapshot_unflatten_dispatcher_terminal_outcome(
    conn: sqlite3.Connection,
    ev: UnflattenDispatcherCorridorCoverageObserved,
    *,
    application_status: str,
) -> int:
    """Create the explicit zero-block diagnostic anchor for a final outcome."""
    first = ev.observations[0]
    maturity = str(_observation_field(first, "maturity", "unknown"))
    # ``snapshots.phase`` is intentionally a closed maturity-lifecycle enum;
    # transaction facts retain their finer-grained ``patch_transaction`` phase
    # in ``fact_observations.phase`` while the synthetic anchor is post-D810.
    del first
    return snapshot_mba(
        conn,
        [],
        label=f"unflatten_dispatcher_outcome:{application_status}",
        func_ea=int(ev.func_ea),
        maturity=maturity,
        phase="post_d810",
    )


def _buffer_unflatten_dispatcher_corridor_coverage(
    ev: UnflattenDispatcherCorridorCoverageObserved,
) -> None:
    with _unflatten_dispatcher_corridor_lock:
        _pending_unflatten_dispatcher_corridor_coverage.append(ev)


def _unflatten_dispatcher_plan_id(
    ev: UnflattenDispatcherCorridorCoverageObserved,
) -> str | None:
    """Return one stable plan scope only when all observations agree."""
    plan_ids: set[str] = set()
    for observation in ev.observations:
        payload = _observation_field(observation, "payload", {})
        if not isinstance(payload, Mapping):
            return None
        plan_id = payload.get("plan_id")
        if plan_id is None:
            return None
        normalized = str(plan_id).strip()
        if not normalized:
            return None
        plan_ids.add(normalized)
    return next(iter(plan_ids)) if len(plan_ids) == 1 else None


def _flush_pending_unflatten_dispatcher_corridor_coverage(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
    *,
    plan_id: str | None = None,
) -> None:
    with _unflatten_dispatcher_corridor_lock:
        matching = [
            ev
            for ev in _pending_unflatten_dispatcher_corridor_coverage
            if int(ev.func_ea) == int(func_ea)
            and (
                plan_id is None
                or _unflatten_dispatcher_plan_id(ev) == str(plan_id)
            )
        ]
        if matching:
            matching_ids = {id(ev) for ev in matching}
            _pending_unflatten_dispatcher_corridor_coverage[:] = [
                ev
                for ev in _pending_unflatten_dispatcher_corridor_coverage
                if id(ev) not in matching_ids
            ]
    for ev in matching:
        snapshot_fact_observations(conn, int(snap_id), ev.func_ea, ev.observations)


def _handle_state_transition_dispatch_resolutions(
    ev: StateTransitionDispatchResolutionsObserved,
) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_state_transition_dispatch_resolutions(
        conn,
        snap_id,
        ev.rows,
    )


def _handle_switch_case_transition_facts(
    ev: SwitchCaseTransitionFactsObserved,
) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    rows = tuple(
        row.to_diag_row() if hasattr(row, "to_diag_row") else row for row in ev.rows
    )
    snapshot_switch_case_transition_facts(conn, snap_id, rows)


def _handle_branch_ownership_proofs(ev: BranchOwnershipProofsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_branch_ownership_proofs(conn, snap_id, ev.rows)


def _handle_branch_witness_decisions(
    ev: BranchWitnessDecisionsObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.rows:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        _buffer_branch_witness_decisions(ev)
        return
    snapshot_branch_witness_decisions(conn, snap_id, ev.rows)


def _buffer_branch_witness_decisions(ev: BranchWitnessDecisionsObserved) -> None:
    with _branch_witness_lock:
        _pending_branch_witness_decisions.append(ev)


def _flush_pending_branch_witness_decisions(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
) -> None:
    with _branch_witness_lock:
        matching = [
            ev
            for ev in _pending_branch_witness_decisions
            if int(ev.func_ea) == int(func_ea)
        ]
        if matching:
            _pending_branch_witness_decisions[:] = [
                ev
                for ev in _pending_branch_witness_decisions
                if int(ev.func_ea) != int(func_ea)
            ]
    for ev in matching:
        snapshot_branch_witness_decisions(conn, int(snap_id), ev.rows)


def _handle_exit_path_shortcut_decisions(
    ev: ExitPathShortcutDecisionsObserved,
) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.rows:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        _buffer_exit_path_shortcut_decisions(ev)
        return
    snapshot_exit_path_shortcut_decisions(conn, snap_id, ev.rows)


def _buffer_exit_path_shortcut_decisions(
    ev: ExitPathShortcutDecisionsObserved,
) -> None:
    with _exit_path_shortcut_lock:
        _pending_exit_path_shortcut_decisions.append(ev)


def _flush_pending_exit_path_shortcut_decisions(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
) -> None:
    with _exit_path_shortcut_lock:
        matching = [
            ev
            for ev in _pending_exit_path_shortcut_decisions
            if int(ev.func_ea) == int(func_ea)
        ]
        if matching:
            _pending_exit_path_shortcut_decisions[:] = [
                ev
                for ev in _pending_exit_path_shortcut_decisions
                if int(ev.func_ea) != int(func_ea)
            ]
    for ev in matching:
        snapshot_exit_path_shortcut_decisions(conn, int(snap_id), ev.rows)


def _handle_dag_local_facts(ev: DagLocalFactsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_dag_local_facts(conn, snap_id, ev.dag)


def _handle_fact_observation(ev: FactObservationsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_fact_observations(conn, snap_id, ev.func_ea, ev.observations)


def _handle_fact_mapping(ev: FactMappingsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_fact_mappings(conn, snap_id, ev.func_ea, ev.mappings)


def _handle_fact_consumer(ev: FactConsumersObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_fact_consumers(conn, snap_id, ev.func_ea, ev.consumers)


def _handle_fact_consumers_latest(ev: FactConsumersForLatestSnapshot) -> None:
    "Late-binding fact-consumer writer.\n\n    Used by preanalysis-time post-hoc auditing where no specific\n    just-emitted capture exists. The handler finds the latest\n    ``snapshots`` row for ``func_ea`` and writes consumer rows there\n    after deduplicating against existing rows.\n"
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.consumers:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        return
    func_hex = _func_hex(ev.func_ea)
    db = active_diag_db()
    if db is None:
        return
    pending = []
    with diag_models_on(db):
        for consumer in ev.consumers:
            exists = (
                FactConsumer.select(FactConsumer.consumer_index)
                .where(
                    (FactConsumer.snapshot == int(snap_id))
                    & (FactConsumer.func_ea_hex == func_hex)
                    & (FactConsumer.consumer == getattr(consumer, "consumer", None))
                    & (FactConsumer.strategy == getattr(consumer, "strategy", None))
                    & (FactConsumer.fact_id == getattr(consumer, "fact_id", None))
                    & (FactConsumer.maturity == getattr(consumer, "maturity", None))
                    & (FactConsumer.decision == getattr(consumer, "decision", None))
                )
                .exists()
            )
            if not exists:
                pending.append(consumer)
    if pending:
        snapshot_fact_consumers(
            conn,
            snap_id,
            int(ev.func_ea),
            tuple(pending),
        )


def _handle_fact_conflict(ev: FactConflictsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_fact_conflicts(conn, snap_id, ev.func_ea, ev.conflicts)


def _handle_modifications(ev: ModificationsObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_modifications(conn, snap_id, list(ev.modifications))


def _handle_rendered_program(ev: RenderedProgramObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_rendered_program(conn, snap_id, ev.program)


def _handle_reachability(ev: ReachabilityObserved) -> None:
    conn = _conn_for(ev.snapshot)
    snap_id = _resolve_snapshot_id(ev.snapshot)
    if conn is None or snap_id is None:
        return
    snapshot_reachability(
        conn,
        snap_id,
        all_serials=set(ev.all_serials),
        reachable=set(ev.reachable),
        condition_chain_serials=set(ev.condition_chain_serials),
        gutted=set(ev.gutted),
        claimed_sources=set(ev.claimed_sources),
    )


def _handle_watch_block_transition(ev: WatchBlockTransitionObserved) -> None:
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    snapshot_watch_transition(
        conn,
        func_ea=ev.func_ea,
        apply_session_id=ev.apply_session_id,
        mod_index=ev.mod_index,
        mod_type=ev.mod_type,
        phase=ev.phase,
        block_serial=ev.block_serial,
        prev_type_name=ev.prev_type_name,
        prev_succs=ev.prev_succs,
        prev_preds=ev.prev_preds,
        now_type_name=ev.now_type_name,
        now_succs=ev.now_succs,
        now_preds=ev.now_preds,
    )


def _handle_cfg_provenance(ev: CfgProvenanceObserved) -> None:
    """Buffer the event until the next snapshot capture flushes it.

    The diag schema attaches provenance rows to a snapshot_id, so we
    can't write until a capture has happened. The
    :func:`_handle_capture_mba` handler drains the buffer at flush
    time.
    """
    with _provenance_lock:
        _pending_provenance.append(ev)


def _flush_pending_provenance(conn: sqlite3.Connection, snap_id: int) -> None:
    """Insert all buffered :class:`CfgProvenanceObserved` events under ``snap_id``."""
    with _provenance_lock:
        events = list(_pending_provenance)
        _pending_provenance.clear()
    _insert_cfg_provenance_events(conn, snap_id, events)


def _handle_cfg_provenance_latest(
    ev: CfgProvenanceForLatestSnapshot,
) -> None:
    """Persist CFG provenance rows under the latest snapshot for ``func_ea``."""
    if not ev.events:
        return
    try:
        conn = get_diag_conn(int(ev.func_ea))
    except Exception:
        return
    if conn is None:
        return
    snap_id = _latest_snapshot_id_for_func(ev.func_ea)
    if snap_id is None:
        return
    _insert_cfg_provenance_events(conn, snap_id, ev.events)


def _insert_cfg_provenance_events(
    conn: sqlite3.Connection,
    snap_id: int,
    events: tuple[CfgProvenanceObserved, ...] | list[CfgProvenanceObserved],
) -> None:
    """Insert CFG provenance rows under ``snap_id`` (ORM)."""
    if not events:
        return
    db = active_diag_db()
    if db is None:
        return
    try:
        with diag_models_on(db):
            current_max = (
                CfgProvenance.select(fn.MAX(CfgProvenance.seq))
                .where(CfgProvenance.snapshot == int(snap_id))
                .scalar()
            )
            next_seq = (int(current_max) + 1) if current_max is not None else 0
            rows = []
            for seq_idx, ev in enumerate(events):
                block_diag = _provenance_block_diag(
                    conn,
                    snap_id,
                    int(ev.block_serial),
                    label=ev.block_label,
                    ea=getattr(ev, "block_ea", None),
                )
                target_serial = (
                    int(ev.target_serial) if ev.target_serial is not None else None
                )
                target_diag = _provenance_block_diag(
                    conn,
                    snap_id,
                    target_serial,
                    label=ev.target_label,
                    ea=getattr(ev, "target_ea", None),
                )
                rows.append(
                    {
                        "snapshot": int(snap_id),
                        "seq": next_seq + seq_idx,
                        "pass_name": ev.pass_name,
                        "action": ev.action,
                        "block_serial": int(ev.block_serial),
                        "block_label": block_diag["label"],
                        "block_ea_hex": block_diag["ea_hex"],
                        "block_ea_i64": block_diag["ea_i64"],
                        "target_serial": target_serial,
                        "target_label": target_diag["label"],
                        "target_ea_hex": target_diag["ea_hex"],
                        "target_ea_i64": target_diag["ea_i64"],
                        "reason": ev.reason,
                        "extra_json": _provenance_extra_json(
                            ev,
                            block_label=block_diag["label"],
                            target_label=target_diag["label"],
                        ),
                    }
                )
            with db.atomic():
                CfgProvenance.insert_many(rows).execute()
    except Exception:
        _logger.exception(
            "flushing %d cfg_provenance rows failed for snap_id=%d",
            len(events),
            snap_id,
        )


def _provenance_block_diag(
    conn: sqlite3.Connection,
    snap_id: int,
    serial: int | None,
    *,
    label: str | None,
    ea: int | None,
) -> dict[str, str | int | None]:
    if serial is None:
        return {"label": None, "ea_hex": None, "ea_i64": None}
    ea_hex, ea_i64 = _dual(int(ea)) if ea is not None else (None, None)
    if ea is None:
        ea_hex, ea_i64 = _lookup_provenance_block_ea(conn, snap_id, int(serial))
    if label is None or label.endswith("@?") or label.endswith("@unknown"):
        label = format_block_id(int(serial), start_ea=ea_hex or ea_i64)
    return {"label": label, "ea_hex": ea_hex, "ea_i64": ea_i64}


def _lookup_provenance_block_ea(
    conn: sqlite3.Connection,
    snap_id: int,
    serial: int,
) -> tuple[str | None, int | None]:
    row = conn.execute(
        """
        SELECT b.start_ea_hex, b.start_ea_i64
        FROM blocks b
        JOIN snapshots s ON s.id = b.snapshot_id
        WHERE b.serial = ?
          AND s.func_ea_hex = (
              SELECT func_ea_hex FROM snapshots WHERE id = ?
          )
          AND s.id <= ?
        ORDER BY s.id DESC
        LIMIT 1
        """,
        (int(serial), int(snap_id), int(snap_id)),
    ).fetchone()
    if row is None:
        return None, None
    return row[0], row[1]


def _provenance_extra_json(
    ev: CfgProvenanceObserved,
    *,
    block_label: object | None = None,
    target_label: object | None = None,
) -> str | None:
    """Serialize the extra dict (plus precomputed labels) as JSON."""
    import json

    extra: dict[str, object] = dict(ev.extra or {})
    if block_label is not None:
        extra.setdefault("block_label", block_label)
    if target_label is not None:
        extra.setdefault("target_label", target_label)
    if ev.maturity_label is not None:
        extra.setdefault("maturity", ev.maturity_label)
    if not extra:
        return None
    try:
        return json.dumps(extra, default=str, sort_keys=True)
    except Exception:
        return str(extra)


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

# (event_type, handler) tuples. Tracked in install/uninstall so the
# subscriber registration is symmetric.
_HANDLERS: tuple[tuple[type, object], ...] = (
    (DiagnosticSessionObserved, _handle_diagnostic_session),
    (InputIdentityResolutionObserved, _handle_input_identity_resolution),
    (LifecycleEventObserved, _handle_lifecycle_event),
    (EvidenceGenerationObserved, _handle_evidence_generation),
    (IdentityDecisionObserved, _handle_identity_decision),
    (
        FrontendNormalizationPlanIntentObserved,
        _handle_frontend_normalization_plan_intent,
    ),
    (SemanticOutputVerifiedObserved, _handle_semantic_output_verified),
    (PassContractEvidencePublished, _handle_pass_contract_evidence),
    (MutationPlanObserved, _handle_mutation_plan),
    (MutationReceiptObserved, _handle_mutation_receipt),
    (CfgTransactionAttemptObserved, _handle_cfg_transaction_attempt),
    (
        SemanticFragmentRouteOracleComparedObserved,
        _handle_semantic_fragment_route_oracle,
    ),
    (CaptureMbaSnapshotRequested, _handle_capture_mba),
    (
        ConditionChainIntervalDispatcherObserved,
        _handle_condition_chain_interval_dispatcher,
    ),
    (StateDispatcherRowsObserved, _handle_state_dispatcher_rows),
    (OptblockCallbackExceptionObserved, _handle_optblock_callback_exception),
    (
        UnflattenDispatcherCorridorCoverageObserved,
        _handle_unflatten_dispatcher_corridor_coverage,
    ),
    (
        StateTransitionDispatchResolutionsObserved,
        _handle_state_transition_dispatch_resolutions,
    ),
    (SwitchCaseTransitionFactsObserved, _handle_switch_case_transition_facts),
    (BranchOwnershipProofsObserved, _handle_branch_ownership_proofs),
    (BranchWitnessDecisionsObserved, _handle_branch_witness_decisions),
    (ExitPathShortcutDecisionsObserved, _handle_exit_path_shortcut_decisions),
    (DagObserved, _handle_dag),
    (
        DagFrontierClosureDiagnosticsObserved,
        _handle_dag_frontier_closure_diagnostics,
    ),
    (DagLocalFactsObserved, _handle_dag_local_facts),
    (FactObservationsObserved, _handle_fact_observation),
    (FactMappingsObserved, _handle_fact_mapping),
    (FactConsumersObserved, _handle_fact_consumer),
    (FactConsumersForLatestSnapshot, _handle_fact_consumers_latest),
    (FactConflictsObserved, _handle_fact_conflict),
    (ModificationsObserved, _handle_modifications),
    (RenderedProgramObserved, _handle_rendered_program),
    (ReachabilityObserved, _handle_reachability),
    (CfgProvenanceObserved, _handle_cfg_provenance),
    (CfgProvenanceForLatestSnapshot, _handle_cfg_provenance_latest),
    (WatchBlockTransitionObserved, _handle_watch_block_transition),
)

_install_lock = threading.Lock()
_installed = False


# Register this module's resolver with core.observability so behavior
# bridges can look up the SQLite row id bound to a SnapshotRef without
# importing core.diag.
register_snapshot_id_resolver(_resolve_snapshot_id)


def install_diag_event_handlers() -> None:
    """Install all SQLite subscribers on the diagnostic event bus.

    Idempotent: a second call uninstalls the existing subscribers
    first so the bus never carries duplicates.
    """
    global _installed
    with _install_lock:
        if _installed:
            _uninstall_locked()
        for event_type, handler in _HANDLERS:
            subscribe(event_type, handler)  # type: ignore[arg-type]
        _installed = True


def uninstall_diag_event_handlers() -> None:
    """Remove all installed SQLite subscribers and clear ref mappings."""
    with _install_lock:
        _uninstall_locked()


def _uninstall_locked() -> None:
    global _installed
    for event_type, handler in _HANDLERS:
        unsubscribe(event_type, handler)  # type: ignore[arg-type]
    _installed = False
    _clear_snapshot_mapping()
    with _provenance_lock:
        _pending_provenance.clear()
    with _condition_chain_interval_lock:
        _pending_condition_chain_intervals.clear()
    with _state_dispatcher_lock:
        _pending_state_dispatcher_rows.clear()
    with _unflatten_dispatcher_corridor_lock:
        _pending_unflatten_dispatcher_corridor_coverage.clear()
    with _branch_witness_lock:
        _pending_branch_witness_decisions.clear()
    with _exit_path_shortcut_lock:
        _pending_exit_path_shortcut_decisions.clear()


def is_installed() -> bool:
    """Return True if the subscribers are currently installed."""
    with _install_lock:
        return _installed


# Re-export internal helpers for test introspection
__all__ = [
    "install_diag_event_handlers",
    "is_installed",
    "uninstall_diag_event_handlers",
]
