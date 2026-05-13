"""SQLite event handlers that persist diagnostic observations.

Subscribes to the observation events declared in
:mod:`d810.recon.observability`, :mod:`d810.cfg.observability`, and
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

from d810.core import logging as _d810_logging
from d810.core.diag import get_diag_db
from d810.core.diag.snapshot import (
    snapshot_bst_interval_dispatcher_rows,
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
    snapshot_watch_transition,
)
from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    register_snapshot_id_resolver,
    subscribe,
    unsubscribe,
)
from d810.core.observability_events import (
    BlockLineageDrainRequested,
    BstIntervalDispatcherObserved,
    CaptureMbaSnapshotRequested,
    CfgProvenanceObserved,
    DagFrontierClosureDiagnosticsObserved,
    DagLocalFactsObserved,
    DagObserved,
    FactConflictsObserved,
    FactConsumersForLatestSnapshot,
    FactConsumersObserved,
    FactMappingsObserved,
    FactObservationsObserved,
    ModificationsObserved,
    ReachabilityObserved,
    RenderedProgramObserved,
    WatchBlockTransitionObserved,
)

_logger = _d810_logging.getLogger("D810.diag.event_handlers")


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

_bst_interval_lock = threading.Lock()
_pending_bst_intervals: list[BstIntervalDispatcherObserved] = []


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
        return get_diag_db(int(snap.func_ea))
    except Exception:
        _logger.exception("get_diag_db failed for func_ea=0x%x", snap.func_ea)
        return None


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
    )
    _bind_snapshot_id(snap, snap_id)
    # Flush any CfgProvenanceObserved events that arrived between the
    # last snapshot and this one. They share the "next snapshot"
    # attribution semantics with the legacy IoC drain.
    _flush_pending_provenance(conn, snap_id)
    _flush_pending_bst_intervals(conn, snap_id, snap.func_ea)
    # Block-lineage drain is fired by snapshot_mba via
    # BlockLineageDrainRequested(conn, snap_id); cfg.block_lineage's
    # subscriber writes the rows. No explicit invocation here.


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


def _handle_bst_interval_dispatcher(
    ev: BstIntervalDispatcherObserved,
) -> None:
    try:
        conn = get_diag_db(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.rows:
        return
    func_hex = f"0x{int(ev.func_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
    row = conn.execute(
        "SELECT id FROM snapshots WHERE func_ea_hex=? "
        "ORDER BY id DESC LIMIT 1",
        (func_hex,),
    ).fetchone()
    if row is None:
        _buffer_bst_interval_dispatcher(ev)
        return
    snapshot_bst_interval_dispatcher_rows(
        conn,
        int(row[0]),
        ev.rows,
        dispatcher_entry_block=ev.dispatcher_entry_block,
        maturity=ev.maturity,
    )


def _buffer_bst_interval_dispatcher(
    ev: BstIntervalDispatcherObserved,
) -> None:
    with _bst_interval_lock:
        _pending_bst_intervals.append(ev)


def _flush_pending_bst_intervals(
    conn: sqlite3.Connection,
    snap_id: int,
    func_ea: int,
) -> None:
    with _bst_interval_lock:
        matching = [
            ev for ev in _pending_bst_intervals
            if int(ev.func_ea) == int(func_ea)
        ]
        if matching:
            _pending_bst_intervals[:] = [
                ev for ev in _pending_bst_intervals
                if int(ev.func_ea) != int(func_ea)
            ]
    for ev in matching:
        snapshot_bst_interval_dispatcher_rows(
            conn,
            int(snap_id),
            ev.rows,
            dispatcher_entry_block=ev.dispatcher_entry_block,
            maturity=ev.maturity,
        )


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
    """Late-binding fact-consumer writer.

    Used by recon-time post-hoc auditing where no specific
    just-emitted capture exists. The handler finds the latest
    ``snapshots`` row for ``func_ea`` and writes consumer rows there
    after deduplicating against existing rows.
    """
    try:
        conn = get_diag_db(int(ev.func_ea))
    except Exception:
        return
    if conn is None or not ev.consumers:
        return
    func_hex = f"0x{int(ev.func_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
    row = conn.execute(
        "SELECT id FROM snapshots WHERE func_ea_hex=? "
        "ORDER BY id DESC LIMIT 1",
        (func_hex,),
    ).fetchone()
    if row is None:
        return
    snap_id = int(row[0])
    pending = []
    for consumer in ev.consumers:
        exists = conn.execute(
            "SELECT 1 FROM fact_consumers "
            "WHERE func_ea_hex=? AND consumer=? AND strategy=? "
            "AND fact_id=? AND maturity=? AND decision=? LIMIT 1",
            (
                func_hex,
                getattr(consumer, "consumer", None),
                getattr(consumer, "strategy", None),
                getattr(consumer, "fact_id", None),
                getattr(consumer, "maturity", None),
                getattr(consumer, "decision", None),
            ),
        ).fetchone()
        if exists is None:
            pending.append(consumer)
    if pending:
        snapshot_fact_consumers(
            conn, snap_id, int(ev.func_ea), tuple(pending),
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
        bst_serials=set(ev.bst_serials),
        gutted=set(ev.gutted),
        claimed_sources=set(ev.claimed_sources),
    )


def _handle_watch_block_transition(ev: WatchBlockTransitionObserved) -> None:
    try:
        conn = get_diag_db(int(ev.func_ea))
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
    if not events:
        return
    rows = [
        (
            int(snap_id),
            seq_idx,
            ev.pass_name,
            ev.action,
            int(ev.block_serial),
            (int(ev.target_serial) if ev.target_serial is not None else None),
            ev.reason,
            _provenance_extra_json(ev),
        )
        for seq_idx, ev in enumerate(events)
    ]
    try:
        conn.executemany(
            "INSERT INTO cfg_provenance VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )
    except Exception:
        _logger.exception(
            "flushing %d cfg_provenance rows failed for snap_id=%d",
            len(rows),
            snap_id,
        )


def _provenance_extra_json(ev: CfgProvenanceObserved) -> str | None:
    """Serialize the extra dict (plus precomputed labels) as JSON."""
    import json

    extra: dict[str, object] = dict(ev.extra or {})
    if ev.block_label is not None:
        extra.setdefault("block_label", ev.block_label)
    if ev.target_label is not None:
        extra.setdefault("target_label", ev.target_label)
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
    (CaptureMbaSnapshotRequested, _handle_capture_mba),
    (BstIntervalDispatcherObserved, _handle_bst_interval_dispatcher),
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
    with _bst_interval_lock:
        _pending_bst_intervals.clear()


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
