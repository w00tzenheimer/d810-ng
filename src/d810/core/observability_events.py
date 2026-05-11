"""Diagnostic observation event dataclasses.

Event types live here under :mod:`d810.core` so the SQLite sink in
:mod:`d810.core.diag.event_handlers` can subscribe without importing
from upper layers (:mod:`d810.recon`, :mod:`d810.cfg`,
:mod:`d810.hexrays`) -- which the layered-architecture import-linter
contract forbids.

Domain observability modules (:mod:`d810.recon.observability`,
:mod:`d810.cfg.observability`, :mod:`d810.hexrays.observability`)
re-export the events relevant to their domain and own the
``observe_*`` emit helpers. Subscribers consume the dataclasses
directly from this module.

Zero imports from :mod:`d810.core.diag` -- the sink subscribes to
these types but does not own them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.observability import SnapshotRef
from d810.core.observability_models import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    Modification,
)
from d810.core.typing import Any


# ---------------------------------------------------------------------------
# Hex-Rays domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMbaSnapshotRequested:
    """Hex-Rays requested a full MBA capture under ``snapshot``.

    The diag subscriber inserts a row in ``snapshots`` and binds
    ``snapshot.key`` to the assigned SQLite id; subsequent
    ``*Observed`` events that carry the same ``snapshot`` then resolve
    to that id and write child rows.
    """

    snapshot: SnapshotRef
    blocks: tuple[BlockSnapshot, ...]


# ---------------------------------------------------------------------------
# Recon domain
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
    :func:`d810.core.diag.snapshot.snapshot_dag_local_facts`.
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
class FactConsumersForLatestSnapshot:
    """Recon observed fact-consumer records to attach to the latest snapshot.

    Late-binding variant for post-hoc fact-consumer logging where the
    rows do not correspond to a specific just-emitted capture but to
    after-the-fact audit of strategy decisions. The subscriber finds
    the latest ``snapshots`` row for ``func_ea`` and writes the rows
    there, deduplicating against existing ``fact_consumers`` rows.
    """

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

    ``program`` is duck-typed: subscribers introspect the attributes
    consumed by :func:`d810.core.diag.snapshot.snapshot_rendered_program`.
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
# CFG domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CfgProvenanceObserved:
    """CFG mutation observed a single attribution-tagged event.

    Mirrors the legacy ``log_cfg_provenance`` signature: callers emit
    one of these per CREATE / DELETE / SOFT_KILL / SEVER_EDGE /
    REDIRECT_EDGE / RENUMBER / MERGE / NOP_INSNS / BULK_DEEP_CLEAN
    action site. The diag subscriber persists rows into the
    ``cfg_provenance`` table under the next captured snapshot.
    """

    pass_name: str
    action: str
    block_serial: int
    target_serial: int | None = None
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    block_label: str | None = None
    target_label: str | None = None
    maturity_label: str | None = None


@dataclass(frozen=True)
class WatchBlockTransitionObserved:
    """DeferredGraphModifier.apply observed a watch-block shape transition."""

    func_ea: int
    apply_session_id: str
    mod_index: int | None
    mod_type: str
    phase: str
    block_serial: int
    prev_type_name: str | None
    prev_succs: tuple[int, ...] | None
    prev_preds: tuple[int, ...] | None
    now_type_name: str | None
    now_succs: tuple[int, ...] | None
    now_preds: tuple[int, ...] | None


@dataclass(frozen=True)
class BlockLineageDrainRequested:
    """The diag sink finished a capture and ran the lineage drain.

    Mostly useful for test observability; the producer side does not
    emit this. The :func:`d810.core.diag.event_handlers._handle_capture_mba`
    handler emits it after lineage rows are flushed under the new
    ``snapshot_id``.
    """

    snapshot: SnapshotRef


__all__ = [
    # Hex-Rays
    "CaptureMbaSnapshotRequested",
    # Recon
    "DagLocalFactsObserved",
    "DagObserved",
    "FactConflictsObserved",
    "FactConsumersForLatestSnapshot",
    "FactConsumersObserved",
    "FactMappingsObserved",
    "FactObservationsObserved",
    "ModificationsObserved",
    "ReachabilityObserved",
    "RenderedProgramObserved",
    # CFG
    "BlockLineageDrainRequested",
    "CfgProvenanceObserved",
    "WatchBlockTransitionObserved",
]
