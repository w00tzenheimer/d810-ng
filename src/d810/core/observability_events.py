"Diagnostic observation event dataclasses.\n\nEvent types live here under :mod:`d810.core` so the SQLite sink in\n:mod:`d810.core.diag.event_handlers` can subscribe without importing\nfrom upper layers (:mod:`d810.preanalysis`, :mod:`d810.cfg`,\n:mod:`d810.hexrays`) -- which the layered-architecture import-linter\ncontract forbids.\n\nDomain observability modules (:mod:`d810.core.observability_recon`,\n:mod:`d810.core.observability_cfg`, :mod:`d810.hexrays.observability`)\nre-export the events relevant to their domain and own the\n``observe_*`` emit helpers. Subscribers consume the dataclasses\ndirectly from this module.\n\nZero imports from :mod:`d810.core.diag` -- the sink subscribes to\nthese types but does not own them.\n"
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


@dataclass(frozen=True)
class DiagnosticSessionObserved:
    """Manager-owned decompilation session entered or changed terminal state."""

    session_id: str
    func_ea: int
    top_level_epoch: int
    native_key_json: str
    status: str
    timestamp: float = 0.0


@dataclass(frozen=True)
class LifecycleEventObserved:
    """Portable event-native diagnostic record with optional snapshot context."""

    session_id: str
    func_ea: int
    event_kind: str
    snapshot: SnapshotRef | None = None
    provider: str | None = None
    maturity: str | None = None
    phase: str | None = None
    evidence_generation: int | None = None
    mba_generation_before: int | None = None
    mba_generation_after: int | None = None
    correlation_id: str | None = None
    summary: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass(frozen=True)
class EvidenceGenerationObserved:
    session_id: str
    func_ea: int
    operation: str
    previous_generation: int
    resulting_generation: int
    evidence_family: str
    outcome: str
    owner: str
    reason: str
    snapshot: SnapshotRef | None = None
    provider: str | None = None
    maturity: str | None = None
    phase: str | None = None
    timestamp: float = 0.0


@dataclass(frozen=True)
class IdentityDecisionObserved:
    session_id: str
    func_ea: int
    decision_kind: str
    consumer: str
    identity_role: str
    native_key_json: str
    exact_eas_json: str
    native_ranges_json: str
    primary_anchor_ea: int | None
    current_serial: int | None
    mba_generation: int
    evidence_generation: int
    maturity: str
    outcome: str
    candidates_json: str
    reason: str
    snapshot: SnapshotRef | None = None
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.current_serial is not None and self.primary_anchor_ea is None:
            raise ValueError("a serial identity decision requires an EA anchor")
        if self.primary_anchor_ea is None:
            raise ValueError("an identity decision requires an EA anchor")
        if int(self.mba_generation) < 0 or int(self.evidence_generation) < 0:
            raise ValueError("identity decision generations must be non-negative")


@dataclass(frozen=True)
class MutationPlanItemObserved:
    item_index: int
    mutation_kind: str
    source_serial: int | None
    source_anchor_ea: int | None
    source_identity_json: str | None
    target_serial: int | None
    target_anchor_ea: int | None
    target_identity_json: str | None
    disposition: str
    reason: str

    def __post_init__(self) -> None:
        if self.source_serial is not None and self.source_anchor_ea is None:
            raise ValueError("a planned source serial requires an EA anchor")
        if self.target_serial is not None and self.target_anchor_ea is None:
            raise ValueError("a planned target serial requires an EA anchor")


@dataclass(frozen=True)
class MutationPlanObserved:
    session_id: str
    func_ea: int
    mutation_batch_id: str
    mutation_kind: str
    planned_operation_count: int
    mba_generation: int
    evidence_generation: int
    maturity: str
    description: str
    items: tuple[MutationPlanItemObserved, ...] = ()
    timestamp: float = 0.0


@dataclass(frozen=True)
class MutationReceiptObserved:
    session_id: str
    func_ea: int
    mutation_batch_id: str
    mutation_kind: str
    pre_generation: int
    post_generation: int
    planned_operation_count: int
    applied_operation_count: int
    evidence_generation: int
    maturity: str
    outcome: str
    description: str
    reason: str
    affected_identity_json: tuple[str, ...] = ()
    affected_anchor_eas: tuple[int, ...] = ()
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.outcome == "committed" and int(self.post_generation) != int(
            self.pre_generation
        ) + 1:
            raise ValueError("a committed receipt must advance one MBA generation")
        if self.outcome == "aborted" and int(self.post_generation) != int(
            self.pre_generation
        ):
            raise ValueError("an aborted receipt cannot advance the MBA generation")
        if len(self.affected_identity_json) != len(self.affected_anchor_eas):
            raise ValueError("receipt identities and EA anchors must align")


# ---------------------------------------------------------------------------
# Preanalysis domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DagObserved:
    "Preanalysis observed a DAG (state-graph) snapshot."

    snapshot: SnapshotRef
    nodes: tuple[DagNode, ...]
    edges: tuple[DagEdge, ...]


@dataclass(frozen=True)
class DagFrontierClosureDiagnosticsObserved:
    "Preanalysis observed DAG-frontier closure verifier diagnostics."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class ConditionChainIntervalDispatcherObserved:
    "Preanalysis observed recovered condition-chain interval-dispatcher rows.\n\n    The producer may not have a fresh SnapshotRef at the emission site, so the\n    diag sink attaches these rows to the latest snapshot for ``func_ea``.\n    "

    func_ea: int
    maturity: str
    dispatcher_entry_block: int | None
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class StateDispatcherRowsObserved:
    "Preanalysis observed exact state-dispatcher rows."

    func_ea: int
    maturity: str
    dispatcher_entry_block: int | None
    dispatcher_kind: str
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class StateTransitionDispatchResolutionsObserved:
    "Preanalysis observed transition resolutions through exact dispatcher rows."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class SwitchCaseTransitionFactsObserved:
    "Preanalysis observed switch-table case transition facts."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class BranchOwnershipProofsObserved:
    "Preanalysis observed conditional branch ownership proof rows."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class BranchWitnessDecisionsObserved:
    "Preanalysis observed branch-witness projection decisions."

    func_ea: int
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class ExitPathShortcutDecisionsObserved:
    "Preanalysis observed exit-path shortcut/liveness decisions."

    func_ea: int
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class DagLocalFactsObserved:
    "Preanalysis observed node-local DAG facts for a LinearizedStateDag.\n\n    ``dag`` is duck-typed: it must expose the attributes consumed by\n    :func:`d810.core.diag.snapshot.snapshot_dag_local_facts`.\n    "

    snapshot: SnapshotRef
    dag: Any


@dataclass(frozen=True)
class FactObservationsObserved:
    "Preanalysis observed a batch of fact observations for a function/snapshot."

    snapshot: SnapshotRef
    func_ea: int
    observations: tuple[Any, ...]


@dataclass(frozen=True)
class FactMappingsObserved:
    "Preanalysis observed a batch of fact mappings."

    snapshot: SnapshotRef
    func_ea: int
    mappings: tuple[Any, ...]


@dataclass(frozen=True)
class FactConsumersObserved:
    "Preanalysis observed a batch of fact-consumer records."

    snapshot: SnapshotRef
    func_ea: int
    consumers: tuple[Any, ...]


@dataclass(frozen=True)
class FactConsumersForLatestSnapshot:
    "Preanalysis observed fact-consumer records to attach to the latest snapshot.\n\n    Late-binding variant for post-hoc fact-consumer logging where the\n    rows do not correspond to a specific just-emitted capture but to\n    after-the-fact audit of strategy decisions. The subscriber finds\n    the latest ``snapshots`` row for ``func_ea`` and writes the rows\n    there, deduplicating against existing ``fact_consumers`` rows.\n    "

    func_ea: int
    consumers: tuple[Any, ...]


@dataclass(frozen=True)
class FactConflictsObserved:
    "Preanalysis observed a batch of fact conflicts."

    snapshot: SnapshotRef
    func_ea: int
    conflicts: tuple[Any, ...]


@dataclass(frozen=True)
class ModificationsObserved:
    "Preanalysis observed a batch of reconstruction modifications."

    snapshot: SnapshotRef
    modifications: tuple[Modification, ...]


@dataclass(frozen=True)
class RenderedProgramObserved:
    "Preanalysis observed a rendered linearized program.\n\n    ``program`` is duck-typed: subscribers introspect the attributes\n    consumed by :func:`d810.core.diag.snapshot.snapshot_rendered_program`.\n    "

    snapshot: SnapshotRef
    program: Any


@dataclass(frozen=True)
class ReachabilityObserved:
    "Preanalysis observed block reachability/classification for a snapshot."

    snapshot: SnapshotRef
    all_serials: frozenset[int]
    reachable: frozenset[int] = field(default_factory=frozenset)
    condition_chain_serials: frozenset[int] = field(default_factory=frozenset)
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
    block_ea: int | None = None
    target_label: str | None = None
    target_ea: int | None = None
    maturity_label: str | None = None


@dataclass(frozen=True)
class CfgProvenanceForLatestSnapshot:
    "CFG provenance that should attach to the latest function snapshot.\n\n    Most CFG mutation provenance is naturally tied to the next MBA\n    capture, so :class:`CfgProvenanceObserved` buffers until that\n    capture occurs. Preanalysis and planning diagnostics can be late-bound:\n    they may explain why a rewrite was *not* selected, so there may be\n    no subsequent snapshot to flush against. This event lets those\n    diagnostics use the same ``cfg_provenance`` table while explicitly\n    requesting \"latest snapshot for this function\" attribution.\n    "

    func_ea: int
    events: tuple[CfgProvenanceObserved, ...]


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
    """The diag sink is about to flush block-lineage rows.

    Emitted by :func:`d810.core.diag.snapshot.snapshot_mba` immediately
    after the snapshots row is created. ``conn`` and ``snapshot_id``
    are the live SQLite handle and row id; subscribers (currently
    :mod:`d810.transforms.block_lineage`) drain their pending buffer and
    write rows directly. ``snapshot`` is the optional SnapshotRef
    (``None`` when called from a direct ``snapshot_mba`` invocation
    outside the event API).
    """

    conn: Any
    snapshot_id: int
    snapshot: SnapshotRef | None = None


__all__ = [
    # Hex-Rays
    "CaptureMbaSnapshotRequested",
    # Preanalysis
    "BranchOwnershipProofsObserved",
    "BranchWitnessDecisionsObserved",
    "ConditionChainIntervalDispatcherObserved",
    "ExitPathShortcutDecisionsObserved",
    "DagFrontierClosureDiagnosticsObserved",
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
    "StateDispatcherRowsObserved",
    "StateTransitionDispatchResolutionsObserved",
    "SwitchCaseTransitionFactsObserved",
    # CFG
    "BlockLineageDrainRequested",
    "CfgProvenanceForLatestSnapshot",
    "CfgProvenanceObserved",
    "WatchBlockTransitionObserved",
]
