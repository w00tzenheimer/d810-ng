"""Central planner for the shared unflattening engine.

Hodur is a first-class consumer of the shared recon-analysis-consumer
lifecycle.  The recon phase collects raw artifacts (handler transitions,
return frontier, terminal return audit); the analysis phase interprets
them into consumer-specific summaries; and this planner consumes those
summaries to bias fragment scoring, policy filtering, and conflict
resolution.

The consumer-specific summary consumed here is :class:`PlannerInputs`
(defined in ``provenance.py``), analogous to
:class:`~d810.analyses.control_flow.models.DeobfuscationHints` for the rule-scope
consumer and :class:`~d810.passes.flow_hints.FlowContextHintSummary`
for the flow-context consumer.

# PLANNER_AUTHORITY: The UnflatteningPlanner is the sole authority for
# pipeline membership, ordering, and conflict resolution.  No downstream
# component (executor, unflattener orchestrator) may re-select, reorder,
# insert, or drop fragments based on strategy-level criteria.
#
# Ownership boundaries:
#   - Planner OWNS: strategy polling, fragment scoring, policy filtering,
#     conflict resolution (greedy independent set), prerequisite ordering.
#   - Planner PRODUCES: an ordered list[PlanFragment] (the pipeline) and
#     a PipelineProvenance ledger.
#   - Executor CONSUMES: the pipeline in-order; may only SKIP via gate
#     enforcement (safeguard, preflight, transaction, semantic gate).
#   - Unflattener orchestrator CONSUMES: pipeline + results; only updates
#     provenance lifecycle phases (APPLIED, GATE_FAILED, BYPASSED).
"""
from __future__ import annotations

import enum
from copy import copy
from dataclasses import dataclass, field, replace
from d810.core.typing import TYPE_CHECKING

from d810.flow.terminal_return import TerminalReturnSourceKind
from d810.core.logging import getLogger
from d810.analyses.control_flow.provenance import (
    DagDisagreementRecord,
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    CumulativePlannerView,
)
from d810.optimizers.microcode.flow.flattening.engine.fragment_arbitration import (
    DAG_AUDIT_METADATA_KEY as _DAG_AUDIT_METADATA_KEY,
    apply_dag_conformance_gate as _apply_engine_dag_conformance_gate,
)
from d810.capabilities.unflattening_strategy import UnflatteningStrategy
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
        DagAuthority,
    )
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Hint signals: normalized recon data for scoring adjustments
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannerHintSignals:
    """Normalized signals derived from raw recon artifacts.

    Each field is a 0.0-1.0 float indicating confidence or risk level
    for a specific recon dimension. Used by :func:`compute_hint_adjustment`
    to bias fragment scoring before conflict resolution and ordering.

    These signals are intentionally ephemeral -- they are not persisted
    because they are cheap to derive from :class:`PlannerInputs` and
    tightly coupled to the planner's scoring policy.  If the scoring
    policy changes, the derivation logic in :func:`derive_hint_signals`
    changes in lock-step, so caching would add staleness risk without
    meaningful cost savings.
    """

    transition_confidence: float = 0.0
    return_frontier_risk: float = 0.0
    terminal_return_risk: float = 0.0


def derive_hint_signals(inputs: PlannerInputs | None) -> PlannerHintSignals:
    """Map raw recon artifacts to normalized hint signals.

    Signals are derived from artifact content, not just artifact presence.

    Args:
        inputs: Structured envelope with recon artifacts, or None.

    Returns:
        A :class:`PlannerHintSignals` with all fields populated.
    """
    if inputs is None:
        return PlannerHintSignals()
    return PlannerHintSignals(
        transition_confidence=_derive_transition_confidence(
            inputs.handler_transitions,
        ),
        return_frontier_risk=_derive_return_frontier_risk(inputs.return_frontier),
        terminal_return_risk=_derive_terminal_return_risk(
            inputs.terminal_return_audit,
        ),
    )


def _clamp01(value: float) -> float:
    """Clamp *value* into the inclusive [0.0, 1.0] range."""
    return max(0.0, min(1.0, value))


def _summary_attr(summary: object, name: str) -> float:
    """Read a numeric summary attribute, defaulting to 0.0."""
    value = getattr(summary, name, 0)
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _derive_transition_confidence(report: object | None) -> float:
    """Derive transition confidence from transition report summary content."""
    summary = getattr(report, "summary", None)
    if summary is None:
        return 0.0

    handlers_total = _summary_attr(summary, "handlers_total")
    if handlers_total <= 0.0:
        return 0.0

    known_count = _summary_attr(summary, "known_count")
    conditional_count = _summary_attr(summary, "conditional_count")
    exit_count = _summary_attr(summary, "exit_count")

    weighted_confidence = (
        known_count + (0.5 * conditional_count) + (0.75 * exit_count)
    ) / handlers_total
    return _clamp01(weighted_confidence)


def _derive_return_frontier_risk(audit: object | None) -> float:
    """Derive frontier risk from broken-site ratio in the audit report."""
    report_fn = getattr(audit, "report", None)
    if not callable(report_fn):
        return 0.0

    report = report_fn()
    if not isinstance(report, dict):
        return 0.0

    total_sites = report.get("total_sites", 0)
    broken_count = report.get("broken_count", 0)
    if not isinstance(total_sites, (int, float)) or total_sites <= 0:
        return 0.0
    if not isinstance(broken_count, (int, float)):
        return 0.0
    return _clamp01(float(broken_count) / float(total_sites))


def _terminal_source_value(source_kind: object) -> str:
    """Normalize enum-or-string source kinds to a lowercase string value."""
    value = getattr(source_kind, "value", source_kind)
    if isinstance(value, str):
        return value.lower()
    return str(value).lower()


def _derive_terminal_return_risk(audit: object | None) -> float:
    """Derive terminal return risk from terminal audit site content."""
    sites = getattr(audit, "sites", None)
    if not isinstance(sites, tuple):
        return 0.0
    if not sites:
        return 0.0

    kind_weights = {
        TerminalReturnSourceKind.DIRECT_RETURN.value: 0.0,
        TerminalReturnSourceKind.EPILOGUE_CORRIDOR.value: 0.5,
        TerminalReturnSourceKind.SHARED_EPILOGUE.value: 1.0,
        TerminalReturnSourceKind.UNREACHABLE.value: 1.0,
        TerminalReturnSourceKind.UNKNOWN.value: 0.75,
    }

    total_risk = 0.0
    for site in sites:
        source_value = _terminal_source_value(getattr(site, "source_kind", ""))
        site_risk = kind_weights.get(source_value, 0.75)
        has_rax_write = getattr(site, "has_rax_write", None)
        if has_rax_write is False:
            site_risk += 0.25
        total_risk += min(site_risk, 1.0)

    return _clamp01(total_risk / float(len(sites)))


@dataclass(frozen=True)
class HintAdjustment:
    """Score adjustment produced by recon hint analysis.

    Attributes:
        score_delta: Additive adjustment to the fragment's composite score.
        reasons: Human-readable reasons for the adjustment.
    """

    score_delta: float = 0.0
    reasons: tuple[str, ...] = ()


def compute_hint_adjustment(
    fragment: PlanFragment, signals: PlannerHintSignals
) -> HintAdjustment:
    """Compute a score adjustment for *fragment* based on recon *signals*.

    This is a pure function with no side effects.

    Args:
        fragment: The plan fragment to evaluate.
        signals: Normalized recon signals.

    Returns:
        A :class:`HintAdjustment` with the cumulative score delta and reasons.
    """
    delta = 0.0
    reasons: list[str] = []

    # Boost direct-family fragments when transition data is confident
    if fragment.family == FAMILY_DIRECT and signals.transition_confidence > 0.5:
        bonus = 2.0 * signals.transition_confidence
        delta += bonus
        reasons.append("transition_report_boost")

    # Penalize all fragments when return frontier risk is elevated
    if signals.return_frontier_risk > 0.3:
        penalty = -1.5 * signals.return_frontier_risk
        delta += penalty
        reasons.append("return_frontier_penalty")

    # Penalize cleanup-family fragments when terminal return risk is elevated
    if fragment.family == FAMILY_CLEANUP and signals.terminal_return_risk > 0.3:
        penalty = -1.0 * signals.terminal_return_risk
        delta += penalty
        reasons.append("terminal_return_penalty")

    return HintAdjustment(score_delta=delta, reasons=tuple(reasons))


# ---------------------------------------------------------------------------
# Planner-owned candidate model (H1)
# ---------------------------------------------------------------------------


class PlannerDecisionReason(str, enum.Enum):
    """Planner-internal reason for accepting or rejecting a candidate.

    These are the planner's own vocabulary, distinct from the provenance-layer
    :class:`DecisionReasonCode` which covers the full lifecycle including
    executor phases. The planner maps these to ``DecisionReasonCode`` when
    producing :class:`DecisionRecord` via :meth:`PlannerDecision.to_decision_record`.
    """

    ACCEPTED = "accepted"
    REJECTED_EMPTY = "rejected_empty"
    REJECTED_RISK = "rejected_risk"
    REJECTED_POLICY = "rejected_policy"
    REJECTED_CONFLICT = "rejected_conflict"
    REJECTED_PREREQUISITE = "rejected_prerequisite"


# Mapping from planner-internal reasons to provenance reason codes.
_REASON_TO_CODE: dict[PlannerDecisionReason, DecisionReasonCode] = {
    PlannerDecisionReason.ACCEPTED: DecisionReasonCode.ACCEPTED,
    PlannerDecisionReason.REJECTED_EMPTY: DecisionReasonCode.REJECTED_EMPTY,
    PlannerDecisionReason.REJECTED_RISK: DecisionReasonCode.REJECTED_RISK,
    PlannerDecisionReason.REJECTED_POLICY: DecisionReasonCode.REJECTED_POLICY,
    PlannerDecisionReason.REJECTED_CONFLICT: DecisionReasonCode.REJECTED_CONFLICT,
    PlannerDecisionReason.REJECTED_PREREQUISITE: DecisionReasonCode.BLOCKED,
}

# Mapping from planner-internal reasons to provenance phases.
_REASON_TO_PHASE: dict[PlannerDecisionReason, DecisionPhase] = {
    PlannerDecisionReason.ACCEPTED: DecisionPhase.SELECTED,
    PlannerDecisionReason.REJECTED_EMPTY: DecisionPhase.INAPPLICABLE,
    PlannerDecisionReason.REJECTED_RISK: DecisionPhase.POLICY_FILTERED,
    PlannerDecisionReason.REJECTED_POLICY: DecisionPhase.POLICY_FILTERED,
    PlannerDecisionReason.REJECTED_CONFLICT: DecisionPhase.CONFLICT_DROPPED,
    PlannerDecisionReason.REJECTED_PREREQUISITE: DecisionPhase.POLICY_FILTERED,
}


@dataclass(frozen=True)
class PlannerCandidate:
    """A strategy fragment wrapped with planner-computed scoring metadata.

    Created by the planner after receiving a :class:`PlanFragment` from a
    strategy. The candidate adds hint-adjusted scoring so that conflict
    resolution and ordering operate on effective scores.

    Attributes:
        fragment: The underlying strategy output.
        base_score: From ``fragment.expected_benefit.composite_score()``.
        hint_adjustment: From :func:`compute_hint_adjustment`.
        effective_score: ``base_score + hint_adjustment.score_delta``.
        strategy_name: Shortcut for ``fragment.strategy_name``.
        family: Shortcut for ``fragment.family``.
    """

    fragment: PlanFragment
    base_score: float
    hint_adjustment: HintAdjustment
    effective_score: float

    @property
    def strategy_name(self) -> str:
        """Delegate to the underlying fragment's strategy name."""
        return self.fragment.strategy_name

    @property
    def family(self) -> str:
        """Delegate to the underlying fragment's family."""
        return self.fragment.family

    @property
    def ownership(self) -> OwnershipScope:
        """Delegate to the underlying fragment's ownership scope."""
        return self.fragment.ownership

    @property
    def prerequisites(self) -> list[str]:
        """Delegate to the underlying fragment's prerequisites."""
        return self.fragment.prerequisites

    @property
    def risk_score(self) -> float:
        """Delegate to the underlying fragment's risk score."""
        return self.fragment.risk_score


@dataclass(frozen=True)
class PlannerDecision:
    """The planner's verdict on a single candidate.

    Pairs a :class:`PlannerCandidate` with a :class:`PlannerDecisionReason`
    and optional human-readable detail. The :meth:`to_decision_record` method
    converts this into the provenance vocabulary for auditing.

    Attributes:
        candidate: The evaluated candidate.
        reason: Why the candidate was accepted or rejected.
        detail: Human-readable explanation.
    """

    candidate: PlannerCandidate
    reason: PlannerDecisionReason
    detail: str = ""

    def to_decision_record(self) -> DecisionRecord:
        """Convert to a :class:`DecisionRecord` for provenance tracking.

        Maps the planner-internal :class:`PlannerDecisionReason` to the
        provenance-layer :class:`DecisionReasonCode` and :class:`DecisionPhase`.

        Returns:
            A frozen :class:`DecisionRecord` suitable for
            :class:`PipelineProvenance`.
        """
        c = self.candidate
        frag = c.fragment
        return DecisionRecord(
            strategy_name=c.strategy_name,
            family=c.family,
            phase=_REASON_TO_PHASE[self.reason],
            reason_code=_REASON_TO_CODE[self.reason],
            reason=self.detail or self.reason.value,
            composite_score=c.base_score,
            risk_score=frag.risk_score,
            handler_count=frag.expected_benefit.handlers_resolved,
            transition_count=frag.expected_benefit.transitions_resolved,
            ownership_blocks=frozenset(frag.ownership.blocks),
            prerequisites=frozenset(frag.prerequisites),
            base_score=c.base_score,
            hint_score_delta=c.hint_adjustment.score_delta,
            effective_score=c.effective_score,
            hint_reasons=c.hint_adjustment.reasons,
        )


def _log_planner_ctx_conflicts(
    fragment: PlanFragment,
    view: CumulativePlannerView,
    log: object,
) -> None:
    """Log (but do not modify) mods whose src is already linearized/claimed.

    Engine-level diagnostic that surfaces the Mode 1 pattern — a strategy
    queuing a graph mod on a source block that a prior fragment already
    linearized or claimed in this same pipeline run. Does not mutate the
    fragment; just logs at WARNING so operators see the conflict in the
    live d810 log without affecting current emission behavior.

    The planner_ctx mechanism's value is validated when this log starts
    firing on real runs. Consumer-side fixes (a strategy gating its own
    emissions on view queries) can be added in follow-up work once the
    specific emission paths that produce the reverse redirects are
    localized in the log stream.
    """
    if view is None:
        return
    # Import locally — graph_modification lives in cfg and would be a
    # heavy top-level dependency for a diagnostic helper.
    from d810.transforms.graph_modification import RedirectGoto
    conflicts: list[str] = []
    for mod in fragment.modifications:
        if not isinstance(mod, RedirectGoto):
            continue
        src = int(mod.from_serial)
        prior_tgt = view.linearization_target_for(src)
        if prior_tgt is None:
            continue
        if prior_tgt == int(mod.new_target):
            # Not a conflict — same target, strategies agree.
            continue
        conflicts.append(
            f"src={src} prior_tgt={prior_tgt} new_tgt={mod.new_target}"
        )
    if conflicts:
        log.warning(
            "PLANNER_CTX_CONFLICT: strategy %r emitted %d redirect(s) "
            "conflicting with prior pipeline decisions: %s",
            fragment.strategy_name,
            len(conflicts),
            "; ".join(conflicts[:10]),  # cap to avoid log explosion
        )


_SUB7FFD3338C040_ENTRY_EA = 0x180012B60


def _corridor_seed_data_for_snapshot(snapshot: AnalysisSnapshot) -> tuple:
    """Return function-specific CorridorSpliceData for the snapshot.

    uee-7wcd seed registry.  Keyed off ``mba.entry_ea``.  Today's only
    registered corridor is sub_7FFD3338C040's poll-corridor splice
    (shared_block=45, base_target=126, clone_source=122,
    clone_target=180).  Returns an empty tuple when the function has
    no registered corridor.

    Until recon analysis can derive corridor patterns directly, this
    seed registry is the canonical source of corridor data for the
    DAG arbiter.
    """
    from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
        CorridorSpliceData,
    )
    mba = getattr(snapshot, "mba", None)
    if mba is None:
        return ()
    try:
        entry_ea = int(getattr(mba, "entry_ea", -1))
    except Exception:
        return ()
    if entry_ea == _SUB7FFD3338C040_ENTRY_EA:
        return (
            CorridorSpliceData(
                function_ea=entry_ea,
                shared_block=45,
                base_target=126,
                clone_source=122,
                clone_target=180,
            ),
        )
    return ()


def _build_dag_authority(snapshot: AnalysisSnapshot) -> "DagAuthority | None":
    """Construct the DAG-as-arbiter for this pipeline run, or None.

    Phase 2 of uee-jrgq.  Reads the recon DAG off ``snapshot.discovery``
    if present; returns ``None`` when no discovery context is available
    (legacy / non-Hodur families that haven't built a LinearizedStateDag
    yet).  Built once per ``UnflatteningPlanner.plan()`` call.

    Per the deferral decision (mem_52073043), per-round rederivation is
    intentionally deferred — the same authority is threaded through
    every cumulative-view rebuild within this plan() invocation.
    """
    discovery = getattr(snapshot, "discovery", None)
    if discovery is None:
        return None
    dag = getattr(discovery, "dag", None)
    if dag is None:
        return None
    # Local import to avoid cyclic-import surface at module load time
    # (planner is imported during d810 startup; dag_authority is a
    # phase-1 artifact that should not be required for engine bootstrap).
    from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
        CorridorSpliceData,
        DagAuthority,
    )
    # uee-7wcd: seed function-specific corridor data based on
    # ``mba.entry_ea``.  Currently only sub_7FFD3338C040 has a
    # registered corridor; new entries can be added here when other
    # functions surface the same shape.  Long-term: have recon
    # analysis derive corridor patterns from the DAG itself.
    corridor_data = _corridor_seed_data_for_snapshot(snapshot)
    try:
        return DagAuthority(dag, corridor_data=corridor_data)
    except Exception as exc:
        logger.warning(
            "Failed to build DagAuthority from snapshot.discovery.dag: %s",
            exc,
            exc_info=True,
        )
        return None


def _collect_dag_audit_records(
    fragments: list[PlanFragment],
) -> tuple[DagDisagreementRecord, ...]:
    """Aggregate ``DagDisagreementRecord`` from each fragment's metadata.

    Strategies that participate in DAG-arbiter conformance store a
    ``tuple[DagDisagreementRecord, ...]`` under ``metadata["dag_audit"]``
    (see
    :mod:`d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder`).
    Fragments without that key contribute nothing.  Returns the flat
    aggregate in the same order fragments were planned, preserving
    intra-fragment record order so the per-run summary is deterministic.
    """
    out: list[DagDisagreementRecord] = []
    for frag in fragments:
        metadata = getattr(frag, "metadata", None)
        if not metadata:
            continue
        records = metadata.get(_DAG_AUDIT_METADATA_KEY)
        if not records:
            continue
        for record in records:
            if isinstance(record, DagDisagreementRecord):
                out.append(record)
    return tuple(out)


def _format_dag_audit_summary(
    records: tuple[DagDisagreementRecord, ...],
) -> str:
    """Render a deterministic ``PLANNER_DAG_AUDIT`` summary string.

    Format:

    .. code-block:: text

        PLANNER_DAG_AUDIT:
          Total disagreements: N across M planner(s)
          By planner:
            <planner_a>: K disagreement(s) (blk[X]->A vs DAG=B; ...)
            <planner_b>: ...

    Records with ``decision_reason`` starting with ``DAG_GAP:`` are
    excluded from disagreement counts but reported as a separate
    "DAG_GAP refusals: N" line so Phase 6 can compute the
    gap-vs-disagreement split when retiring the legacy conflict mode.

    Returns the empty string when ``records`` is empty so callers can
    skip emission entirely.
    """
    if not records:
        return ""

    disagreements = [
        r for r in records
        if not r.decision_reason.startswith("DAG_GAP:")
    ]
    gaps = [r for r in records if r.decision_reason.startswith("DAG_GAP:")]

    by_planner: dict[str, list[DagDisagreementRecord]] = {}
    for r in disagreements:
        by_planner.setdefault(r.planner_name, []).append(r)

    lines: list[str] = ["PLANNER_DAG_AUDIT:"]
    lines.append(
        f"  Total disagreements: {len(disagreements)} across "
        f"{len(by_planner)} planner(s)"
    )

    if by_planner:
        lines.append("  By planner:")
        # Sort by descending count, then alphabetical for deterministic output.
        ordered = sorted(
            by_planner.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        for planner_name, planner_records in ordered:
            details = "; ".join(
                _format_disagreement_detail(r)
                for r in planner_records[:5]
            )
            suffix = (
                f" (+{len(planner_records) - 5} more)"
                if len(planner_records) > 5 else ""
            )
            lines.append(
                f"    {planner_name}: {len(planner_records)} "
                f"disagreement(s) ({details}){suffix}"
            )

    if gaps:
        lines.append(
            f"  DAG_GAP refusals: {len(gaps)} mod(s) deferred to legacy filter"
        )

    return "\n".join(lines)


def _format_disagreement_detail(record: DagDisagreementRecord) -> str:
    """Render one ``DagDisagreementRecord`` as a compact detail string."""
    planner_tgt_str = (
        str(record.planner_target) if record.planner_target is not None else "?"
    )
    dag_tgt_str = (
        str(record.dag_target) if record.dag_target is not None else "?"
    )
    return (
        f"blk[{record.source_block}]->{planner_tgt_str} vs DAG={dag_tgt_str}"
    )


@dataclass
class PipelinePolicy:
    """Policy for strategy selection and ordering."""

    direct_coverage_threshold: float = 0.8  # block fallbacks if direct covers this fraction
    max_risk_score: float = 0.7  # reject fragments above this risk
    allow_fallback_families: bool = True


class UnflatteningPlanner:
    """Selects, orders, and arbitrates strategy fragments.

    As a lifecycle consumer, the planner receives a :class:`PlannerInputs`
    envelope containing recon artifacts (handler transitions, return
    frontier, terminal return audit) and derives :class:`PlannerHintSignals`
    to bias fragment scoring.  The outcome layer --
    :class:`PipelineProvenance` -- records every accept/reject decision
    with full audit trail, closing the lifecycle loop.

    **Hint persistence:** ``PlannerHintSignals`` remain ephemeral —
    see :class:`~d810.analyses.control_flow.provenance.PlannerInputs`
    for rationale.  Persist only if a concrete need appears (offline
    audit, cross-pass caching, or a second planner consumer).
    """

    def __init__(self, policy: PipelinePolicy | None = None):
        self.policy = policy or PipelinePolicy()

    def plan(
        self,
        snapshot: AnalysisSnapshot,
        strategies: list[UnflatteningStrategy],
        inputs: PlannerInputs | None = None,
    ) -> tuple[list[PlanFragment], PipelineProvenance]:
        """Poll strategies, collect fragments, and compose the pipeline.

        This is the primary public API. It owns:
        1. Strategy polling (``is_applicable`` + ``plan``).
        2. Fragment collection.
        3. Pipeline composition via :meth:`compose_pipeline`.
        4. Provenance generation (including INAPPLICABLE/CRASHED records).

        Args:
            snapshot: Read-only view of the current function's analysis state.
            strategies: Ordered list of strategy instances to poll.
            inputs: Structured envelope with recon artifacts and handler count.

        Returns:
            A tuple of (ordered pipeline, complete provenance ledger).
        """
        fragments: list[PlanFragment] = []
        pre_planner_records: list[DecisionRecord] = []

        # Build a DagAuthority once per pipeline run from the recon DAG
        # if one is available. Per the deferral decision (mem_52073043),
        # the authority is NOT re-derived per round — same DagAuthority
        # is threaded through every CumulativePlannerView.compile() call
        # below.  ``discovery`` may be ``None`` (legacy / DAG-less family);
        # in that case ``dag_authority`` stays ``None`` and downstream
        # consumers fall back to the legacy LinearizationDecision path.
        dag_authority = _build_dag_authority(snapshot)

        for strategy in strategies:
            if not strategy.is_applicable(snapshot):
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_INAPPLICABLE,
                    reason="is_applicable returned False",
                ))
                continue
            # Build the cumulative planner-context view from prior fragments'
            # metadata and inject it onto the snapshot. This is what lets a
            # later strategy see "blk[76] was already linearized by srw in
            # round 0" and skip emitting a contradictory reverse redirect.
            # Rebuilt every iteration because fragments accumulates; cost is
            # O(n) in prior contributions, trivially cheap at realistic sizes.
            cumulative_view = CumulativePlannerView.compile(
                fragments, dag_authority=dag_authority,
            )
            try:
                snapshot_for_strategy = replace(
                    snapshot, cumulative_planner_view=cumulative_view
                )
            except TypeError:
                snapshot_for_strategy = copy(snapshot)
                setattr(snapshot_for_strategy, "cumulative_planner_view", cumulative_view)
            try:
                fragment = strategy.plan(snapshot_for_strategy)
                if fragment is not None:
                    # LS12 C4: stamp target CFG-shape provenance from the
                    # producing strategy. PROVENANCE-ONLY -- never read by
                    # scoring / arbitration / executor (which key on
                    # ``fragment.family``). setdefault() can't raise.
                    _lowering_mode = getattr(strategy, "lowering_mode", None)
                    if _lowering_mode is not None:
                        fragment.metadata.setdefault("lowering_mode", _lowering_mode)
            except Exception as e:
                logger.warning(
                    "Strategy %s crashed: %s", strategy.name, e,
                    exc_info=True,
                )
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.CRASHED,
                    reason_code=DecisionReasonCode.REJECTED_CRASHED,
                    reason=f"plan() raised: {e}",
                    notes=str(e),
                ))
                continue
            if isinstance(fragment, list):
                for frag in fragment:
                    _log_planner_ctx_conflicts(frag, cumulative_view, logger)
                fragments.extend(fragment)
                # Extract nop_state_values from any fragment metadata
                # and inject into snapshot for subsequent strategies.
                for frag in fragment:
                    nsv = frag.metadata.get("nop_state_values")
                    if nsv and not snapshot.nop_state_values:
                        snapshot = replace(snapshot, nop_state_values=nsv)
                        logger.info(
                            "Planner: injected %d NOP'd state values from "
                            "strategy '%s' into snapshot",
                            len(nsv), frag.strategy_name,
                        )
                if strategy.name in (
                    "direct_handler_linearization",
                    "linearized_flow_graph",
                    "state_write_reconstruction",
                ):
                    for frag in fragment:
                        if frag.strategy_name != strategy.name:
                            continue
                        lfg_src = {src for src, _ in frag.ownership.edges}
                        if not lfg_src:
                            continue
                        snapshot = replace(
                            snapshot,
                            lfg_redirected_blocks=(
                                frozenset(snapshot.lfg_redirected_blocks) | frozenset(lfg_src)
                            ),
                        )
                        logger.info(
                            "Planner: injected %d redirected blocks "
                            "from strategy '%s' into snapshot",
                            len(lfg_src),
                            frag.strategy_name,
                        )
                        break
            elif fragment is not None:
                _log_planner_ctx_conflicts(fragment, cumulative_view, logger)
                # Engine-level DAG-conformance gate (uee-2hng).  Applied
                # to every fragment, idempotent for SRW which already
                # ran the same check internally.  Strategies that
                # construct PlanFragment directly (LFG, residual_handoff,
                # etc.) get DAG-disagreement filtering here that they
                # would otherwise bypass.
                fragment = _apply_engine_dag_conformance_gate(
                    fragment, cumulative_view,
                )
                fragments.append(fragment)
                # Extract nop_state_values from fragment metadata
                # and inject into snapshot for subsequent strategies.
                nsv = fragment.metadata.get("nop_state_values")
                if nsv and not snapshot.nop_state_values:
                    snapshot = replace(snapshot, nop_state_values=nsv)
                    logger.info(
                        "Planner: injected %d NOP'd state values from "
                        "strategy '%s' into snapshot",
                        len(nsv), fragment.strategy_name,
                    )
                # Inject lfg_redirected_blocks from LFG fragment's
                # ownership edges so backward_pred skips blocks that
                # LFG already redirected (prevents SUCC_MISMATCH).
                if strategy.name in (
                    "direct_handler_linearization",
                    "linearized_flow_graph",
                    "state_write_reconstruction",
                ):
                    lfg_src = {src for src, _ in fragment.ownership.edges}
                    if lfg_src:
                        snapshot = replace(
                            snapshot,
                            lfg_redirected_blocks=(
                                frozenset(snapshot.lfg_redirected_blocks) | frozenset(lfg_src)
                            ),
                        )
                        logger.info(
                            "Planner: injected %d redirected blocks "
                            "from strategy '%s' into snapshot",
                            len(lfg_src),
                            fragment.strategy_name,
                        )
            else:
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_EMPTY,
                    reason="applicable but produced no fragment",
                ))

        # Compose pipeline from collected fragments
        pipeline, provenance = self.compose_pipeline(
            fragments,
            inputs=inputs,
        )

        # Phase 5 of uee-jrgq: aggregate DAG-arbiter audit records
        # captured by every fragment that participated in DAG conformance
        # filtering, store them on PipelineProvenance, and emit a single
        # PLANNER_DAG_AUDIT summary line at INFO so operators see it in
        # ``d810.log`` without enabling DEBUG.  Aggregation runs over the
        # full ``fragments`` list (including any policy/conflict-dropped
        # fragments) — every captured drop is interesting regardless of
        # whether the fragment that caused it survived.
        dag_audit_records = _collect_dag_audit_records(fragments)
        if dag_audit_records:
            summary = _format_dag_audit_summary(dag_audit_records)
            if summary:
                logger.info("%s", summary)

        # Prepend strategy-level INAPPLICABLE/CRASHED records to planner provenance
        if pre_planner_records:
            provenance = PipelineProvenance(
                rows=tuple(pre_planner_records) + provenance.rows,
                input_summary=provenance.input_summary,
                dag_audit_records=dag_audit_records,
            )
        elif dag_audit_records:
            # Even when there were no pre-planner records, attach the
            # aggregated DAG audit so callers can inspect the run.
            provenance = PipelineProvenance(
                rows=provenance.rows,
                input_summary=provenance.input_summary,
                dag_audit_records=dag_audit_records,
            )

        return pipeline, provenance

    def compose_pipeline(
        self,
        fragments: list[PlanFragment],
        *,
        inputs: PlannerInputs | None = None,
    ) -> tuple[list[PlanFragment], PipelineProvenance]:
        """Full pipeline: filter -> policy -> resolve conflicts -> order.

        Args:
            fragments: Candidate plan fragments from strategies.
            inputs: Structured envelope with recon artifacts and handler count.

        Returns:
            A tuple of (ordered pipeline, provenance ledger).
        """
        if inputs is not None:
            effective_total_handlers = inputs.total_handlers
            input_summary = inputs.to_input_summary()
            # Apply policy overrides from inputs envelope
            if inputs.policy_overrides:
                if "coverage_threshold" in inputs.policy_overrides:
                    self.policy.direct_coverage_threshold = float(
                        inputs.policy_overrides["coverage_threshold"],
                    )
                if "max_risk_score" in inputs.policy_overrides:
                    self.policy.max_risk_score = float(
                        inputs.policy_overrides["max_risk_score"],
                    )
                if "allow_fallback_families" in inputs.policy_overrides:
                    self.policy.allow_fallback_families = bool(
                        inputs.policy_overrides["allow_fallback_families"],
                    )
        else:
            effective_total_handlers = 0
            input_summary = None

        rows: list[DecisionRecord] = []

        # --- Gate 1: Empty filter (fragments with no actions) ---
        filtered: list[PlanFragment] = []
        for f in fragments:
            if f.is_empty():
                rows.append(self._record(
                    f,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_EMPTY,
                    reason="fragment has no modifications",
                ))
            else:
                filtered.append(f)

        # --- Gate 2: Risk filter (risk_score > threshold) ---
        risk_passed: list[PlanFragment] = []
        for f in filtered:
            if f.risk_score > self.policy.max_risk_score:
                rows.append(self._record(
                    f,
                    phase=DecisionPhase.POLICY_FILTERED,
                    reason_code=DecisionReasonCode.REJECTED_RISK,
                    reason=(
                        f"risk_score={f.risk_score:.2f} > "
                        f"threshold={self.policy.max_risk_score:.2f}"
                    ),
                ))
            else:
                risk_passed.append(f)

        # --- Hint signal scoring (between Gate 2 and Gate 3) ---
        signals = derive_hint_signals(inputs)
        hint_adjustments: dict[str, HintAdjustment] = {}
        effective_scores: dict[str, float] = {}
        for f in risk_passed:
            adj = compute_hint_adjustment(f, signals)
            hint_adjustments[f.strategy_name] = adj
            effective_scores[f.strategy_name] = (
                f.expected_benefit.composite_score() + adj.score_delta
            )

        # --- Wrap surviving fragments in PlannerCandidates ---
        candidates = [
            PlannerCandidate(
                fragment=f,
                base_score=f.expected_benefit.composite_score(),
                hint_adjustment=hint_adjustments.get(
                    f.strategy_name, HintAdjustment(),
                ),
                effective_score=effective_scores.get(
                    f.strategy_name, f.expected_benefit.composite_score(),
                ),
            )
            for f in risk_passed
        ]

        # --- Gate 3: Policy gate (coverage threshold drops fallbacks) ---
        accepted_candidates = self._apply_policy_with_provenance_candidates(
            candidates, effective_total_handlers, rows,
        )

        # --- Gate 4: Conflict resolution (greedy independent set) ---
        accepted_fragments = [c.fragment for c in accepted_candidates]
        conflicts = self.find_conflicts(accepted_fragments)
        if conflicts:
            accepted_candidates = self._resolve_conflicts_candidates(
                accepted_candidates, conflicts, rows,
            )

        # --- Gate 5: Selection (surviving candidates) ---
        ordered_candidates = self._order_candidates(accepted_candidates)
        for c in ordered_candidates:
            decision = PlannerDecision(
                candidate=c,
                reason=PlannerDecisionReason.ACCEPTED,
                detail=(
                    f"composite_score={c.base_score:.1f}, "
                    f"selected into pipeline"
                ),
            )
            rows.append(decision.to_decision_record())

        ordered = [c.fragment for c in ordered_candidates]

        provenance = PipelineProvenance(
            rows=tuple(rows),
            input_summary=input_summary,
        )
        logger.info("Pipeline provenance: %s", provenance.summary())
        return ordered, provenance

    def order_fragments(
        self,
        fragments: list[PlanFragment],
        *,
        effective_scores: dict[str, float] | None = None,
    ) -> list[PlanFragment]:
        """Order by prerequisites first, then by descending effective score.

        Args:
            fragments: Fragments to order.
            effective_scores: Optional mapping of strategy_name to effective score
                (composite + hint delta). Falls back to composite_score() when absent.
        """
        ordered: list[PlanFragment] = []
        remaining = list(fragments)
        resolved_names: set[str] = set()

        def _score(f: PlanFragment) -> float:
            if effective_scores is not None and f.strategy_name in effective_scores:
                return effective_scores[f.strategy_name]
            return f.expected_benefit.composite_score()

        while remaining:
            ready = [
                f for f in remaining if all(p in resolved_names for p in f.prerequisites)
            ]
            if not ready:
                ready = remaining  # cycle or unmet prereqs — add by score
            ready.sort(key=_score, reverse=True)
            chosen = ready[0]
            ordered.append(chosen)
            resolved_names.add(chosen.strategy_name)
            remaining.remove(chosen)
        return ordered

    def find_conflicts(
        self, fragments: list[PlanFragment]
    ) -> list[tuple[str, str, frozenset[int]]]:
        """Find pairs of fragments with overlapping block, edge, or transition ownership."""
        conflicts = []
        for i, a in enumerate(fragments):
            for b in fragments[i + 1 :]:
                block_overlap = a.ownership.overlap_blocks(b.ownership)
                edge_overlap = a.ownership.overlap_edges(b.ownership)
                trans_overlap = a.ownership.transitions & b.ownership.transitions
                if block_overlap or edge_overlap or trans_overlap:
                    conflicts.append((a.strategy_name, b.strategy_name, block_overlap))
        return conflicts

    def _apply_policy_with_provenance_candidates(
        self,
        candidates: list[PlannerCandidate],
        total_handlers: int,
        rows: list[DecisionRecord],
    ) -> list[PlannerCandidate]:
        """Apply policy gate on candidates and record provenance for dropped fallbacks."""
        if not self.policy.allow_fallback_families:
            accepted: list[PlannerCandidate] = []
            for c in candidates:
                if c.family == FAMILY_FALLBACK:
                    decision = PlannerDecision(
                        candidate=c,
                        reason=PlannerDecisionReason.REJECTED_POLICY,
                        detail="fallback families disallowed by policy",
                    )
                    rows.append(decision.to_decision_record())
                else:
                    accepted.append(c)
            return accepted

        direct_handlers = sum(
            c.fragment.expected_benefit.handlers_resolved
            for c in candidates
            if c.family != FAMILY_FALLBACK
        )
        if total_handlers > 0:
            coverage = direct_handlers / total_handlers
            if coverage >= self.policy.direct_coverage_threshold:
                accepted = []
                for c in candidates:
                    if c.family == FAMILY_FALLBACK:
                        decision = PlannerDecision(
                            candidate=c,
                            reason=PlannerDecisionReason.REJECTED_POLICY,
                            detail=(
                                f"direct coverage {coverage:.0%} >= "
                                f"{self.policy.direct_coverage_threshold:.0%} threshold"
                            ),
                        )
                        rows.append(decision.to_decision_record())
                    else:
                        accepted.append(c)
                return accepted
        return candidates

    def _resolve_conflicts_candidates(
        self,
        candidates: list[PlannerCandidate],
        conflicts: list[tuple[str, str, frozenset[int]]],
        rows: list[DecisionRecord],
    ) -> list[PlannerCandidate]:
        """Greedy independent set on candidates with provenance for dropped ones."""
        scored = sorted(
            candidates,
            key=lambda c: c.effective_score,
            reverse=True,
        )
        accepted: list[PlannerCandidate] = []
        claimed = OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )
        for c in scored:
            overlap_blocks = c.ownership.blocks & claimed.blocks
            overlap_edges = c.ownership.edges & claimed.edges
            overlap_transitions = c.ownership.transitions & claimed.transitions
            if not overlap_blocks and not overlap_edges and not overlap_transitions:
                accepted.append(c)
                claimed = claimed.union(c.ownership)
            elif self._can_stack_cleanup_block_overlap(c, accepted):
                accepted.append(c)
                claimed = claimed.union(c.ownership)
            else:
                decision = PlannerDecision(
                    candidate=c,
                    reason=PlannerDecisionReason.REJECTED_CONFLICT,
                    detail=(
                        f"ownership conflict: {len(overlap_blocks)} shared blocks"
                    ),
                )
                rows.append(decision.to_decision_record())
        return accepted

    @staticmethod
    def _can_stack_cleanup_block_overlap(
        candidate: PlannerCandidate,
        accepted: list[PlannerCandidate],
    ) -> bool:
        """Allow narrow cleanup fragments to stack on prerequisite blocks.

        Some cleanup passes intentionally operate inside blocks already claimed
        by a prerequisite direct strategy, without rewriting CFG edges or state
        transitions.  Those should be allowed to layer on top of the selected
        prerequisite instead of being conflict-dropped.
        """
        metadata = getattr(candidate.fragment, "metadata", {}) or {}
        if not metadata.get("allow_prerequisite_block_overlap"):
            return False

        overlap_edges = set(candidate.ownership.edges)
        overlap_transitions = set(candidate.ownership.transitions)
        overlapping_accepted: list[PlannerCandidate] = []
        for accepted_candidate in accepted:
            if candidate.ownership.blocks.isdisjoint(accepted_candidate.ownership.blocks):
                continue
            overlapping_accepted.append(accepted_candidate)
            if candidate.ownership.edges & accepted_candidate.ownership.edges:
                return False
            if (
                candidate.ownership.transitions
                & accepted_candidate.ownership.transitions
            ):
                return False
            overlap_edges -= accepted_candidate.ownership.edges
            overlap_transitions -= accepted_candidate.ownership.transitions

        if not overlapping_accepted:
            return False
        if overlap_edges or overlap_transitions:
            return False

        prerequisite_names = set(candidate.prerequisites)
        if not prerequisite_names:
            return False
        return all(
            accepted_candidate.strategy_name in prerequisite_names
            for accepted_candidate in overlapping_accepted
        )

    def _order_candidates(
        self,
        candidates: list[PlannerCandidate],
    ) -> list[PlannerCandidate]:
        """Order candidates by prerequisites first, then by descending effective score."""
        ordered: list[PlannerCandidate] = []
        remaining = list(candidates)
        resolved_names: set[str] = set()

        while remaining:
            ready = [
                c for c in remaining
                if all(p in resolved_names for p in c.prerequisites)
            ]
            if not ready:
                ready = remaining  # cycle or unmet prereqs — add by score
            ready.sort(key=lambda c: c.effective_score, reverse=True)
            chosen = ready[0]
            ordered.append(chosen)
            resolved_names.add(chosen.strategy_name)
            remaining.remove(chosen)
        return ordered

    @staticmethod
    def _record(
        frag: PlanFragment,
        *,
        phase: DecisionPhase,
        reason_code: DecisionReasonCode,
        reason: str,
        ownership_blocks: frozenset[int] | None = None,
        base_score: float = 0.0,
        hint_score_delta: float = 0.0,
        effective_score: float = 0.0,
        hint_reasons: tuple[str, ...] = (),
    ) -> DecisionRecord:
        """Build a DecisionRecord from a PlanFragment."""
        return DecisionRecord(
            strategy_name=frag.strategy_name,
            family=frag.family,
            phase=phase,
            reason_code=reason_code,
            reason=reason,
            composite_score=frag.expected_benefit.composite_score(),
            risk_score=frag.risk_score,
            handler_count=frag.expected_benefit.handlers_resolved,
            transition_count=frag.expected_benefit.transitions_resolved,
            ownership_blocks=ownership_blocks or frozenset(frag.ownership.blocks),
            prerequisites=frozenset(frag.prerequisites),
            base_score=base_score,
            hint_score_delta=hint_score_delta,
            effective_score=effective_score,
            hint_reasons=hint_reasons,
        )
