"""Terminal plan-fragment finalizer for the Hodur reconstruction strategy.

Packages the round's accumulated modifications + ownership + metadata into a
``PlanFragment``. Also applies the late PTS-vs-block-creator deferral and the
structured-region-leakage soft-gate on post-apply BST cleanup.

Lives in the Hodur strategies package because ``PlanFragment`` is a
Hodur-specific type; moving this to ``d810.cfg`` would require an upward
import. Kept Hodur-local per the Option C decomposition plan.

Conflict-resolution filter cascade (uee-jrgq Phase 6 — retirement gate)
=======================================================================

When ``finalize_reconstruction_fragment`` runs, modifications flow through
three filters in this order.  Each filter is single-purpose; together they
form a cascade with a clear retirement criterion.

  1. ``_drop_intra_fragment_dup_conflicts`` — intra-fragment overlap
     between ``DuplicateAndRedirect`` and ``RedirectGoto``/``ConvertToGoto``
     on the same source.  DupAndRedirect always wins (per-pred routing is
     strictly more expressive than uniform redirect).  Pure intra-fragment
     pass; does NOT consult the cumulative view.

  2. ``_drop_dag_disagreement`` (Phase 3 of uee-jrgq) — the DAG-as-arbiter
     check.  When ``cumulative_planner_view.dag_authority`` is present,
     each redirect mod is validated against the recon DAG's canonical
     decision.  Drops on ``DAG_DISAGREEMENT``; keeps and lets through on
     ``ALLOW`` or ``DAG_GAP:<name>`` (DAG silent).  Records each
     disagreement as a ``DagDisagreementRecord`` (Phase 5) for the
     pipeline-level audit summary.

  3. ``_drop_conflicting_redirects`` — legacy "first-fragment-wins"
     Mode 1 filter.  Fallback for DAG_GAP regions where the DAG cannot
     answer authoritatively.  Reads ``cumulative_planner_view``'s
     ``LinearizationDecision`` aggregates (echoed from prior fragments'
     emitted mods via ``_build_planner_context_contribution``).

Retirement gate
---------------
Filters (1) and (3) and the mod-echo logic in
``_build_planner_context_contribution`` are CONCEPTUALLY redundant once
the DAG arbiter has authoritative coverage of every emission decision
point.  Today the DAG returns ``DAG_GAP`` for ``DuplicateAndRedirect``
and ``ZeroStateWrite`` mods (covered by extension tickets uee-7wcd,
uee-7snc, uee-qli0, uee-bwdk) and for sources the
``LinearizedStateDag`` doesn't enumerate as in-scope edges.  Until
those gaps close, retiring the legacy filters would regress observable
behaviour — e.g., on sub_7FFD3338C040 the legacy filter catches 5 of 8
Mode 1 drops in DAG_GAP regions that the arbiter cannot yet see.

Retirement criterion: when ``PipelineProvenance.dag_audit_records``
shows zero ``DAG_GAP``-bucket drops on the corpus AND filters (1)+(3)
fire zero times across the corpus for a full release cycle, both can
be deleted along with the mod-echo in ``_build_planner_context_contribution``.

This module's docstring + Phase 6 commit (uee-6yu7) formalises the
retirement contract; the actual deletion lands as a follow-up commit
once the criterion is met.
"""
from __future__ import annotations

from d810.core import logging
from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
)
from d810.cfg.plan import is_block_creating_modification
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    CumulativePlannerView,
    LinearizationDecision,
    PlannerContextContribution,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DagDisagreementRecord,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)


# Metadata key under which finalize_reconstruction_fragment stores the
# tuple[DagDisagreementRecord, ...] captured during DAG-arbiter conformance
# filtering.  Parallel to PLANNER_CTX_METADATA_KEY; the planner aggregates
# every fragment's records into ``PipelineProvenance.dag_audit_records``
# at the end of ``UnflatteningPlanner.plan()``.
DAG_AUDIT_METADATA_KEY: str = "dag_audit"

__all__ = (
    "DAG_AUDIT_METADATA_KEY",
    "finalize_reconstruction_fragment",
)

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)


def _build_planner_context_contribution(
    *,
    strategy_name: str,
    modifications: list,
    owned_blocks: set[int],
    round_index: int,
) -> PlannerContextContribution:
    """Scan emitted mods + owned_blocks to produce a PlannerContextContribution.

    Every :class:`RedirectGoto` becomes a :class:`LinearizationDecision` so
    later strategies (same pipeline, later rounds) can call
    ``view.is_linearized(src)`` and skip emitting a contradictory reverse
    redirect. Owned blocks populate ``claimed_sources`` so the same
    strategies can also call ``view.is_claimed(src)`` for broader scope.

    Every :class:`DuplicateAndRedirect` also becomes a
    :class:`LinearizationDecision` keyed on its ``source_serial`` (uee-dnhk
    extension).  DupAndRedirect mutates the source block's goto to its
    first per-pred target, so it is a linearization decision in the same
    sense as a RedirectGoto from the cumulative view's perspective.
    Tracking it lets a later strategy that emits a plain RedirectGoto on
    a shared block (a less-specific decision) be dropped by the existing
    Mode 1 filter — empirically observed on sub_7FFD where SRW emits
    DupAndRedirect on shared blocks {10, 32, 35, 64, 100, 104, 156, 184,
    187, 192, 195, 200, 203} while later residual/conditional strategies
    emit overlapping RedirectGotos.  The source's ``source_serial`` is
    also added to ``claimed_sources``.

    ``StateWriteNeutralization`` contributions are deliberately omitted in
    this first pass — building them would require threading the original
    state constant through the emission path (``ZeroStateWrite`` stores
    only the insn_ea, not the pre-zeroing value). Added incrementally.
    """
    redirect_linearizations = tuple(
        LinearizationDecision(
            src=int(mod.from_serial),
            tgt=int(mod.new_target),
            reason="state_write_reconstruction",
            strategy=strategy_name,
            round_index=round_index,
        )
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    )
    dup_linearizations = tuple(
        LinearizationDecision(
            src=int(mod.source_serial),
            # DupAndRedirect's first per-pred entry is the goto target
            # the original block ends up with (later per-pred entries get
            # their own duplicated copies).  Use that as the linearization
            # target so the cumulative view can detect later RedirectGotos
            # that disagree.  Empty per_pred_targets is a planner bug, but
            # we defensively skip rather than crash.
            tgt=int(mod.per_pred_targets[0][1]),
            reason=f"{strategy_name}_duplicate_and_redirect",
            strategy=strategy_name,
            round_index=round_index,
        )
        for mod in modifications
        if isinstance(mod, DuplicateAndRedirect) and mod.per_pred_targets
    )
    dup_claimed_sources = frozenset(
        int(mod.source_serial) for mod in modifications
        if isinstance(mod, DuplicateAndRedirect)
    )
    return PlannerContextContribution(
        linearizations=redirect_linearizations + dup_linearizations,
        neutralizations=(),
        claimed_sources=(
            frozenset(int(blk) for blk in owned_blocks)
            | dup_claimed_sources
        ),
    )


def _redirect_source(mod: object) -> int | None:
    """Return the source-block serial of a RedirectGoto/ConvertToGoto, else None."""
    if isinstance(mod, RedirectGoto):
        return int(mod.from_serial)
    if isinstance(mod, ConvertToGoto):
        return int(mod.block_serial)
    return None


def _redirect_target(mod: object) -> int | None:
    """Return the new target serial of a RedirectGoto/ConvertToGoto, else None."""
    if isinstance(mod, RedirectGoto):
        return int(mod.new_target)
    if isinstance(mod, ConvertToGoto):
        return int(mod.goto_target)
    return None


def _drop_intra_fragment_dup_conflicts(
    modifications: list,
    *,
    strategy_name: str,
) -> list:
    """Drop RedirectGoto/ConvertToGoto when a DupAndRedirect targets the same source.

    Tracer-revealed conflict (uee-dnhk): when one planner emits
    ``DuplicateAndRedirect(source_serial=X, per_pred_targets=[(p1, t1),
    (p2, t2)])`` and another emits ``RedirectGoto(from_serial=X,
    new_target=T)``, both reach the fragment.  Outcomes if both apply:

      * If all per_pred_targets equal T, the RedirectGoto is redundant
        (DupAndRedirect's first per_pred entry already sets blk[X]'s
        goto to t1, and t1 == T).
      * If any per_pred_target differs from T, the result depends on
        apply order: whichever ran last wins on blk[X]'s goto, while
        per-pred routing emitted by DupAndRedirect remains.  Pred-level
        targets diverge from RedirectGoto's uniform intent.

    Resolution policy: **DupAndRedirect always wins**.  Per-pred routing
    is strictly more expressive than uniform RedirectGoto on a shared
    block; the planner that emitted DupAndRedirect knew about the
    multi-pred nature, the one that emitted plain RedirectGoto did not.
    Drop every RedirectGoto/ConvertToGoto whose source matches a
    DupAndRedirect's source_serial.

    This filter does NOT consult ``cumulative_planner_view`` — it is
    purely an intra-fragment pass.  Cross-fragment DupAndRedirect-vs-
    RedirectGoto coordination would require extending the cumulative
    view's contribution model and is tracked separately.

    Returns the filtered list.  Non-redirect, non-dup mods untouched.
    """
    dup_sources = {
        int(mod.source_serial) for mod in modifications
        if isinstance(mod, DuplicateAndRedirect)
    }
    if not dup_sources:
        return modifications
    kept: list = []
    dropped: list[tuple[str, int, int]] = []  # (mod_type, src, dropped_tgt)
    for mod in modifications:
        if isinstance(mod, DuplicateAndRedirect):
            kept.append(mod)
            continue
        src = _redirect_source(mod)
        if src is None or src not in dup_sources:
            kept.append(mod)
            continue
        # Conflict: same source has both a RedirectGoto/ConvertToGoto
        # and a DupAndRedirect.  Drop the redirect, keep the dup.
        tgt = _redirect_target(mod)
        dropped.append((type(mod).__name__, src, tgt if tgt is not None else -1))
    if dropped:
        logger.warning(
            "RECON: dropped %d redirect mod(s) from strategy %r as "
            "intra-fragment duplicates of DuplicateAndRedirect on the "
            "same source (per-pred routing is more specific): %s",
            len(dropped),
            strategy_name,
            "; ".join(
                f"{mtype}(src={src} dropped_tgt={dtgt})"
                for mtype, src, dtgt in dropped[:10]
            ),
        )
    return kept


_DAG_DISAGREEMENT_REGEX = (
    "DAG_DISAGREEMENT:"  # used only for prefix detection in callers
)


def _parse_dag_target_from_reason(reason: str) -> int | None:
    """Extract the DAG canonical target from a DAG_DISAGREEMENT reason.

    The reason format is
    ``DAG_DISAGREEMENT:<src>->{planner=<T1>,dag=<T2>}``. Returns ``T2``
    as ``int`` when parseable, else ``None``. Robust to integer formats
    Python ``int()`` accepts (decimal, ``0x`` hex). Non-numeric or
    malformed reasons return ``None`` so the audit record carries the
    raw reason without crashing.
    """
    marker = "dag="
    idx = reason.find(marker)
    if idx == -1:
        return None
    tail = reason[idx + len(marker):]
    # Trim trailing punctuation like '}' or ',' or whitespace.
    end = 0
    for ch in tail:
        if ch in "0123456789abcdefABCDEFxX":
            end += 1
        else:
            break
    raw = tail[:end]
    if not raw:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return None


def _drop_dag_disagreement(
    modifications: list,
    cumulative_planner_view: CumulativePlannerView | None,
    *,
    strategy_name: str,
    phase: str = "post_apply_filter",
) -> tuple[list, tuple[DagDisagreementRecord, ...]]:
    """Drop redirect mods the DAG-arbiter refuses (Phase 3 of uee-jrgq).

    Phase 5 extension: alongside the filtered modification list, returns a
    tuple of :class:`DagDisagreementRecord` per dropped mod so the
    planner can aggregate per-run audit data into
    :attr:`PipelineProvenance.dag_audit_records` and emit a
    ``PLANNER_DAG_AUDIT`` summary at the end of the run.

    DAG-as-arbiter conformance check: ask the DagAuthority whether each
    redirect mod is permitted by the canonical recon DAG.  Resolution
    rules:

      * ``ALLOW`` → keep (mod conforms to DAG)
      * ``DAG_DISAGREEMENT:...`` → drop (planner proposed a target the
        DAG explicitly disagrees with) + log DAG_DISAGREEMENT + record
      * ``DAG_GAP:...`` → keep (DAG silent; let the legacy
        prior-fragment-wins filter
        ``_drop_conflicting_redirects`` decide whether to drop)

    Only RedirectGoto / ConvertToGoto are validated here today — those
    are the two mod kinds whose DAG queries are fully covered.  Other
    mod kinds (DupAndRedirect, ZSW) currently get strict ``DAG_GAP``
    refusals from DagAuthority; we keep them in the fragment and let
    the existing intra-fragment dup-conflict filter / coalescer handle
    them downstream.

    No-op when ``cumulative_planner_view`` lacks a ``dag_authority``
    (legacy / non-Hodur families that haven't built a recon DAG yet);
    returns ``(modifications, ())`` unchanged.
    """
    if cumulative_planner_view is None:
        return modifications, ()
    authority = cumulative_planner_view.dag_authority
    if authority is None:
        return modifications, ()

    kept: list = []
    dropped: list[tuple[str, int, str]] = []  # (mod_type, src, reason)
    records: list[DagDisagreementRecord] = []
    gaps: int = 0
    for mod in modifications:
        # Only validate redirect-shaped mods; let everything else pass.
        if _redirect_source(mod) is None:
            kept.append(mod)
            continue
        decision = authority.permits(mod)
        if decision.allowed:
            kept.append(mod)
            continue
        if decision.is_gap:
            # DAG silent — leave the mod in place for the legacy
            # prior-fragment-wins filter to potentially drop.
            kept.append(mod)
            gaps += 1
            continue
        # decision is a refusal (disagreement or other).  Drop + record.
        src = int(_redirect_source(mod) or -1)
        planner_tgt = _redirect_target(mod)
        dag_tgt = (
            _parse_dag_target_from_reason(decision.reason)
            if decision.is_disagreement
            else None
        )
        records.append(
            DagDisagreementRecord(
                planner_name=strategy_name,
                mod_kind=type(mod).__name__,
                source_block=src,
                # branch_arm: today every emission is unconditional
                # (RedirectGoto / ConvertToGoto), so the canonical anchor
                # is None.  Future arm-aware mod kinds will populate this.
                branch_arm=None,
                planner_target=int(planner_tgt) if planner_tgt is not None else None,
                dag_target=dag_tgt,
                phase=phase,
                decision_reason=decision.reason,
            )
        )
        dropped.append((type(mod).__name__, src, decision.reason))
    if dropped:
        logger.warning(
            "RECON DAG_ARBITER: dropped %d mod(s) from strategy %r as "
            "DAG-disagreement (planner target ≠ DAG canonical target): %s",
            len(dropped),
            strategy_name,
            "; ".join(
                f"{mtype}(src={src} reason={reason})"
                for mtype, src, reason in dropped[:10]
            ),
        )
    if gaps:
        logger.debug(
            "RECON DAG_ARBITER: %d mod(s) from strategy %r in DAG_GAP "
            "regions; deferring to legacy prior-fragment-wins filter",
            gaps, strategy_name,
        )
    return kept, tuple(records)


def _drop_conflicting_redirects(
    modifications: list,
    cumulative_planner_view: CumulativePlannerView | None,
    *,
    strategy_name: str,
) -> list:
    """Drop RedirectGoto mods that contradict prior-fragment linearizations.

    Legacy "first-fragment-wins" Mode 1 filter.  Since Phase 3 of
    uee-jrgq, this filter is the FALLBACK consulted only for mods the
    DagAuthority returned ``DAG_GAP`` for — i.e., regions where the
    recon DAG cannot answer authoritatively.  For DAG-known regions,
    ``_drop_dag_disagreement`` has already dropped any planner mod that
    disagreed with the canonical DAG decision, so this filter sees
    only conforming or gap-region mods.

    Original Mode 1 fix rationale (preserved for context): when SSR
    (running first in the pipeline) linearizes blk[X] to tgt=A via a
    RedirectGoto, then SRW (running second) queues RedirectGoto src=X
    tgt=B (B != A), the coalescer can't dedupe because old_target
    differs.  The engine's ``PLANNER_CTX_CONFLICT`` diagnostic surfaces
    this, but defaults to log-only.  This filter enforces
    "first fragment wins" — SRW's contradictory emission is dropped
    and SSR's decision stands.

    Returns the filtered list. Non-RedirectGoto mods are untouched.
    Matching emissions (same src + same new_target) are also untouched.
    """
    if cumulative_planner_view is None:
        return modifications
    kept: list = []
    dropped: list[tuple[str, int, int, int]] = []  # (mod_type, src, prior_tgt, dropped_tgt)
    for mod in modifications:
        src = _redirect_source(mod)
        new_tgt = _redirect_target(mod)
        if src is None or new_tgt is None:
            kept.append(mod)
            continue
        prior_tgt = cumulative_planner_view.linearization_target_for(src)
        if prior_tgt is None or prior_tgt == new_tgt:
            kept.append(mod)
            continue
        dropped.append((type(mod).__name__, src, int(prior_tgt), new_tgt))
    if dropped:
        logger.warning(
            "RECON: dropped %d mod(s) from strategy %r to honor prior "
            "cross-fragment linearizations: %s",
            len(dropped),
            strategy_name,
            "; ".join(
                f"{mtype}(src={src} prior_tgt={ptgt} dropped_tgt={dtgt})"
                for mtype, src, ptgt, dtgt in dropped[:10]
            ),
        )
    return kept


def finalize_reconstruction_fragment(
    *,
    strategy_name: str,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    rejected_metadata: list[dict[str, int | str | None]],
    allow_post_apply_bst_cleanup: bool,
    post_apply_bst_cleanup_reason: str | None,
    residual_dispatcher_preds: tuple[int, ...],
    structured_region_fidelity: dict[str, object] | None = None,
    round_index: int = 0,
    cumulative_planner_view: CumulativePlannerView | None = None,
) -> PlanFragment:
    """Assemble the terminal ``PlanFragment`` for one reconstruction round.

    When *cumulative_planner_view* is provided, RedirectGoto mods that
    contradict prior-fragment linearizations are dropped before the
    fragment is returned. Callers (SRW.plan()) should pass
    ``snapshot.cumulative_planner_view`` so Mode 1 conflicts surfaced by
    the engine-level PLANNER_CTX_CONFLICT diagnostic are resolved at
    the emission site rather than merely logged.
    """
    pts_types = (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)
    pts_mods = [mod for mod in modifications if isinstance(mod, pts_types)]
    has_block_creators = any(
        is_block_creating_modification(mod) for mod in modifications
    )
    structured_region_fidelity = structured_region_fidelity or {}
    leaked_units = tuple(structured_region_fidelity.get("leaked_units", ()))
    if leaked_units and allow_post_apply_bst_cleanup:
        allow_post_apply_bst_cleanup = False
        post_apply_bst_cleanup_reason = "structured_region_leakage"

    if pts_mods and has_block_creators:
        non_pts_mods = [mod for mod in modifications if not isinstance(mod, pts_types)]
        logger.info(
            "RECON: deferring %d PTS mods to next invocation "
            "(block-creating ops would shift suffix serials)",
            len(pts_mods),
        )
        modifications = non_pts_mods

    modifications = _drop_intra_fragment_dup_conflicts(
        modifications,
        strategy_name=strategy_name,
    )

    # Phase 3 of uee-jrgq: DAG-as-arbiter conformance check runs
    # BEFORE the legacy prior-fragment-wins filter.  When the DAG can
    # answer authoritatively, its decision wins; when it returns
    # DAG_GAP the legacy filter is consulted as a fallback.
    # Phase 5: also captures structured DagDisagreementRecord per drop
    # for the per-run PLANNER_DAG_AUDIT summary.
    modifications, dag_audit_records = _drop_dag_disagreement(
        modifications,
        cumulative_planner_view,
        strategy_name=strategy_name,
    )

    modifications = _drop_conflicting_redirects(
        modifications,
        cumulative_planner_view,
        strategy_name=strategy_name,
    )

    planner_ctx = _build_planner_context_contribution(
        strategy_name=strategy_name,
        modifications=modifications,
        owned_blocks=owned_blocks,
        round_index=round_index,
    )

    return PlanFragment(
        strategy_name=strategy_name,
        family=FAMILY_DIRECT,
        ownership=OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=len(owned_blocks),
            transitions_resolved=len(accepted_metadata),
            blocks_freed=len(owned_blocks),
            conflict_density=0.0,
        ),
        risk_score=0.25,
        metadata={
            "mode": "experimental_reconstruction",
            "reconstruction_sites": tuple(accepted_metadata),
            "reconstruction_rejections": tuple(rejected_metadata),
            "allow_post_apply_bst_cleanup": allow_post_apply_bst_cleanup,
            "post_apply_bst_cleanup_reason": post_apply_bst_cleanup_reason,
            "residual_dispatcher_preds": residual_dispatcher_preds,
            "structured_region_fidelity": structured_region_fidelity,
            "safeguard_min_required": 1,
            PLANNER_CTX_METADATA_KEY: planner_ctx,
            DAG_AUDIT_METADATA_KEY: dag_audit_records,
        },
        modifications=modifications,
    )
