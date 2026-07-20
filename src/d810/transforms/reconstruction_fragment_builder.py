"Terminal plan-fragment finalizer for the Hodur reconstruction strategy.\n\nPackages the round's accumulated modifications + ownership + metadata into a\n``PlanFragment``. Also applies the late PTS-vs-block-creator deferral and the\nstructured-region-leakage soft-gate on post-apply condition-chain cleanup.\n\nLives in the Hodur strategies package because ``PlanFragment`` is a\nHodur-specific type; moving this to ``d810.transforms`` would require an upward\nimport. Kept Hodur-local per the Option C decomposition plan.\n\nConflict-resolution filter cascade (uee-jrgq Phase 6 \u2014 retirement gate)\n=======================================================================\n\nWhen ``finalize_reconstruction_fragment`` runs, modifications flow through\ntwo filters in this order.  Each filter is single-purpose; together they\nform a cascade with a clear retirement criterion.\n\n  1. ``filter_dag_disagreements`` (Phase 3 of uee-jrgq) \u2014 the shared\n     engine DAG-as-arbiter check.  When\n     ``cumulative_planner_view.dag_authority`` is present, each redirect\n     mod is validated against the preanalysis DAG's canonical decision.  Drops\n     on ``DAG_DISAGREEMENT``; keeps and lets through on ``ALLOW`` or\n     ``DAG_GAP:<name>`` (DAG silent).  Records each disagreement as a\n     ``DagDisagreementRecord`` (Phase 5) for the pipeline-level audit\n     summary.\n\n  2. ``_drop_conflicting_redirects`` \u2014 legacy \"first-fragment-wins\"\n     Mode 1 filter.  Fallback for DAG_GAP regions where the DAG cannot\n     answer authoritatively.  Reads ``cumulative_planner_view``'s\n     ``LinearizationDecision`` aggregates (echoed from prior fragments'\n     emitted mods via ``_build_planner_context_contribution``).\n\nRetirement gate\n---------------\nFilter (2) and the mod-echo logic in\n``_build_planner_context_contribution`` are conceptually redundant once\nthe DAG arbiter has authoritative coverage of every emission decision\npoint.  Today the DAG returns ``DAG_GAP`` for sources the\n``LinearizedStateDag`` doesn't enumerate as in-scope edges.  Until\nthose gaps close, retiring the legacy filter would regress observable\nbehaviour \u2014 e.g., on sub_7FFD3338C040 the legacy filter catches 5 of 8\nMode 1 drops in DAG_GAP regions that the arbiter cannot yet see.\n\nRetirement criterion: when ``PipelineProvenance.dag_audit_records``\nshows zero ``DAG_GAP``-bucket drops on the corpus AND filter (2)\nfires zero times across the corpus for a full release cycle, it can\nbe deleted along with the mod-echo in ``_build_planner_context_contribution``.\n\nThis module's docstring + Phase 6 commit (uee-6yu7) formalises the\nretirement contract; the actual deletion lands as a follow-up commit\nonce the criterion is met.\n"
from __future__ import annotations

from d810.core import logging
from d810.transforms.graph_modification import (
    ConvertToGoto,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
)
from d810.transforms.plan import is_block_creating_modification
from d810.transforms.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    CumulativePlannerView,
    LinearizationDecision,
    PlannerContextContribution,
)
from d810.transforms.fragment_arbitration import (
    DAG_AUDIT_METADATA_KEY,
    filter_dag_disagreements,
)
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)


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
    return PlannerContextContribution(
        linearizations=redirect_linearizations,
        neutralizations=(),
        claimed_sources=frozenset(int(blk) for blk in owned_blocks),
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


def _drop_conflicting_redirects(
    modifications: list,
    cumulative_planner_view: CumulativePlannerView | None,
    *,
    strategy_name: str,
) -> list:
    "Drop RedirectGoto mods that contradict prior-fragment linearizations.\n\n    Legacy \"first-fragment-wins\" Mode 1 filter.  Since Phase 3 of\n    uee-jrgq, this filter is the FALLBACK consulted only for mods the\n    DagAuthority returned ``DAG_GAP`` for \u2014 i.e., regions where the\n    preanalysis DAG cannot answer authoritatively.  For DAG-known regions,\n    ``filter_dag_disagreements`` has already dropped any planner mod that\n    disagreed with the canonical DAG decision, so this filter sees\n    only conforming or gap-region mods.\n\n    Original Mode 1 fix rationale (preserved for context): when SSR\n    (running first in the pipeline) linearizes blk[X] to tgt=A via a\n    RedirectGoto, then SRW (running second) queues RedirectGoto src=X\n    tgt=B (B != A), the coalescer can't dedupe because old_target\n    differs.  The engine's ``PLANNER_CTX_CONFLICT`` diagnostic surfaces\n    this, but defaults to log-only.  This filter enforces\n    \"first fragment wins\" \u2014 SRW's contradictory emission is dropped\n    and SSR's decision stands.\n\n    Returns the filtered list. Non-RedirectGoto mods are untouched.\n    Matching emissions (same src + same new_target) are also untouched.\n    "
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
    allow_post_apply_condition_chain_cleanup: bool,
    post_apply_condition_chain_cleanup_reason: str | None,
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
    if leaked_units and allow_post_apply_condition_chain_cleanup:
        allow_post_apply_condition_chain_cleanup = False
        post_apply_condition_chain_cleanup_reason = "structured_region_leakage"

    if pts_mods and has_block_creators:
        non_pts_mods = [mod for mod in modifications if not isinstance(mod, pts_types)]
        logger.info(
            "RECON: deferring %d PTS mods to next invocation "
            "(block-creating ops would shift suffix serials)",
            len(pts_mods),
        )
        modifications = non_pts_mods

    # Phase 3 of uee-jrgq: DAG-as-arbiter conformance check runs
    # BEFORE the legacy prior-fragment-wins filter.  When the DAG can
    # answer authoritatively, its decision wins; when it returns
    # DAG_GAP the legacy filter is consulted as a fallback.
    # Phase 5: also captures structured DagDisagreementRecord per drop
    # for the per-run PLANNER_DAG_AUDIT summary.
    modifications, dag_audit_records = filter_dag_disagreements(
        modifications,
        cumulative_planner_view,
        strategy_name=strategy_name,
        phase="post_apply_filter",
        log_prefix="RECON DAG_ARBITER",
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
            "allow_post_apply_condition_chain_cleanup": allow_post_apply_condition_chain_cleanup,
            "post_apply_condition_chain_cleanup_reason": post_apply_condition_chain_cleanup_reason,
            "residual_dispatcher_preds": residual_dispatcher_preds,
            "structured_region_fidelity": structured_region_fidelity,
            "safeguard_min_required": 1,
            PLANNER_CTX_METADATA_KEY: planner_ctx,
            DAG_AUDIT_METADATA_KEY: dag_audit_records,
        },
        modifications=modifications,
    )
