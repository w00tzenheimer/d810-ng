"""Terminal plan-fragment finalizer for the Hodur reconstruction strategy.

Packages the round's accumulated modifications + ownership + metadata into a
``PlanFragment``. Also applies the late PTS-vs-block-creator deferral and the
structured-region-leakage soft-gate on post-apply BST cleanup.

Lives in the Hodur strategies package because ``PlanFragment`` is a
Hodur-specific type; moving this to ``d810.cfg`` would require an upward
import. Kept Hodur-local per the Option C decomposition plan.
"""
from __future__ import annotations

from d810.core import logging
from d810.cfg.graph_modification import (
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
)
from d810.cfg.plan import is_block_creating_modification
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    LinearizationDecision,
    PlannerContextContribution,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)


__all__ = ("finalize_reconstruction_fragment",)


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
    linearizations = tuple(
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
        linearizations=linearizations,
        neutralizations=(),
        claimed_sources=frozenset(int(blk) for blk in owned_blocks),
    )


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
) -> PlanFragment:
    """Assemble the terminal ``PlanFragment`` for one reconstruction round."""
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
        },
        modifications=modifications,
    )
