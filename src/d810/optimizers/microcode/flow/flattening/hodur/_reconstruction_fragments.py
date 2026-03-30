from __future__ import annotations

from d810.cfg.graph_modification import (
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.plan import is_block_creating_modification
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)


def finalize_reconstruction_fragment(
    logger,
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
) -> PlanFragment:
    _PTS_TYPES = (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)
    pts_mods = [m for m in modifications if isinstance(m, _PTS_TYPES)]
    has_block_creators = any(is_block_creating_modification(m) for m in modifications)

    if pts_mods and has_block_creators:
        non_pts_mods = [m for m in modifications if not isinstance(m, _PTS_TYPES)]
        logger.info(
            "RECON: deferring %d PTS mods to next invocation "
            "(block-creating ops would shift suffix serials)",
            len(pts_mods),
        )
        modifications = non_pts_mods

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
            "safeguard_min_required": 1,
        },
        modifications=modifications,
    )


__all__ = ["finalize_reconstruction_fragment"]
