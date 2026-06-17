"""Post-apply helpers for Hodur-compatible family runtime paths."""
from __future__ import annotations

from d810.core.typing import Any
from d810.transforms.snapshot import AnalysisSnapshot
from d810.transforms.plan_fragment import (
    PlanFragment,
    StageResult,
)
from d810.analyses.control_flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)


def collect_live_residual_dispatcher_preds(
    mba: object,
    snapshot: AnalysisSnapshot,
    *,
    strategies: list[object],
    strategy_name: str,
    cfg_translator: object,
    logger: Any | None = None,
) -> tuple[int, ...]:
    """Collect live residual non-BST predecessors to the dispatcher."""
    bst_result = snapshot.bst_result
    if bst_result is None or snapshot.bst_dispatcher_serial < 0:
        return ()
    strategy = next(
        (
            candidate
            for candidate in strategies
            if getattr(candidate, "name", None) == strategy_name
        ),
        None,
    )
    collector = getattr(strategy, "_collect_residual_dispatcher_predecessors", None)
    if collector is None:
        collector = collect_residual_dispatcher_predecessors
    try:
        flow_graph = cfg_translator.lift(mba)
        raw_collector = getattr(strategy, "_collect_dispatcher_predecessors", None)
        active_collector = raw_collector or collector
        return active_collector(
            flow_graph,
            snapshot.bst_dispatcher_serial,
            bst_node_blocks=set(bst_result.condition_chain_blocks),
        )
    except Exception:
        if logger is not None:
            logger.debug(
                "Failed to collect live residual dispatcher preds for %s",
                strategy_name,
                exc_info=True,
            )
        return ()


def collect_live_lfg_residual_dispatcher_preds(
    mba: object,
    snapshot: AnalysisSnapshot,
    *,
    strategies: list[object],
    cfg_translator: object,
    logger: Any | None = None,
) -> tuple[int, ...]:
    return collect_live_residual_dispatcher_preds(
        mba,
        snapshot,
        strategies=strategies,
        strategy_name="linearized_flow_graph",
        cfg_translator=cfg_translator,
        logger=logger,
    )


def collect_post_apply_bst_cleanup_blockers(
    pipeline: list[PlanFragment],
    results: list[StageResult],
    *,
    live_residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]] | None = None,
) -> dict[str, tuple[int, ...]]:
    """Return strategy blockers that must prevent post-apply BST cleanup."""
    blockers: dict[str, tuple[int, ...]] = {}
    live_residual_dispatcher_preds_by_strategy = (
        live_residual_dispatcher_preds_by_strategy or {}
    )
    for fragment, result in zip(pipeline, results):
        if not (result.success and result.edits_applied > 0):
            continue
        if fragment.metadata.get("allow_post_apply_bst_cleanup", True):
            continue
        cleanup_reason = fragment.metadata.get("post_apply_bst_cleanup_reason")
        group_name = fragment.metadata.get("post_apply_bst_cleanup_group")
        if isinstance(group_name, str):
            residual_source = live_residual_dispatcher_preds_by_strategy.get(
                f"group:{group_name}"
            )
            if residual_source is not None:
                residual_preds = tuple(int(serial) for serial in residual_source)
                if not residual_preds:
                    continue
                blockers[fragment.strategy_name] = residual_preds
                continue
        residual_preds = tuple(
            int(serial)
            for serial in live_residual_dispatcher_preds_by_strategy.get(
                fragment.strategy_name,
                tuple(fragment.metadata.get("residual_dispatcher_preds", ())),
            )
        )
        if residual_preds:
            blockers[fragment.strategy_name] = residual_preds
            continue
        if isinstance(cleanup_reason, str) and cleanup_reason:
            blockers[fragment.strategy_name] = ()
    return blockers
