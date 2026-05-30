"""Experimental hammock-style lowering for exact conditional semantic nodes.

Unlike straight-line exact-node lowering, this strategy owns the source node as
one mini-region: predicate head, taken setup path, semantic successor, and the
untaken terminal arm.  The first live target is `0x298372CC -> 0x09EB3382`.
"""
from __future__ import annotations

from d810.core import logging
from d810.transforms.lowering import LoweringMode
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.flow.sese_hammock import (
    ExactConditionalNodeShape,
    conditional_distance_to_return as _conditional_distance_to_return,
    compute_postdominator_tree as _compute_postdominator_tree,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
)
from d810.cfg.semantic_conditional_lowering import (
    ConditionalExactNodeSite,
    ExactConditionalSiteInventory,
    analyze_exact_conditional_sites,
    collect_conditional_node_scope as _collect_conditional_node_scope,
    collect_exact_conditional_sites,
    edge_kind_name as _edge_kind_name,
    site_key as _site_key,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    build_semantic_exact_round_summary,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile_gate import (
    accepts_exact_sub7ffd_glbopt1,
)
from d810.analyses.control_flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)
from d810.analyses.control_flow.shared_suffix_discovery import (
    pred_split_target_reaches_via_pred,
)

logger = logging.getLogger(
    "D810.hodur.strategy.exact_conditional_node",
    logging.DEBUG,
)

__all__ = [
    "ConditionalExactNodeSite",
    "ExactConditionalNodeLoweringStrategy",
    "ExactConditionalNodeShape",
    "ExactConditionalSiteInventory",
    "analyze_exact_conditional_sites",
    "collect_exact_conditional_sites",
]


@algorithm_metadata(
    algorithm_id="hodur.exact_conditional_node_lowering",
    family="semantic_exact_node_lowering",
    summary="Predicate-aware hammock lowering for exact conditional semantic nodes.",
    use_cases=(
        "Lower an exact semantic node with a local predicate, a taken setup path, and an untaken terminal/return arm.",
        "Preserve both exits of a conditional exact node instead of collapsing it into a single direct successor jump.",
    ),
    examples=(
        "Treat `0x298372CC` as a mini-region with head predicate, taken setup path, semantic successor `0x09EB3382`, and untaken return.",
        "Generalize to any exact source site with one conditional transition and one sibling conditional return.",
    ),
    tags=("exact-node", "conditional", "hammock", "predicate-aware", "tail-duplication"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_node.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/semantic_exact_node.py",
    ),
)
class ExactConditionalNodeLoweringStrategy:
    """Lower exact conditional sites by owning both exits together."""

    lowering_mode = LoweringMode.DIRECT_GRAPH
    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "exact_conditional_node_lowering"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot) -> bool:
        if not accepts_exact_sub7ffd_glbopt1(
            snapshot,
            expected_entry_ea=_SUB7FFD_FUNC_EA,
        ):
            return False
        return (
            getattr(snapshot, "state_machine", None) is not None
            and getattr(snapshot, "bst_result", None) is not None
            and getattr(snapshot, "flow_graph", None) is not None
            and getattr(snapshot, "bst_dispatcher_serial", -1) >= 0
        )

    def plan(self, snapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        setup, round_summary = build_semantic_exact_round_summary(snapshot)
        flow_graph = snapshot.flow_graph
        mba = snapshot.mba
        assert flow_graph is not None
        assert mba is not None

        sites, inventory = analyze_exact_conditional_sites(round_summary, flow_graph)
        if not sites:
            logger.info(
                "EXACT CONDITIONAL NODE: no conditional exact-node sites found (multi_transition=%s missing_return=%s shape_rejected=%s alias_handled=%s)",
                inventory.multi_transition_blocks,
                inventory.missing_return_blocks,
                inventory.shape_rejected_blocks,
                inventory.alias_handled_blocks,
            )
            return None
        logger.info(
            "EXACT CONDITIONAL NODE: inventory selected=%d multi_transition=%s missing_return=%s shape_rejected=%s alias_handled=%s",
            inventory.selected_count,
            inventory.multi_transition_blocks,
            inventory.missing_return_blocks,
            inventory.shape_rejected_blocks,
            inventory.alias_handled_blocks,
        )
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        accepted_edges: list[tuple[int, int]] = []
        emission_modes: list[str] = []
        for site in sites:
            taken_snapshot = flow_graph.get_block(site.taken_tail)
            if taken_snapshot is None:
                continue
            emission_mode = "taken_suffix_redirect"
            direct_plan = plan_direct_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=int(site.taken_tail),
                target_entry=int(site.target_entry),
                ordered_path=tuple(
                    int(node) for node in getattr(site.transition_edge, "ordered_path", ()) or ()
                ),
            )
            if not direct_plan.accepted:
                continue

            if int(getattr(taken_snapshot, "npred", 0)) > 1:
                bst_blocks = {
                    int(block)
                    for block in getattr(snapshot.bst_result, "bst_node_blocks", set()) or set()
                }
                can_pred_split = not pred_split_target_reaches_via_pred(
                    flow_graph,
                    target_entry=int(site.target_entry),
                    via_pred=int(site.source_block),
                    source_block=int(site.taken_tail),
                    ignored_blocks=bst_blocks | {int(snapshot.bst_dispatcher_serial)},
                )
                if can_pred_split:
                    modifications.append(
                        setup.builder.edge_redirect(
                            site.taken_tail,
                            site.target_entry,
                            via_pred=site.source_block,
                            rule_priority=650,
                        )
                    )
                    emission_mode = "taken_suffix_pred_split"
                else:
                    modifications.extend(direct_plan.modifications)
            else:
                modifications.extend(direct_plan.modifications)
            site_blocks, site_edges = _collect_conditional_node_scope(
                round_summary.dag,
                site.transition_edge,
                source_state=site.source_state,
                source_block=site.source_block,
            )
            site_edges.add((site.taken_tail, site.target_entry))
            owned_blocks.update(site_blocks)
            owned_edges.update(site_edges)
            owned_transitions.add((site.source_state, site.target_state))
            accepted_edges.append((site.source_state, site.target_state))
            emission_modes.append(emission_mode)
            logger.info(
                "EXACT CONDITIONAL NODE: edge 0x%08X -> 0x%08X lowered via %s (source=%d taken_tail=%d target=%d taken_succ=%d fallback_succ=%d follow=%s dist=(taken=%s,fallback=%s) owned_blocks=%s)",
                site.source_state,
                site.target_state,
                emission_mode,
                site.source_block,
                site.taken_tail,
                site.target_entry,
                site.shape.taken_successor,
                site.shape.fallback_successor,
                "None" if site.shape.follow_block is None else str(site.shape.follow_block),
                "None"
                if site.shape.taken_return_distance is None
                else str(site.shape.taken_return_distance),
                "None"
                if site.shape.fallback_return_distance is None
                else str(site.shape.fallback_return_distance),
                sorted(site_blocks),
            )
        if not modifications:
            return None

        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            flow_graph,
            int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            reachable_from_serial=getattr(getattr(snapshot, "reachability", None), "entry_serial", None),
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(owned_transitions),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(accepted_edges),
                transitions_resolved=len(accepted_edges),
                blocks_freed=0,
                conflict_density=0.15,
            ),
            risk_score=0.2,
            metadata={
                "accepted_edges": tuple(accepted_edges),
                "safeguard_min_required": max(1, len(modifications)),
                "allow_post_apply_bst_cleanup": False,
                "post_apply_bst_cleanup_group": "exact_nodes",
                "post_apply_bst_cleanup_reason": "exact_conditional_node_lowering",
                "residual_dispatcher_preds": tuple(int(serial) for serial in residual_dispatcher_preds),
                "emission_modes": tuple(emission_modes),
                "site_count": len(accepted_edges),
            },
        )
