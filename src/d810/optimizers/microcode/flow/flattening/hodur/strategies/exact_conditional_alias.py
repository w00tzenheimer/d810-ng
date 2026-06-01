"""Alias-aware lowering for duplicate-arm exact conditional nodes."""
from __future__ import annotations

from d810.core import logging
from d810.transforms.lowering import LoweringMode
from d810.core.algorithm_metadata import algorithm_metadata
from d810.transforms.semantic_conditional_lowering import (
    ExactConditionalAliasInventory,
    analyze_exact_conditional_alias_sites,
    collect_exact_conditional_alias_sites,
)
from d810.transforms.plan_fragment import (
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
    "D810.hodur.strategy.exact_conditional_alias",
    logging.DEBUG,
)

__all__ = [
    "ExactConditionalAliasInventory",
    "ExactConditionalAliasNodeLoweringStrategy",
    "analyze_exact_conditional_alias_sites",
    "collect_exact_conditional_alias_sites",
]


@algorithm_metadata(
    algorithm_id="hodur.exact_conditional_alias_lowering",
    family="semantic_exact_node_lowering",
    summary="Lower duplicate-arm exact conditional nodes by collapsing alias-equivalent semantic exits to one canonical target.",
    use_cases=(
        "Handle conditional exact sources whose semantic arms are not real forks because every arm resolves to the same tail and target entry.",
        "Prefer pred-split on the shared tail instead of treating the source as a fork or missing-return hammock.",
    ),
    examples=(
        "Collapse the duplicate-arm `blk[28]` family to one canonical tail/entry and rewrite the shared tail corridor.",
        "Handle `blk[98]`, `blk[136]`, and `blk[181]` as alias-equivalent conditional sites rather than fork candidates.",
    ),
    tags=("exact-node", "conditional", "alias", "duplicate-arm", "pred-split"),
    related_paths=(
        "src/d810/cfg/flow/conditional_alias.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_alias.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_fork.py",
    ),
)
class ExactConditionalAliasNodeLoweringStrategy:
    lowering_mode = LoweringMode.DIRECT_GRAPH
    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "exact_conditional_alias_lowering"

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
        assert flow_graph is not None

        sites, inventory = analyze_exact_conditional_alias_sites(round_summary, flow_graph)
        if not sites:
            logger.info("EXACT CONDITIONAL ALIAS: no alias sites found")
            return None

        bst_blocks = {
            int(block)
            for block in getattr(snapshot.bst_result, "bst_node_blocks", set()) or set()
        }
        dispatcher_serial = int(snapshot.bst_dispatcher_serial)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        accepted_blocks: list[int] = []
        emission_modes: list[str] = []

        for site in sites:
            tail_snapshot = flow_graph.get_block(int(site.common_tail))
            if tail_snapshot is None or int(getattr(tail_snapshot, "nsucc", 0)) != 1:
                continue
            tail_preds = tuple(int(pred) for pred in getattr(tail_snapshot, "preds", ()))
            old_target = int(getattr(tail_snapshot, "succs", (0,))[0])
            if old_target == int(site.canonical_target_entry):
                continue

            ordered_path = tuple(
                int(node) for node in getattr(site.representative_edge, "ordered_path", ()) or ()
            )
            site_blocks = set(ordered_path)
            site_blocks.update({int(site.source_block), int(site.common_tail)})
            site_edges = set(zip(ordered_path, ordered_path[1:]))
            site_edges.add((int(site.common_tail), int(site.canonical_target_entry)))

            emission_mode = "alias_tail_redirect"
            if len(tail_preds) > 1 and int(site.source_block) in tail_preds:
                can_pred_split = not pred_split_target_reaches_via_pred(
                    flow_graph,
                    target_entry=int(site.canonical_target_entry),
                    via_pred=int(site.source_block),
                    source_block=int(site.common_tail),
                    ignored_blocks=bst_blocks | {dispatcher_serial},
                )
                if can_pred_split:
                    modifications.append(
                        setup.builder.edge_redirect(
                            int(site.common_tail),
                            int(site.canonical_target_entry),
                            via_pred=int(site.source_block),
                            rule_priority=645,
                        )
                    )
                    emission_mode = "alias_tail_pred_split"
                else:
                    logger.info(
                        "EXACT CONDITIONAL ALIAS: abstaining from alias tail clone "
                        "without corridor/replay proof source blk=%d common_tail=%d target=%d",
                        site.source_block,
                        site.common_tail,
                        site.canonical_target_entry,
                    )
                    continue
            else:
                modifications.append(
                    setup.builder.edge_redirect(
                        int(site.common_tail),
                        int(site.canonical_target_entry),
                        old_target=int(old_target),
                    )
                )

            owned_blocks.update(site_blocks)
            owned_edges.update(site_edges)
            owned_transitions.add(
                (
                    int(site.source_state) & 0xFFFFFFFF,
                    int(site.canonical_target_state) & 0xFFFFFFFF,
                )
            )
            accepted_blocks.append(int(site.source_block))
            emission_modes.append(emission_mode)
            logger.info(
                "EXACT CONDITIONAL ALIAS: source blk=%d alias_count=%d common_tail=%d target=%d mode=%s first_hop=%s",
                site.source_block,
                site.alias_count,
                site.common_tail,
                site.canonical_target_entry,
                emission_mode,
                "None" if site.first_hop is None else str(site.first_hop),
            )

        if not modifications:
            return None

        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            reachable_from_serial=getattr(flow_graph, "entry_serial", None),
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
                handlers_resolved=len(accepted_blocks),
                transitions_resolved=len(accepted_blocks),
                blocks_freed=0,
                conflict_density=0.2,
            ),
            risk_score=0.25,
            metadata={
                "accepted_blocks": tuple(accepted_blocks),
                "alias_blocks": inventory.alias_blocks,
                "safeguard_min_required": max(1, len(modifications)),
                "allow_post_apply_bst_cleanup": False,
                "post_apply_bst_cleanup_group": "exact_nodes",
                "post_apply_bst_cleanup_reason": "exact_conditional_alias_lowering",
                "residual_dispatcher_preds": tuple(int(serial) for serial in residual_dispatcher_preds),
                "emission_modes": tuple(emission_modes),
            },
        )
