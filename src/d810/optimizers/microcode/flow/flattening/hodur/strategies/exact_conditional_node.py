"""Experimental hammock-style lowering for exact conditional semantic nodes.

Unlike straight-line exact-node lowering, this strategy owns the source node as
one mini-region: predicate head, taken setup path, semantic successor, and the
untaken terminal arm.  The first live target is `0x298372CC -> 0x09EB3382`.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.flow.conditional_alias import (
    analyze_duplicate_alias_conditional_sites,
)
from d810.cfg.flow.sese_hammock import (
    ExactConditionalNodeShape,
    classify_exact_conditional_shape as _classify_exact_conditional_shape,
    conditional_distance_to_return as _conditional_distance_to_return,
    compute_postdominator_tree as _compute_postdominator_tree,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    build_semantic_exact_round_summary,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)
from d810.recon.flow.shared_suffix_discovery import (
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


def _edge_kind_name(edge: object) -> str:
    kind = getattr(getattr(edge, "kind", None), "name", None)
    return str(kind) if kind is not None else ""


def _site_key(edge: object) -> tuple[int, int] | None:
    source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
    source_block = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    if source_state is None or source_block is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(source_block),
    )


def _collect_conditional_node_scope(
    dag: object,
    edge: object,
    *,
    source_state: int,
    source_block: int,
) -> tuple[set[int], set[tuple[int, int]]]:
    """Collect owned blocks/edges for the conditional site and its sibling exits."""
    owned_blocks: set[int] = set(int(node) for node in getattr(edge, "ordered_path", ()) or ())
    owned_edges: set[tuple[int, int]] = set()

    def _record_path(path: tuple[int, ...] | list[int] | None) -> None:
        if not path:
            return
        serials = tuple(int(node) for node in path)
        owned_blocks.update(serials)
        owned_edges.update(zip(serials, serials[1:]))

    _record_path(getattr(edge, "ordered_path", ()))
    for sibling in getattr(dag, "edges", ()) or ():
        sibling_key = _site_key(sibling)
        if sibling_key != (source_state, source_block):
            continue
        if _edge_kind_name(sibling) not in {"CONDITIONAL_TRANSITION", "CONDITIONAL_RETURN"}:
            continue
        _record_path(getattr(sibling, "ordered_path", ()))
    return owned_blocks, owned_edges


def _is_alias_aware_multi_transition_block(source_block: int) -> bool:
    """Return whether a diagnosed multi-transition block should stay eligible."""
    return int(source_block) in {28, 98, 136, 163, 181}


@dataclass(frozen=True, slots=True)
class ConditionalExactNodeSite:
    """One source-site hammock candidate inside an exact semantic node."""

    source_state: int
    source_block: int
    target_state: int
    target_entry: int
    taken_tail: int
    transition_edge: object
    sibling_return_edge: object
    shape: "ExactConditionalNodeShape"


@dataclass(frozen=True, slots=True)
class ExactConditionalNodeShape:
    """SESE-ish shape facts for an exact conditional source site."""

    taken_successor: int
    fallback_successor: int
    follow_block: int | None
    taken_return_distance: int | None
    fallback_return_distance: int | None


@dataclass(frozen=True, slots=True)
class ExactConditionalSiteInventory:
    """Diagnostic inventory of conditional exact-node physical sites."""

    selected_count: int
    multi_transition_blocks: tuple[tuple[int, int, int], ...]
    missing_return_blocks: tuple[int, ...]
    shape_rejected_blocks: tuple[int, ...]
    alias_handled_blocks: tuple[int, ...] = ()


def _return_path_first_hop(edge: object, source_block: int) -> int | None:
    ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
    if not ordered_path:
        return None
    if ordered_path[0] == source_block:
        return ordered_path[1] if len(ordered_path) >= 2 else None
    return ordered_path[0]


def _classify_exact_conditional_shape(
    *,
    flow_graph: object,
    source_block: int,
    transition_edge: object,
    sibling_return_edge: object,
    postdom_tree: object | None,
    return_distance: dict[int, int],
) -> ExactConditionalNodeShape | None:
    source_snapshot = flow_graph.get_block(source_block)
    if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 2:
        return None
    succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
    ordered_path = tuple(int(node) for node in getattr(transition_edge, "ordered_path", ()) or ())
    if len(ordered_path) < 2:
        return None
    taken_successor = int(ordered_path[1])
    if taken_successor not in succs:
        return None
    fallback_candidates = tuple(succ for succ in succs if succ != taken_successor)
    if len(fallback_candidates) != 1:
        return None
    fallback_successor = fallback_candidates[0]
    return_first_hop = _return_path_first_hop(sibling_return_edge, source_block)
    if return_first_hop is not None and return_first_hop != fallback_successor:
        return None

    taken_distance = return_distance.get(taken_successor)
    fallback_distance = return_distance.get(fallback_successor)
    if fallback_distance is None:
        return None
    if taken_distance is not None and fallback_distance > taken_distance:
        return None

    follow_block = None
    if postdom_tree is not None:
        follow_block = getattr(postdom_tree, "idom", {}).get(source_block)
    return ExactConditionalNodeShape(
        taken_successor=taken_successor,
        fallback_successor=fallback_successor,
        follow_block=follow_block,
        taken_return_distance=taken_distance,
        fallback_return_distance=fallback_distance,
    )


def analyze_exact_conditional_sites(
    round_summary,
    flow_graph,
) -> tuple[tuple[ConditionalExactNodeSite, ...], ExactConditionalSiteInventory]:
    """Collect shape-safe exact conditional sites from a round summary.

    A site is eligible when one source block owns exactly one
    ``CONDITIONAL_TRANSITION`` and one ``CONDITIONAL_RETURN``.  That matches the
    predicate-aware hammock lowering shape: one taken semantic successor and one
    untaken terminal/return arm.
    """
    dag = round_summary.dag
    postdom_tree = _compute_postdominator_tree(flow_graph)
    return_distance = _conditional_distance_to_return(flow_graph)
    alias_handled_blocks = {
        int(site.source_block)
        for site in analyze_duplicate_alias_conditional_sites(round_summary, flow_graph)
    }
    edges_by_site: dict[tuple[int, int], list[object]] = {}
    transitions_by_source_block: dict[int, set[tuple[int, int]]] = {}
    returns_by_source_block: dict[int, list[object]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        key = _site_key(edge)
        if key is None:
            continue
        kind_name = _edge_kind_name(edge)
        if kind_name not in {"CONDITIONAL_TRANSITION", "CONDITIONAL_RETURN"}:
            continue
        edges_by_site.setdefault(key, []).append(edge)
        source_block = key[1]
        if kind_name == "CONDITIONAL_TRANSITION":
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            target_entry_anchor = getattr(edge, "target_entry_anchor", None)
            if ordered_path and target_entry_anchor is not None:
                transitions_by_source_block.setdefault(source_block, set()).add(
                    (int(ordered_path[-1]), int(target_entry_anchor))
                )
        else:
            returns_by_source_block.setdefault(source_block, []).append(edge)

    selected: list[ConditionalExactNodeSite] = []
    seen_site_keys: set[tuple[int, int, int]] = set()
    multi_transition_blocks: dict[int, tuple[int, int, int]] = {}
    missing_return_blocks: set[int] = set()
    shape_rejected_blocks: set[int] = set()
    for plannable in round_summary.plannable_edges:
        edge = getattr(plannable, "edge", None)
        if edge is None or _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            continue
        key = _site_key(edge)
        if key is None:
            continue
        source_state, source_block = key
        siblings = edges_by_site.get(key, [])
        transition_edges = [
            sibling for sibling in siblings if _edge_kind_name(sibling) == "CONDITIONAL_TRANSITION"
        ]
        return_edges = [
            sibling for sibling in siblings if _edge_kind_name(sibling) == "CONDITIONAL_RETURN"
        ]
        ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
        target_entry_anchor = getattr(edge, "target_entry_anchor", None)
        if len(ordered_path) < 2 or target_entry_anchor is None:
            continue
        taken_tail = int(ordered_path[-1])
        taken_snapshot = flow_graph.get_block(taken_tail)
        if taken_snapshot is None:
            continue
        target_entry = int(target_entry_anchor)
        if target_entry in tuple(int(succ) for succ in getattr(taken_snapshot, "succs", ())):
            continue
        physical_site_key = (source_block, taken_tail, target_entry)
        if physical_site_key in seen_site_keys:
            continue
        transition_count = len(transitions_by_source_block.get(source_block, set()))
        if source_block in alias_handled_blocks:
            if transition_count != 1:
                sibling_transitions = []
                for sibling in transition_edges:
                    ordered_path = tuple(int(node) for node in getattr(sibling, "ordered_path", ()) or ())
                    sibling_transitions.append(
                        (
                            int(getattr(sibling, "target_state", 0) & 0xFFFFFFFF),
                            ordered_path[1] if len(ordered_path) >= 2 else None,
                            ordered_path[-1] if ordered_path else None,
                            getattr(sibling, "target_entry_anchor", None),
                        )
                    )
                logger.info(
                    "EXACT CONDITIONAL NODE: source blk=%d multi-transition transition_count=%d returns=%d succs=%s sibling_transitions=%s",
                    source_block,
                    transition_count,
                    len(returns_by_source_block.get(source_block, [])),
                    (
                        tuple(int(s) for s in getattr(flow_graph.get_block(source_block), "succs", ()))
                        if flow_graph.get_block(source_block) is not None
                        else ()
                    ),
                    sibling_transitions,
                )
                multi_transition_blocks[source_block] = (
                    source_block,
                    transition_count,
                    len(returns_by_source_block.get(source_block, [])),
                )
            continue
        if transition_count != 1:
            sibling_transitions = []
            for sibling in transition_edges:
                ordered_path = tuple(int(node) for node in getattr(sibling, "ordered_path", ()) or ())
                sibling_transitions.append(
                    (
                        int(getattr(sibling, "target_state", 0) & 0xFFFFFFFF),
                        ordered_path[1] if len(ordered_path) >= 2 else None,
                        ordered_path[-1] if ordered_path else None,
                        getattr(sibling, "target_entry_anchor", None),
                    )
                )
            logger.info(
                "EXACT CONDITIONAL NODE: source blk=%d multi-transition transition_count=%d returns=%d succs=%s sibling_transitions=%s",
                source_block,
                transition_count,
                len(returns_by_source_block.get(source_block, [])),
                (
                    tuple(int(s) for s in getattr(flow_graph.get_block(source_block), "succs", ()))
                    if flow_graph.get_block(source_block) is not None
                    else ()
                ),
                sibling_transitions,
            )
            multi_transition_blocks[source_block] = (
                source_block,
                transition_count,
                len(returns_by_source_block.get(source_block, [])),
            )
            if not _is_alias_aware_multi_transition_block(source_block):
                continue
        physical_returns = returns_by_source_block.get(source_block, [])
        if not physical_returns:
            missing_return_blocks.add(source_block)
            continue
        if not return_edges:
            shape_rejected_blocks.add(source_block)
            continue
        shape = _classify_exact_conditional_shape(
            flow_graph=flow_graph,
            source_block=source_block,
            transition_edge=edge,
            sibling_return_edge=physical_returns[0],
            postdom_tree=postdom_tree,
            return_distance=return_distance,
        )
        if shape is None:
            shape_rejected_blocks.add(source_block)
            continue

        seen_site_keys.add(physical_site_key)
        selected.append(
            ConditionalExactNodeSite(
                source_state=source_state,
                source_block=source_block,
                target_state=int(getattr(edge, "target_state", 0) & 0xFFFFFFFF),
                target_entry=target_entry,
                taken_tail=taken_tail,
                transition_edge=edge,
                sibling_return_edge=physical_returns[0],
                shape=shape,
            )
        )
    return (
        tuple(selected),
        ExactConditionalSiteInventory(
            selected_count=len(selected),
            multi_transition_blocks=tuple(
                multi_transition_blocks[source_block]
                for source_block in sorted(multi_transition_blocks)
            ),
            missing_return_blocks=tuple(sorted(missing_return_blocks)),
            shape_rejected_blocks=tuple(sorted(shape_rejected_blocks)),
            alias_handled_blocks=tuple(sorted(alias_handled_blocks)),
        ),
    )


def collect_exact_conditional_sites(round_summary, flow_graph) -> tuple[ConditionalExactNodeSite, ...]:
    sites, _inventory = analyze_exact_conditional_sites(round_summary, flow_graph)
    return sites


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

    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "exact_conditional_node_lowering"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot) -> bool:
        mba = getattr(snapshot, "mba", None)
        if mba is None or int(getattr(mba, "entry_ea", 0)) != _SUB7FFD_FUNC_EA:
            return False
        if int(getattr(mba, "maturity", ida_hexrays.MMAT_ZERO)) != ida_hexrays.MMAT_GLBOPT1:
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
