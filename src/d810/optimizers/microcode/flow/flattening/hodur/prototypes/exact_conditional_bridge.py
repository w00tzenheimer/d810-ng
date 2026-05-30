"""Prototype lowering for mixed-shape exact conditional bridge sites.

This experimental path isolates blk[163]-style sites where one conditional arm
is a pure bridge corridor and the other arm is a terminal/local arm. That is
not a two-way semantic fork, so the prototype keeps it out of the fork
strategy and reuses the bridge/direct/shared-group CFG helpers instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays

from d810.core import logging
from d810.transforms.lowering import LoweringMode
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.reconstruction_bridge_planning import (
    plan_reconstruction_bridge_modifications,
)
from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    _compute_postdominator_tree,
    _edge_kind_name,
    _site_key,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    build_semantic_exact_round_summary,
)

logger = logging.getLogger(
    "D810.hodur.strategy.exact_conditional_bridge",
    logging.DEBUG,
)

__all__ = [
    "ExactConditionalBridgeNodeLoweringStrategy",
    "ExactConditionalBridgeInventory",
    "MixedShapeBridgeSite",
    "analyze_exact_conditional_bridge_sites",
    "collect_exact_conditional_bridge_sites",
]


@dataclass(frozen=True, slots=True)
class MixedShapeBridgeSite:
    """One exact conditional source site with one bridge arm and one terminal arm."""

    source_state: int
    source_block: int
    bridge_tail: int
    exit_block: int
    target_entry: int
    terminal_tail: int | None
    follow_block: int | None
    transition_edge: object
    shared_candidates: tuple[SharedGroupEmissionCandidate, ...] = ()


@dataclass(frozen=True, slots=True)
class ExactConditionalBridgeInventory:
    """Diagnostics for the mixed-shape bridge selector."""

    selected_count: int
    candidate_blocks: tuple[int, ...]
    shape_rejected_blocks: tuple[int, ...]


def _source_block_succs(flow_graph: object, source_block: int) -> tuple[int, ...]:
    source_snapshot = flow_graph.get_block(source_block)
    if source_snapshot is None:
        return ()
    return tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))


def _ordered_path_bridge_tail(
    ordered_path: tuple[int, ...],
    source_block: int,
) -> int | None:
    try:
        source_index = ordered_path.index(source_block)
    except ValueError:
        return None
    if source_index + 1 >= len(ordered_path):
        return None
    return int(ordered_path[source_index + 1])


def _collect_bridge_scope(site: MixedShapeBridgeSite) -> tuple[set[int], set[tuple[int, int]]]:
    owned_blocks = {
        int(site.source_block),
        int(site.bridge_tail),
        int(site.exit_block),
    }
    if site.terminal_tail is not None:
        owned_blocks.add(int(site.terminal_tail))
    owned_edges = {
        (int(site.source_block), int(site.bridge_tail)),
        (int(site.bridge_tail), int(site.exit_block)),
    }
    if site.terminal_tail is not None:
        owned_edges.add((int(site.source_block), int(site.terminal_tail)))
    return owned_blocks, owned_edges


def analyze_exact_conditional_bridge_sites(
    round_summary,
    flow_graph,
) -> tuple[tuple[MixedShapeBridgeSite, ...], ExactConditionalBridgeInventory]:
    """Select exact conditional sites that are bridge-shaped rather than fork-shaped."""
    dag = round_summary.dag
    postdom_tree = _compute_postdominator_tree(flow_graph)
    transition_edges_by_source: dict[int, list[object]] = {}
    plannable_edges_by_source: dict[int, list[object]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        key = _site_key(edge)
        if key is None or _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            continue
        transition_edges_by_source.setdefault(key[1], []).append(edge)
    for plannable in round_summary.plannable_edges:
        edge = getattr(plannable, "edge", None)
        if edge is None or _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            continue
        key = _site_key(edge)
        if key is None:
            continue
        plannable_edges_by_source.setdefault(key[1], []).append(edge)

    candidate_blocks = tuple(sorted(transition_edges_by_source))
    selected: list[MixedShapeBridgeSite] = []
    shape_rejected_blocks: set[int] = set()
    for source_block, plannable_edges in sorted(plannable_edges_by_source.items()):
        if not plannable_edges:
            continue
        source_state = None

        source_snapshot = flow_graph.get_block(source_block)
        if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 2:
            shape_rejected_blocks.add(source_block)
            continue

        succs = _source_block_succs(flow_graph, source_block)
        selected_edge = None
        bridge_tail = None
        exit_block = None
        terminal_tail = None
        target_entry = None
        for edge in plannable_edges:
            key = _site_key(edge)
            if key is None:
                continue
            source_state = key[0]
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            candidate_bridge_tail = _ordered_path_bridge_tail(ordered_path, source_block)
            if candidate_bridge_tail is None:
                continue
            candidate_exit_block = int(ordered_path[-1])
            candidate_terminal_tail = next(
                (succ for succ in succs if succ != candidate_bridge_tail),
                None,
            )
            if candidate_terminal_tail is None:
                continue
            if candidate_exit_block in succs:
                continue
            selected_edge = edge
            bridge_tail = int(candidate_bridge_tail)
            exit_block = candidate_exit_block
            terminal_tail = int(candidate_terminal_tail)
            target_entry = int(getattr(edge, "target_entry_anchor", 0))
            break
        if (
            selected_edge is None
            or bridge_tail is None
            or exit_block is None
            or terminal_tail is None
            or target_entry is None
            or source_state is None
        ):
            shape_rejected_blocks.add(source_block)
            continue

        follow_block = None
        if postdom_tree is not None:
            follow_block = getattr(postdom_tree, "idom", {}).get(source_block)

        selected.append(
            MixedShapeBridgeSite(
                source_state=int(source_state) & 0xFFFFFFFF,
                source_block=source_block,
                bridge_tail=bridge_tail,
                exit_block=exit_block,
                target_entry=target_entry,
                terminal_tail=terminal_tail,
                follow_block=follow_block,
                transition_edge=selected_edge,
            )
        )

    return (
        tuple(selected),
        ExactConditionalBridgeInventory(
            selected_count=len(selected),
            candidate_blocks=candidate_blocks,
            shape_rejected_blocks=tuple(sorted(shape_rejected_blocks)),
        ),
    )


def collect_exact_conditional_bridge_sites(round_summary, flow_graph) -> tuple[MixedShapeBridgeSite, ...]:
    sites, _inventory = analyze_exact_conditional_bridge_sites(round_summary, flow_graph)
    return sites


@algorithm_metadata(
    algorithm_id="hodur.exact_conditional_bridge_lowering_prototype",
    family="semantic_exact_node_lowering",
    summary="Prototype bridge-only lowering for exact conditional sites with one bridge arm and one terminal arm.",
    use_cases=(
        "Keep blk[163]-style mixed bridge sites out of the two-way fork strategy.",
        "Reuse bridge, direct-source, and shared-group CFG helpers for the bridge arm when only one arm is semantic.",
    ),
    examples=(
        "Lower a conditional source whose bridge arm exits through a corridor and whose sibling arm terminates locally.",
        "Treat a source block with one bridge tail and one terminal tail as a bridge rewrite, not a fork rewrite.",
    ),
    tags=("exact-node", "bridge", "mixed-shape", "prototype", "predicate-aware"),
    related_paths=(
        "src/d810/cfg/reconstruction_bridge_planning.py",
        "src/d810/cfg/reconstruction_modification_planning.py",
        "src/d810/cfg/lowering_selector.py",
        "src/d810/cfg/reconstruction_lowering.py",
    ),
)
class ExactConditionalBridgeNodeLoweringStrategy:
    """Prototype strategy for mixed-shape exact conditional bridge sites."""

    lowering_mode = LoweringMode.DIRECT_GRAPH
    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "exact_conditional_bridge_lowering_prototype"

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
        assert flow_graph is not None

        sites, inventory = analyze_exact_conditional_bridge_sites(round_summary, flow_graph)
        if not sites:
            logger.info(
                "EXACT CONDITIONAL BRIDGE: no bridge sites found (candidates=%s rejected=%s)",
                inventory.candidate_blocks,
                inventory.shape_rejected_blocks,
            )
            return None

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        accepted_sites: list[tuple[int, int]] = []
        for site in sites:
            site_blocks, site_edges = _collect_bridge_scope(site)
            bridge_dag = SimpleNamespace(edges=(site.transition_edge,))
            bridge_plan = plan_reconstruction_bridge_modifications(
                dag=bridge_dag,
                flow_graph=flow_graph,
                builder=setup.builder,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                claimed_sources=set(),
                claimed_targets=set(),
                suppressed_bridge_pairs=set(),
            )
            if bridge_plan.modifications:
                modifications.extend(bridge_plan.modifications)
                accepted_sites.append((site.source_state, int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF))
                owned_blocks.update(site_blocks)
                owned_edges.update(site_edges)
                owned_transitions.add(
                    (
                        int(site.source_state) & 0xFFFFFFFF,
                        int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF,
                    )
                )
                logger.info(
                    "EXACT CONDITIONAL BRIDGE: source blk=%d bridge_tail=%d exit=%d target=%d terminal=%s follow=%s",
                    site.source_block,
                    site.bridge_tail,
                    site.exit_block,
                    site.target_entry,
                    site.terminal_tail,
                    site.follow_block,
                )
                continue

            direct_plan = plan_direct_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=site.exit_block,
                target_entry=site.target_entry,
                ordered_path=tuple(int(node) for node in getattr(site.transition_edge, "ordered_path", ()) or ()),
            )
            if direct_plan.accepted:
                modifications.extend(direct_plan.modifications)
                accepted_sites.append((site.source_state, int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF))
                owned_blocks.update(site_blocks)
                owned_edges.update(site_edges)
                owned_transitions.add(
                    (
                        int(site.source_state) & 0xFFFFFFFF,
                        int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF,
                    )
                )
                continue

            shared_plan = plan_shared_group_reconstruction_modifications(
                flow_graph=flow_graph,
                shared_block=site.source_block,
                ordered_path=tuple(int(node) for node in getattr(site.transition_edge, "ordered_path", ()) or ()),
                shared_candidates=site.shared_candidates,
            )
            if shared_plan.accepted:
                modifications.extend(shared_plan.modifications)
                accepted_sites.append((site.source_state, int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF))
                owned_blocks.update(site_blocks)
                owned_edges.update(site_edges)
                owned_transitions.add(
                    (
                        int(site.source_state) & 0xFFFFFFFF,
                        int(getattr(site.transition_edge, "target_state", 0)) & 0xFFFFFFFF,
                    )
                )

        if not modifications:
            return None

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
                handlers_resolved=len(accepted_sites),
                transitions_resolved=len(accepted_sites),
                blocks_freed=0,
                conflict_density=0.15,
            ),
            risk_score=0.25,
            metadata={
                "accepted_sites": tuple(accepted_sites),
                "selected_count": inventory.selected_count,
                "bridge_case": True,
                "safeguard_min_required": max(1, len(modifications)),
                "allow_post_apply_bst_cleanup": False,
                "post_apply_bst_cleanup_group": "exact_nodes",
            },
        )
