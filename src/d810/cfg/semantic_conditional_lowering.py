"""Backend-neutral exact conditional site analysis.

This module classifies conditional semantic-DAG sites that are safe to lower as
small SESE-style hammocks.  It deliberately accepts DAG-like objects from the
caller instead of importing recon models, and it does not touch live Hex-Rays
objects.  Hodur remains responsible for strategy ordering, logging policy, and
materializing any returned sites into backend-specific modifications.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.cfg.flow.conditional_alias import analyze_duplicate_alias_conditional_sites
from d810.cfg.flow.sese_hammock import (
    ExactConditionalNodeShape,
    classify_exact_conditional_shape,
    conditional_distance_to_return,
    compute_postdominator_tree,
)

logger = logging.getLogger("D810.cfg.semantic_conditional_lowering", logging.DEBUG)

__all__ = [
    "ConditionalExactNodeSite",
    "ExactConditionalNodeShape",
    "ExactConditionalSiteInventory",
    "analyze_exact_conditional_sites",
    "collect_conditional_node_scope",
    "collect_exact_conditional_sites",
    "edge_kind_name",
    "site_key",
]


def edge_kind_name(edge: object) -> str:
    kind = getattr(getattr(edge, "kind", None), "name", None)
    return str(kind) if kind is not None else ""


def site_key(edge: object) -> tuple[int, int] | None:
    source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
    source_block = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    if source_state is None or source_block is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(source_block),
    )


def collect_conditional_node_scope(
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
        sibling_key = site_key(sibling)
        if sibling_key != (source_state, source_block):
            continue
        if edge_kind_name(sibling) not in {"CONDITIONAL_TRANSITION", "CONDITIONAL_RETURN"}:
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
class ExactConditionalSiteInventory:
    """Diagnostic inventory of conditional exact-node physical sites."""

    selected_count: int
    multi_transition_blocks: tuple[tuple[int, int, int], ...]
    missing_return_blocks: tuple[int, ...]
    shape_rejected_blocks: tuple[int, ...]
    alias_handled_blocks: tuple[int, ...] = ()


def _describe_sibling_transitions(transition_edges: list[object]) -> list[tuple[int, int | None, int | None, object]]:
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
    return sibling_transitions


def _record_multi_transition_block(
    *,
    source_block: int,
    transition_count: int,
    return_count: int,
    transition_edges: list[object],
    flow_graph: object,
) -> tuple[int, int, int]:
    source_snapshot = flow_graph.get_block(source_block)
    logger.info(
        "EXACT CONDITIONAL NODE: source blk=%d multi-transition transition_count=%d returns=%d succs=%s sibling_transitions=%s",
        source_block,
        transition_count,
        return_count,
        (
            tuple(int(s) for s in getattr(source_snapshot, "succs", ()))
            if source_snapshot is not None
            else ()
        ),
        _describe_sibling_transitions(transition_edges),
    )
    return (
        source_block,
        transition_count,
        return_count,
    )


def analyze_exact_conditional_sites(
    round_summary: object,
    flow_graph: object,
) -> tuple[tuple[ConditionalExactNodeSite, ...], ExactConditionalSiteInventory]:
    """Collect shape-safe exact conditional sites from a round summary.

    A site is eligible when one source block owns exactly one
    ``CONDITIONAL_TRANSITION`` and one ``CONDITIONAL_RETURN``.  That matches the
    predicate-aware hammock lowering shape: one taken semantic successor and one
    untaken terminal/return arm.
    """
    dag = round_summary.dag
    postdom_tree = compute_postdominator_tree(flow_graph)
    return_distance = conditional_distance_to_return(flow_graph)
    alias_handled_blocks = {
        int(site.source_block)
        for site in analyze_duplicate_alias_conditional_sites(round_summary, flow_graph)
    }
    edges_by_site: dict[tuple[int, int], list[object]] = {}
    transitions_by_source_block: dict[int, set[tuple[int, int]]] = {}
    returns_by_source_block: dict[int, list[object]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        key = site_key(edge)
        if key is None:
            continue
        kind_name = edge_kind_name(edge)
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
        if edge is None or edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            continue
        key = site_key(edge)
        if key is None:
            continue
        source_state, source_block = key
        siblings = edges_by_site.get(key, [])
        transition_edges = [
            sibling for sibling in siblings if edge_kind_name(sibling) == "CONDITIONAL_TRANSITION"
        ]
        return_edges = [
            sibling for sibling in siblings if edge_kind_name(sibling) == "CONDITIONAL_RETURN"
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
                multi_transition_blocks[source_block] = _record_multi_transition_block(
                    source_block=source_block,
                    transition_count=transition_count,
                    return_count=len(returns_by_source_block.get(source_block, [])),
                    transition_edges=transition_edges,
                    flow_graph=flow_graph,
                )
            continue
        if transition_count != 1:
            multi_transition_blocks[source_block] = _record_multi_transition_block(
                source_block=source_block,
                transition_count=transition_count,
                return_count=len(returns_by_source_block.get(source_block, [])),
                transition_edges=transition_edges,
                flow_graph=flow_graph,
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
        shape = classify_exact_conditional_shape(
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


def collect_exact_conditional_sites(
    round_summary: object,
    flow_graph: object,
) -> tuple[ConditionalExactNodeSite, ...]:
    sites, _inventory = analyze_exact_conditional_sites(round_summary, flow_graph)
    return sites
