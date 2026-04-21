"""Duplicate-arm conditional alias detection for exact-node lowering."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AliasConditionalSite",
    "analyze_duplicate_alias_conditional_sites",
]


def _edge_kind_name(edge: object) -> str:
    kind = getattr(getattr(edge, "kind", None), "name", None)
    return str(kind) if kind is not None else ""


def _site_key(edge: object) -> tuple[int, int] | None:
    source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
    source_block = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    if source_state is None or source_block is None:
        return None
    return (int(source_state) & 0xFFFFFFFF, int(source_block))


def _path_first_hop_after_source(
    ordered_path: tuple[int, ...],
    source_block: int,
) -> int | None:
    if not ordered_path:
        return None
    try:
        source_index = ordered_path.index(int(source_block))
    except ValueError:
        return int(ordered_path[0])
    if source_index + 1 >= len(ordered_path):
        return None
    return int(ordered_path[source_index + 1])


@dataclass(frozen=True, slots=True)
class AliasConditionalSite:
    source_state: int
    source_block: int
    canonical_target_state: int
    canonical_target_entry: int
    common_tail: int
    first_hop: int | None
    representative_edge: object
    alias_count: int


def analyze_duplicate_alias_conditional_sites(
    round_summary,
    flow_graph,
) -> tuple[AliasConditionalSite, ...]:
    """Return duplicate-arm conditional sources whose semantic arms collapse.

    These are exact-node sources with multiple ``CONDITIONAL_TRANSITION`` edges
    and no sibling ``CONDITIONAL_RETURN`` where every semantic arm resolves to
    the same physical tail and target entry. They are not real forks and should
    be handled by alias-aware lowering instead of fork or hammock paths.
    """

    dag = round_summary.dag
    edges_by_source: dict[int, list[object]] = {}
    has_return_by_source: set[int] = set()
    for edge in getattr(dag, "edges", ()) or ():
        key = _site_key(edge)
        if key is None:
            continue
        _source_state, source_block = key
        kind_name = _edge_kind_name(edge)
        if kind_name == "CONDITIONAL_TRANSITION":
            edges_by_source.setdefault(int(source_block), []).append(edge)
        elif kind_name == "CONDITIONAL_RETURN":
            has_return_by_source.add(int(source_block))

    selected: list[AliasConditionalSite] = []
    for source_block, edges in sorted(edges_by_source.items()):
        if source_block in has_return_by_source or len(edges) < 2:
            continue
        source_snapshot = flow_graph.get_block(int(source_block))
        if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 2:
            continue

        canonical_pairs: set[tuple[int, int]] = set()
        source_states: set[int] = set()
        target_states: set[int] = set()
        representative_edge = None
        first_hop = None
        for edge in edges:
            key = _site_key(edge)
            if key is not None:
                source_states.add(int(key[0]) & 0xFFFFFFFF)
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            target_entry_anchor = getattr(edge, "target_entry_anchor", None)
            if not ordered_path or target_entry_anchor is None:
                representative_edge = None
                break
            representative_edge = edge
            first_hop = _path_first_hop_after_source(ordered_path, int(source_block))
            canonical_pairs.add((int(ordered_path[-1]), int(target_entry_anchor)))
            target_states.add(int(getattr(edge, "target_state", 0)) & 0xFFFFFFFF)
        if representative_edge is None or len(canonical_pairs) != 1:
            continue
        common_tail, canonical_target_entry = next(iter(canonical_pairs))
        source_state = (
            next(iter(source_states))
            if len(source_states) == 1
            else int(getattr(getattr(representative_edge, "source_key", None), "state_const", 0))
            & 0xFFFFFFFF
        )
        canonical_target_state = (
            next(iter(target_states))
            if len(target_states) == 1
            else int(getattr(representative_edge, "target_state", 0)) & 0xFFFFFFFF
        )
        selected.append(
            AliasConditionalSite(
                source_state=int(source_state) & 0xFFFFFFFF,
                source_block=int(source_block),
                canonical_target_state=canonical_target_state,
                canonical_target_entry=int(canonical_target_entry),
                common_tail=int(common_tail),
                first_hop=first_hop,
                representative_edge=representative_edge,
                alias_count=len(edges),
            )
        )
    return tuple(selected)
