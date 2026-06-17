"""Query helpers for semantic state-DAG edges.

The index is intentionally DAG-native: callers ask for proven semantic edges by
node key, entry anchor, or source anchor.  The proof producer may be a dispatcher
map, range row, legacy emulation, or another recon source, but lowering code does
not consume producer-specific candidate types.
"""

from __future__ import annotations

from dataclasses import dataclass


def _u64_or_none(value: object | None) -> int | None:
    if value is None:
        return None
    return int(value) & 0xFFFFFFFFFFFFFFFF


def _node_identity(
    key: object | None,
) -> tuple[int | None, int | None, int | None, int | None] | None:
    if key is None:
        return None
    handler_serial = getattr(key, "handler_serial", None)
    state_const = _u64_or_none(getattr(key, "state_const", None))
    range_lo = _u64_or_none(getattr(key, "range_lo", None))
    range_hi = _u64_or_none(getattr(key, "range_hi", None))
    if (
        handler_serial is None
        and state_const is None
        and range_lo is None
        and range_hi is None
    ):
        return None
    return (
        None if handler_serial is None else int(handler_serial),
        state_const,
        range_lo,
        range_hi,
    )


@dataclass(frozen=True, slots=True)
class DagParentEdge:
    """One incoming semantic edge with its operational redirect evidence."""

    edge: object
    parent_key: object | None
    child_key: object | None
    source_block: int
    branch_arm: int | None
    source_state: int | None
    target_state: int | None
    target_entry_anchor: int | None
    ordered_path: tuple[int, ...]
    last_write_site: tuple[int, int] | None
    semantic_kind: str
    proof_source: str
    proof_kind: str


class StateDagIndex:
    """Read-only index over a linearized state-DAG snapshot."""

    def __init__(self, edges: tuple[DagParentEdge, ...]) -> None:
        self._edges = edges
        self._by_anchor: dict[tuple[int, int | None], list[DagParentEdge]] = {}
        self._by_child_key: dict[
            tuple[int | None, int | None, int | None, int | None],
            list[DagParentEdge],
        ] = {}
        self._by_target_state: dict[int, list[DagParentEdge]] = {}
        self._by_target_entry: dict[int, list[DagParentEdge]] = {}
        for edge in edges:
            self._by_anchor.setdefault((edge.source_block, edge.branch_arm), []).append(edge)
            child_identity = _node_identity(edge.child_key)
            if child_identity is not None:
                self._by_child_key.setdefault(child_identity, []).append(edge)
            if edge.target_state is not None:
                self._by_target_state.setdefault(edge.target_state, []).append(edge)
            if edge.target_entry_anchor is not None:
                self._by_target_entry.setdefault(edge.target_entry_anchor, []).append(edge)

    @classmethod
    def from_dag(cls, dag: object | None) -> "StateDagIndex":
        indexed: list[DagParentEdge] = []
        for edge in tuple(getattr(dag, "edges", ()) or ()):
            source_anchor = getattr(edge, "source_anchor", None)
            source_block = getattr(source_anchor, "block_serial", None)
            if source_block is None:
                continue
            source_key = getattr(edge, "source_key", None)
            target_key = getattr(edge, "target_key", None)
            kind = getattr(edge, "kind", None)
            kind_name = str(getattr(kind, "name", kind))
            raw_proof_source = getattr(edge, "proof_source", None)
            proof_source = (
                kind_name
                if raw_proof_source is None
                else str(getattr(raw_proof_source, "name", raw_proof_source))
            )
            raw_last_write_site = getattr(edge, "last_write_site", None)
            last_write_site = (
                None
                if raw_last_write_site is None
                else (int(raw_last_write_site[0]), int(raw_last_write_site[1]))
            )
            indexed.append(
                DagParentEdge(
                    edge=edge,
                    parent_key=source_key,
                    child_key=target_key,
                    source_block=int(source_block),
                    branch_arm=getattr(source_anchor, "branch_arm", None),
                    source_state=_u64_or_none(getattr(source_key, "state_const", None)),
                    target_state=_u64_or_none(
                        getattr(edge, "target_state", None)
                        if getattr(edge, "target_state", None) is not None
                        else getattr(target_key, "state_const", None)
                    ),
                    target_entry_anchor=(
                        None
                        if getattr(edge, "target_entry_anchor", None) is None
                        else int(getattr(edge, "target_entry_anchor"))
                    ),
                    ordered_path=tuple(
                        int(block) for block in (getattr(edge, "ordered_path", ()) or ())
                    ),
                    last_write_site=last_write_site,
                    semantic_kind=kind_name,
                    proof_source=proof_source,
                    proof_kind=kind_name,
                )
            )
        return cls(tuple(indexed))

    @property
    def edges(self) -> tuple[DagParentEdge, ...]:
        return self._edges

    def parents_of(self, node_key: object) -> tuple[DagParentEdge, ...]:
        child_identity = _node_identity(node_key)
        if child_identity is None:
            return ()
        return tuple(self._by_child_key.get(child_identity, ()))

    def incoming_for_state(self, state_const: int) -> tuple[DagParentEdge, ...]:
        state_const = _u64_or_none(state_const)
        if state_const is None:
            return ()
        return tuple(self._by_target_state.get(state_const, ()))

    def incoming_to_entry(self, entry_anchor: int) -> tuple[DagParentEdge, ...]:
        return tuple(self._by_target_entry.get(int(entry_anchor), ()))

    def edge_from_anchor(
        self,
        block_serial: int,
        branch_arm: int | None,
    ) -> DagParentEdge | None:
        matches = self._by_anchor.get((int(block_serial), branch_arm), ())
        if len(matches) != 1:
            return None
        return matches[0]

    def edges_from_anchor(
        self,
        block_serial: int,
        branch_arm: int | None = None,
    ) -> tuple[DagParentEdge, ...]:
        if branch_arm is not None:
            return tuple(self._by_anchor.get((int(block_serial), branch_arm), ()))
        matches: list[DagParentEdge] = []
        for (source_block, _arm), edges in self._by_anchor.items():
            if source_block == int(block_serial):
                matches.extend(edges)
        return tuple(matches)


__all__ = [
    "DagParentEdge",
    "StateDagIndex",
]
