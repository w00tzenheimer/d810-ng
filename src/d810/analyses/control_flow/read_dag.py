"""Portable read-off of a ``LinearizedStateDag`` from the dispatcher + owner fixpoints.

``read_dag_from`` projects one canonical :class:`StateDagNode` per handler as a
READ-OFF of two fixpoints -- the dispatcher discovery (:class:`DispatcherView`:
key/kind) x the block-ownership fixpoint (owned/exclusive/shared_suffix) --
reusing the canonical ``StateDagNode`` / ``StateDagNodeKey`` / ``StateNodeKind`` /
``LinearizedStateDag`` types.

It is the portable replacement for the live
``build_live_linearized_state_dag_from_graph`` node construction: the
anchor/corridor/supplemental heuristics collapse to lattice read-offs.  Local
segment/edge structure (``StateLocalSegment`` / ``StateLocalEdge``) and the outer
transition edges (``StateDagEdge``) land in follow-up increments; this increment
is the node projection.
"""
from __future__ import annotations

from d810.analyses.control_flow.block_ownership_domain import (
    block_owners,
    exclusive_blocks,
    owned_blocks,
    shared_suffix_blocks,
)
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import DispatcherView
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagNode,
    StateNodeKind,
)
from d810.analyses.data_flow import FixpointResult
from d810.ir.state_dag_key import StateDagNodeKey

__all__ = ["read_dag_from"]


def _state_label(
    kind: StateNodeKind, state_const: int | None, lo: int | None, hi: int | None
) -> str:
    if kind is StateNodeKind.RANGE_BACKED:
        return f"range_{int(lo):#010x}_{int(hi):#010x}"
    return f"state_{int(state_const):#010x}"


def read_dag_from(
    *,
    view: DispatcherView,
    owner_result: FixpointResult,
    dispatcher_entry_serial: int | None = None,
    state_var_stkoff: int | None = None,
    pre_header_serial: int | None = None,
    initial_state: int | None = None,
) -> LinearizedStateDag:
    """Project a :class:`LinearizedStateDag` of nodes off the two fixpoints.

    One node per distinct handler block in ``view.handler_entry_by_state`` (the
    exact handlers plus the P1-promoted genuine range handlers; shadows are
    already excluded by the discovery).  ``kind`` / ``key`` come from the
    discovery (``handler_range_map`` -> ``RANGE_BACKED``, else ``EXACT``); the
    ownership fields are the owner-set read-off.
    """
    owners = block_owners(owner_result)
    range_map = {int(b): (int(lo), int(hi)) for b, (lo, hi) in view.handler_range_map.items()}

    # Invert state -> handler to one node per handler (lowest mapped state wins).
    handler_to_state: dict[int, int] = {}
    for state_const, handler in view.handler_entry_by_state.items():
        handler, state_const = int(handler), int(state_const)
        if handler not in handler_to_state or state_const < handler_to_state[handler]:
            handler_to_state[handler] = state_const

    nodes: list[StateDagNode] = []
    for handler in sorted(handler_to_state):
        state_const = handler_to_state[handler]
        if handler in range_map:
            lo, hi = range_map[handler]
            kind = StateNodeKind.RANGE_BACKED
            key = StateDagNodeKey(handler_serial=handler, range_lo=lo, range_hi=hi)
            label = _state_label(kind, None, lo, hi)
        else:
            kind = StateNodeKind.EXACT
            key = StateDagNodeKey(handler_serial=handler, state_const=state_const)
            label = _state_label(kind, state_const, None, None)
        nodes.append(
            StateDagNode(
                key=key,
                kind=kind,
                state_label=label,
                handler_serial=handler,
                entry_anchor=handler,
                owned_blocks=tuple(owned_blocks(owners, handler)),
                exclusive_blocks=tuple(exclusive_blocks(owners, handler)),
                shared_suffix_blocks=tuple(shared_suffix_blocks(owners, handler)),
                local_segments=(),
                local_edges=(),
            )
        )

    entry = (
        dispatcher_entry_serial
        if dispatcher_entry_serial is not None
        else view.dispatcher_entry
    )
    return LinearizedStateDag(
        dispatcher_entry_serial=int(entry) if entry is not None else -1,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        bst_node_blocks=tuple(sorted(int(b) for b in view.bst_node_blocks)),
        nodes=tuple(nodes),
        edges=(),
    )
