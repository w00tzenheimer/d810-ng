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
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.local_structure import build_local_structure
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.data_flow import FixpointResult
from d810.analyses.data_flow.domain import NodeId
from d810.core.typing import Callable, FrozenSet, Iterable
from d810.ir.state_dag_key import StateDagNodeKey

__all__ = ["read_dag_from"]

_Succ = Callable[[NodeId], Iterable[NodeId]]


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
    transitions: TransitionResult | None = None,
    successors_of: _Succ | None = None,
    predecessors_of: _Succ | None = None,
    terminal_exit_blocks: FrozenSet[int] = frozenset(),
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

    # state -> handler: the exact handlers, plus (when a transition result is given)
    # the full transition handler map -- so the read-off expands to one node per
    # ROUTED STATE (the legacy's state-level granularity) and the edges can cover
    # every transition, not just the exact-handler subset.
    state_to_handler: dict[int, int] = {
        int(s): int(h) for s, h in view.handler_entry_by_state.items()
    }
    if transitions is not None:
        for state, handler in transitions.handlers.items():
            check_block = getattr(handler, "check_block", None)
            if check_block is not None:
                state_to_handler.setdefault(int(state), int(check_block))

    nodes: list[StateDagNode] = []
    for state_const in sorted(state_to_handler):
        handler = state_to_handler[state_const]
        if handler in range_map:
            lo, hi = range_map[handler]
            kind = StateNodeKind.RANGE_BACKED
            key = StateDagNodeKey(
                handler_serial=handler, state_const=state_const, range_lo=lo, range_hi=hi
            )
            label = _state_label(kind, state_const, lo, hi)
        else:
            kind = StateNodeKind.EXACT
            key = StateDagNodeKey(handler_serial=handler, state_const=state_const)
            label = _state_label(kind, state_const, None, None)

        owned = tuple(owned_blocks(owners, handler))
        shared = tuple(shared_suffix_blocks(owners, handler))
        if successors_of is not None and predecessors_of is not None:
            local_segments, local_edges = build_local_structure(
                owned,
                successors_of=successors_of,
                predecessors_of=predecessors_of,
                shared_blocks=frozenset(shared),
                terminal_exit_blocks=frozenset(terminal_exit_blocks),
            )
        else:
            local_segments, local_edges = (), ()

        nodes.append(
            StateDagNode(
                key=key,
                kind=kind,
                state_label=label,
                handler_serial=handler,
                entry_anchor=handler,
                owned_blocks=owned,
                exclusive_blocks=tuple(exclusive_blocks(owners, handler)),
                shared_suffix_blocks=shared,
                local_segments=local_segments,
                local_edges=local_edges,
            )
        )

    edges = _build_outer_edges(nodes, transitions)

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
        edges=edges,
    )


def _build_outer_edges(
    nodes: list[StateDagNode],
    transitions: TransitionResult | None,
) -> tuple[StateDagEdge, ...]:
    """Project the outer state-level DAG edges off ``recover_transition_result``.

    Each :class:`StateTransition` (``from_state -> to_state``) becomes a
    :class:`StateDagEdge` between the state-level nodes (keyed by ``state_const``),
    ``CONDITIONAL_TRANSITION`` when the transition is conditional else
    ``TRANSITION``.  A ``to_state`` with no node yields ``target_key=None`` (a
    return/exit).  The richer ``ordered_path`` lowering lands with the spine port.
    """
    if transitions is None:
        return ()
    node_by_state = {
        int(n.key.state_const): n for n in nodes if n.key.state_const is not None
    }

    edges: list[StateDagEdge] = []
    for transition in transitions.transitions:
        if transition.from_state is None:
            continue
        source_node = node_by_state.get(int(transition.from_state))
        if source_node is None:
            continue
        target_node = node_by_state.get(int(transition.to_state))
        target_handler = (
            int(target_node.handler_serial) if target_node is not None else None
        )
        is_conditional = bool(transition.is_conditional)
        anchor = StateRedirectAnchor(
            kind=(
                RedirectSourceKind.CONDITIONAL_BRANCH
                if is_conditional
                else RedirectSourceKind.UNCONDITIONAL
            ),
            block_serial=int(transition.from_block),
            branch_arm=None,
        )
        edges.append(
            StateDagEdge(
                kind=(
                    SemanticEdgeKind.CONDITIONAL_TRANSITION
                    if is_conditional
                    else SemanticEdgeKind.TRANSITION
                ),
                source_key=source_node.key,
                target_key=target_node.key if target_node is not None else None,
                target_state=int(transition.to_state),
                target_entry_anchor=target_handler if target_handler is not None else None,
                target_label=target_node.state_label if target_node is not None else "",
                source_anchor=anchor,
                ordered_path=(int(transition.from_block),),
                last_write_site=None,
            )
        )

    edges.sort(
        key=lambda e: (
            int(e.source_key.handler_serial),
            int(e.target_state) if e.target_state is not None else -1,
            e.kind.name,
        )
    )
    return tuple(edges)
