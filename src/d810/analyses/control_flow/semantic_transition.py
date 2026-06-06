"""In-memory transition resolution through exact state-dispatcher maps."""
from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.state_machine_analysis import (
    find_last_state_write_site_on_path_snapshot,
)
from d810.analyses.data_flow.abstract_value import Block
from d810.ir import ValueRef

# Maximum corridor depth followed when folding a binop-computed next-state.
# A handler whose next-state is computed (not a literal ``mov #const``) is
# resolved by carrying a const env down its UNIQUE successor chain; the bound
# keeps the walk finite for malformed graphs.
_MAX_CORRIDOR_HOPS = 8


@dataclass(frozen=True, slots=True)
class StateTransitionFact:
    """Portable view of one state-transition observation."""

    fact_id: str
    source_block_serial: int
    source_state_const: int
    source_state_const_hex: str | None = None
    successor_kind: str = "branch"
    state_var_stkoff: int | None = None


@dataclass(frozen=True, slots=True)
class StateWriteAnchor:
    """Portable view of a state write observed at a handler block."""

    block_serial: int
    state_const: int
    state_var_stkoff: int | None = None


@dataclass(frozen=True, slots=True)
class StateTransitionResolution:
    """Result of resolving one transition through a state-dispatcher map."""

    fact_id: str
    source_block_serial: int
    source_state_const_hex: str
    resolved_next_block_serial: int | None
    resolved_next_state_const_hex: str | None
    resolved_next_state_const_u64: int | None
    resolution_kind: str
    resolution_reason: str

    def to_diag_row(self, *, resolution_maturity: str) -> dict[str, object]:
        """Return the row shape expected by the diag snapshot sink."""
        return {
            "fact_id": self.fact_id,
            "source_block_serial": self.source_block_serial,
            "source_state_const_hex": self.source_state_const_hex,
            "resolved_next_block_serial": self.resolved_next_block_serial,
            "resolved_next_state_const_hex": self.resolved_next_state_const_hex,
            "resolved_next_state_const_u64": self.resolved_next_state_const_u64,
            "resolution_kind": self.resolution_kind,
            "resolution_reason": self.resolution_reason,
            "resolution_maturity": str(resolution_maturity),
        }


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _state_write_lookup(
    anchors: tuple[StateWriteAnchor, ...],
) -> dict[tuple[int, int | None], int]:
    lookup: dict[tuple[int, int | None], int] = {}
    for anchor in anchors:
        key = (int(anchor.block_serial), anchor.state_var_stkoff)
        lookup.setdefault(key, int(anchor.state_const) & 0xFFFFFFFFFFFFFFFF)
    return lookup


def _select_state_write(
    lookup: dict[tuple[int, int | None], int],
    *,
    block_serial: int,
    state_var_stkoff: int | None,
) -> int | None:
    exact = lookup.get((int(block_serial), state_var_stkoff))
    if exact is not None:
        return exact
    if state_var_stkoff is not None:
        return lookup.get((int(block_serial), None))
    for (candidate_block, _candidate_stkoff), state_const in lookup.items():
        if candidate_block == int(block_serial):
            return state_const
    return None


def _route_target(
    model: object | None,
    dispatch_map: StateDispatcherMap,
    source_state: int,
) -> int | None:
    """Route a source state to a target block via ``model.route()`` (S2) or exact rows.

    When a ``model`` (e.g. ``ComparisonDispatcherModel``) is supplied, route
    through it and unwrap a single :class:`Block` (interval-aware); else fall
    back to the exact-only ``dispatch_map.resolve_target`` (legacy behaviour).
    """
    if model is not None and hasattr(model, "route"):
        rr = model.route(int(source_state))
        return rr.serial if isinstance(rr, Block) else None
    return dispatch_map.resolve_target(int(source_state))


def _build_corridor_path(
    graph: object,
    target_block: int,
    dispatch_map: StateDispatcherMap,
    *,
    max_hops: int = _MAX_CORRIDOR_HOPS,
) -> tuple[int, ...]:
    """Follow the UNIQUE successor chain from *target_block* into a corridor path.

    Stops when a block has != 1 successor, when the next block re-enters the
    dispatcher, on a cycle, or after *max_hops* hops.  The returned path always
    starts with ``target_block`` so the snapshot path-eval can carry the
    handler-local const env (the two ``mov #const`` register loads) forward into
    the corridor block that performs the binop state write.
    """
    path: list[int] = [int(target_block)]
    visited: set[int] = {int(target_block)}
    current = int(target_block)
    for _ in range(max_hops):
        block = graph.get_block(current)
        if block is None:
            break
        succs = tuple(block.succs)
        if len(succs) != 1:
            break
        nxt = int(succs[0])
        if nxt in visited or nxt in dispatch_map.dispatcher_blocks:
            break
        path.append(nxt)
        visited.add(nxt)
        current = nxt
    return tuple(path)


def _fold_corridor_state_write(
    graph: object | None,
    dispatch_map: StateDispatcherMap,
    *,
    target_block: int,
    state_var_stkoff: int | None,
) -> int | None:
    """Fold a binop-computed next-state along *target_block*'s single corridor.

    Returns the folded 32-bit next-state ONLY when it is a known dispatcher
    target (``dispatch_map.resolve_target`` succeeds, or it appears as a state
    constant in the map); otherwise ``None`` so the caller keeps the next-state
    BLANK.  This handles UNCONDITIONAL single-corridor handlers only.
    """
    if graph is None or state_var_stkoff is None:
        return None

    ordered_path = _build_corridor_path(graph, int(target_block), dispatch_map)
    folded = find_last_state_write_site_on_path_snapshot(
        graph,
        ordered_path,
        int(state_var_stkoff),
    )
    if folded is None:
        return None

    _write_block, site = folded
    candidate = int(site.state_value) & 0xFFFFFFFF
    known_states = set(dispatch_map.state_to_handler().keys())
    if (
        dispatch_map.resolve_target(candidate) is not None
        or candidate in known_states
    ):
        return candidate
    return None


def resolve_state_transitions_with_dispatcher_map(
    transition_facts: tuple[StateTransitionFact, ...],
    *,
    dispatch_map: StateDispatcherMap | None,
    state_write_anchors: tuple[StateWriteAnchor, ...] = (),
    resolution_kind: str = "state_dispatcher_map",
    model: object | None = None,
    graph: object | None = None,
    state_var_stkoff: int | None = None,
) -> tuple[StateTransitionResolution, ...]:
    """Resolve transition facts using in-memory dispatcher rows.

    ``model`` (S2) is an optional ``ComparisonDispatcherModel`` (any object with
    a ``route(value) -> RouteResult`` method).  When supplied, routing goes
    through ``model.route()`` — exact *and* interval rows — so an interval-routed
    next-state (``0x79F598F7 ∈ [..] -> blk 52``) resolves instead of being
    dropped as ``"state_not_in_dispatcher_map"`` (the 28-orphan fix).  Absent a
    model, routing stays exact-only via ``dispatch_map.resolve_target``
    (byte-identical legacy behaviour).
    """
    write_lookup = _state_write_lookup(state_write_anchors)
    resolutions: list[StateTransitionResolution] = []
    for fact in transition_facts:
        source_state = int(fact.source_state_const) & 0xFFFFFFFFFFFFFFFF
        source_hex = fact.source_state_const_hex or _hex_u64(source_state)
        target_block: int | None = None
        next_state: int | None = None
        next_state_hex: str | None = None

        if fact.successor_kind != "branch":
            reason = (
                f"successor_kind={fact.successor_kind}; "
                "not a dispatcher-bound transition"
            )
        elif dispatch_map is None or not dispatch_map.rows:
            reason = "no_dispatcher_rows_available"
        else:
            target_block = _route_target(model, dispatch_map, source_state)
            if target_block is None:
                reason = "state_not_in_dispatcher_map"
            elif target_block in dispatch_map.dispatcher_blocks:
                reason = "target_is_dispatcher_block"
                target_block = None
            else:
                next_state = _select_state_write(
                    write_lookup,
                    block_serial=target_block,
                    state_var_stkoff=fact.state_var_stkoff,
                )
                if next_state is not None:
                    next_state_hex = _hex_u64(next_state)
                    reason = "resolved_exact_state"
                else:
                    # No LITERAL state-write anchor at the routed handler: the
                    # next-state is binop-computed (e.g. ``xor eax,ecx``).  Fold
                    # it along the handler's single corridor.  Additive/safe:
                    # only fills a previously-BLANK next-state, never overrides
                    # an existing literal resolution.
                    fold_stkoff = (
                        fact.state_var_stkoff
                        if fact.state_var_stkoff is not None
                        else state_var_stkoff
                        if state_var_stkoff is not None
                        else dispatch_map.state_var_stkoff
                    )
                    folded = _fold_corridor_state_write(
                        graph,
                        dispatch_map,
                        target_block=target_block,
                        state_var_stkoff=fold_stkoff,
                    )
                    if folded is not None:
                        next_state = folded
                        next_state_hex = _hex_u64(next_state)
                        reason = "resolved_folded_state_write"
                    else:
                        reason = "resolved_exact_state"

        resolutions.append(
            StateTransitionResolution(
                fact_id=str(fact.fact_id),
                source_block_serial=int(fact.source_block_serial),
                source_state_const_hex=str(source_hex),
                resolved_next_block_serial=target_block,
                resolved_next_state_const_hex=next_state_hex,
                resolved_next_state_const_u64=next_state,
                resolution_kind=resolution_kind,
                resolution_reason=reason,
            )
        )
    return tuple(resolutions)


def facts_from_validated_view(
    fact_view: object | None,
) -> tuple[tuple[StateTransitionFact, ...], tuple[StateWriteAnchor, ...]]:
    """Project a validated fact view into in-memory transition evidence."""
    if fact_view is None:
        return (), ()
    observations = tuple(getattr(fact_view, "active_observations", ()) or ())
    transition_facts: list[StateTransitionFact] = []
    state_write_anchors: list[StateWriteAnchor] = []

    for observation in observations:
        kind = str(getattr(observation, "kind", ""))
        payload = dict(getattr(observation, "payload", {}) or {})
        if kind == "StateTransitionAnchorFact":
            source_block = payload.get("source_block_serial")
            source_state = payload.get("source_state_const")
            if source_block is None or source_state is None:
                continue
            try:
                transition_facts.append(
                    StateTransitionFact(
                        fact_id=str(getattr(observation, "fact_id")),
                        source_block_serial=int(source_block),
                        source_state_const=int(source_state),
                        source_state_const_hex=_maybe_str(
                            payload.get("source_state_const_hex")
                        ),
                        successor_kind=str(
                            payload.get("successor_kind", "branch")
                        ),
                        state_var_stkoff=_maybe_int(
                            payload.get("state_var_stkoff")
                        ),
                    )
                )
            except (TypeError, ValueError):
                continue
        elif kind == "StateWriteAnchorFact":
            block_serial = payload.get("block_serial")
            state_const = payload.get("state_const_u64")
            if state_const is None:
                state_const = payload.get("state_const")
            if block_serial is None or state_const is None:
                continue
            try:
                state_write_anchors.append(
                    StateWriteAnchor(
                        block_serial=int(block_serial),
                        state_const=int(state_const),
                        state_var_stkoff=_maybe_int(
                            payload.get("state_var_stkoff")
                        ),
                    )
                )
            except (TypeError, ValueError):
                continue

    return tuple(transition_facts), tuple(state_write_anchors)


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


class SemanticTransitionKind(str, enum.Enum):
    """Normalized vocabulary for every state-transition source (LS11 C7)."""

    HANDLER_WRITE = "handler_write"
    CASE_WRITE = "case_write"
    LOOP_UPDATE = "loop_update"
    CARRIED_STATE = "carried_state"
    CONDITIONAL_RETURN = "conditional_return"
    EXIT_ROUTINE = "exit_routine"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SemanticTransition:
    """One normalized semantic state transition (LS11 C7).

    ``subject`` carries portable value identity (LS11 C4) for the value whose
    write drives the transition, typed as ``d810.ir.ValueRef`` (analyses -> ir
    is downward-legal).  Net-new and unwired in LS11; future slices consume it
    in place of the ad-hoc transition shapes scattered across the dispatcher
    cluster.
    """

    source_block_serial: int
    source_state_const: int
    kind: SemanticTransitionKind
    target_block_serial: int | None = None
    target_state_const: int | None = None
    subject: ValueRef | None = None
    source_state_const_hex: str | None = None
    evidence_fact_id: str | None = None


def semantic_transition_from_fact(
    fact: StateTransitionFact,
) -> SemanticTransition:
    """Project a legacy ``StateTransitionFact`` into the normalized vocabulary.

    Conservative: an unrecognized ``successor_kind`` maps to ``UNKNOWN`` rather
    than guessing a specific transition source.
    """
    kind = (
        SemanticTransitionKind.HANDLER_WRITE
        if fact.successor_kind == "branch"
        else SemanticTransitionKind.UNKNOWN
    )
    return SemanticTransition(
        source_block_serial=fact.source_block_serial,
        source_state_const=fact.source_state_const,
        kind=kind,
        source_state_const_hex=fact.source_state_const_hex,
        evidence_fact_id=fact.fact_id,
    )


def resolve_state_transitions(
    graph,
    facts,
    *,
    dispatch_map: "StateDispatcherMap | None" = None,
    model: object | None = None,
    state_var_stkoff: int | None = None,
) -> "tuple[StateTransitionResolution, ...]":
    """§1a pass #2: resolve transition facts through the portable dispatcher map.

    Composes the canonical portable resolver — ``facts_from_validated_view`` projects the
    validated facts into ``(transition_facts, state_write_anchors)``, then
    ``resolve_state_transitions_with_dispatcher_map`` resolves each transition. LiSA-style: this is
    the transfer step over the state-machine graph. ``dispatch_map`` is the seam input produced by
    ``recover_dispatcher``; while it is ``None`` (state-machine detection not yet ported out of the
    live ``emulated_dispatcher_family``), transitions resolve to an explicit ``unresolved`` kind
    rather than silently dropping. ``graph``/``facts`` are duck-typed (FlowGraph / ValidatedFactView).
    """
    transition_facts, state_write_anchors = facts_from_validated_view(facts)
    return resolve_state_transitions_with_dispatcher_map(
        transition_facts,
        dispatch_map=dispatch_map,
        state_write_anchors=state_write_anchors,
        model=model,
        graph=graph,
        state_var_stkoff=state_var_stkoff,
    )


__all__ = [
    "SemanticTransition",
    "SemanticTransitionKind",
    "facts_from_validated_view",
    "semantic_transition_from_fact",
    "resolve_state_transitions",
    "StateTransitionFact",
    "StateTransitionResolution",
    "StateWriteAnchor",
    "resolve_state_transitions_with_dispatcher_map",
]
