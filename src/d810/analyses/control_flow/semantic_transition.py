"""In-memory transition resolution through exact state-dispatcher maps."""
from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.ir import ValueRef


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


def resolve_state_transitions_with_dispatcher_map(
    transition_facts: tuple[StateTransitionFact, ...],
    *,
    dispatch_map: StateDispatcherMap | None,
    state_write_anchors: tuple[StateWriteAnchor, ...] = (),
    resolution_kind: str = "state_dispatcher_map",
) -> tuple[StateTransitionResolution, ...]:
    """Resolve transition facts using in-memory exact dispatcher rows."""
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
            target_block = dispatch_map.resolve_target(source_state)
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


__all__ = [
    "SemanticTransition",
    "SemanticTransitionKind",
    "facts_from_validated_view",
    "semantic_transition_from_fact",
    "StateTransitionFact",
    "StateTransitionResolution",
    "StateWriteAnchor",
    "resolve_state_transitions_with_dispatcher_map",
]
