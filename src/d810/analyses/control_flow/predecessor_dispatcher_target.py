"""Resolve predecessor-carried states through dispatcher row evidence."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainAnalysisResult,
)
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.semantic_transition import (
    SUCCESSFUL_TRANSITION_RESOLUTION_REASONS as _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS,
)


PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS = (
    "predecessor_dispatcher_target_facts"
)


@dataclass(frozen=True, slots=True)
class PredecessorDispatcherTargetFact:
    """One proof that a predecessor state value routes to a dispatcher target.

    ``state_const`` is the value reaching the dispatcher from
    ``predecessor_block_serial``.  The fact records whether that value was
    resolved by an exact state-dispatcher row or by an interval/range row, so
    consumers do not need to rediscover the dispatcher topology.
    """

    fact_id: str
    predecessor_block_serial: int
    dispatcher_entry_serial: int
    state_const: int
    target_block_serial: int
    resolver_kind: str
    row_kind: str
    dispatcher_block_serial: int | None = None
    compare_block_serial: int | None = None
    branch_kind: str | None = None
    row_lo_inclusive: int | None = None
    row_hi_exclusive: int | None = None
    source_state_const: int | None = None
    transition_provenance_kind: str | None = None
    condition_block_serial: int | None = None
    state_var_stkoff: int | None = None
    confidence: float = 1.0
    source_instruction_ea: int | None = None
    state_var_reg: int | None = None

    @property
    def state_const_hex(self) -> str:
        return _hex_u64(self.state_const)

    @property
    def source_state_const_hex(self) -> str | None:
        if self.source_state_const is None:
            return None
        return _hex_u64(self.source_state_const)

    def to_dict(self) -> dict[str, object]:
        return {
            "fact_id": self.fact_id,
            "predecessor_block_serial": self.predecessor_block_serial,
            "dispatcher_entry_serial": self.dispatcher_entry_serial,
            "state_const": self.state_const,
            "state_const_hex": self.state_const_hex,
            "target_block_serial": self.target_block_serial,
            "resolver_kind": self.resolver_kind,
            "row_kind": self.row_kind,
            "dispatcher_block_serial": self.dispatcher_block_serial,
            "compare_block_serial": self.compare_block_serial,
            "branch_kind": self.branch_kind,
            "row_lo_inclusive": self.row_lo_inclusive,
            "row_hi_exclusive": self.row_hi_exclusive,
            "source_state_const": self.source_state_const,
            "source_state_const_hex": self.source_state_const_hex,
            "transition_provenance_kind": self.transition_provenance_kind,
            "condition_block_serial": self.condition_block_serial,
            "state_var_stkoff": self.state_var_stkoff,
            "state_var_reg": self.state_var_reg,
            "source_instruction_ea": self.source_instruction_ea,
            "confidence": self.confidence,
        }


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _fact_id(
    *,
    dispatcher_entry_serial: int,
    predecessor_block_serial: int,
    state_const: int,
    target_block_serial: int,
    resolver_kind: str,
) -> str:
    return (
        "predecessor_dispatcher_target:"
        f"dispatcher={int(dispatcher_entry_serial)}:"
        f"pred={int(predecessor_block_serial)}:"
        f"state={_hex_u64(state_const)}:"
        f"target={int(target_block_serial)}:"
        f"resolver={resolver_kind}"
    )


def _build_fact(
    *,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    state_const: int,
    target_block_serial: int,
    resolver_kind: str,
    row_kind: str,
    dispatcher_block_serial: int | None,
    compare_block_serial: int | None,
    branch_kind: str | None,
    row_lo_inclusive: int | None,
    row_hi_exclusive: int | None,
    source_state_const: int | None,
    transition_provenance_kind: str | None,
    condition_block_serial: int | None,
    state_var_stkoff: int | None,
    confidence: float = 1.0,
    source_instruction_ea: int | None = None,
    state_var_reg: int | None = None,
) -> PredecessorDispatcherTargetFact:
    return PredecessorDispatcherTargetFact(
        fact_id=_fact_id(
            dispatcher_entry_serial=dispatcher_entry_serial,
            predecessor_block_serial=predecessor_block_serial,
            state_const=state_const,
            target_block_serial=target_block_serial,
            resolver_kind=resolver_kind,
        ),
        predecessor_block_serial=int(predecessor_block_serial),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        state_const=int(state_const) & 0xFFFFFFFFFFFFFFFF,
        target_block_serial=int(target_block_serial),
        resolver_kind=resolver_kind,
        row_kind=row_kind,
        dispatcher_block_serial=dispatcher_block_serial,
        compare_block_serial=compare_block_serial,
        branch_kind=branch_kind,
        row_lo_inclusive=row_lo_inclusive,
        row_hi_exclusive=row_hi_exclusive,
        source_state_const=source_state_const,
        transition_provenance_kind=transition_provenance_kind,
        condition_block_serial=condition_block_serial,
        state_var_stkoff=state_var_stkoff,
        confidence=confidence,
        source_instruction_ea=(
            None
            if source_instruction_ea is None
            else int(source_instruction_ea)
        ),
        state_var_reg=(None if state_var_reg is None else int(state_var_reg)),
    )


def _dispatcher_topology_serials(
    state_dispatcher_map: StateDispatcherMap | None,
) -> frozenset[int]:
    """Return every serial that belongs to the current dispatcher topology."""
    if state_dispatcher_map is None:
        return frozenset()
    serials = {
        int(state_dispatcher_map.dispatcher_entry_block),
        *(int(serial) for serial in state_dispatcher_map.dispatcher_blocks),
    }
    for row in state_dispatcher_map.rows:
        serials.add(int(row.dispatcher_block))
        if row.compare_block is not None:
            serials.add(int(row.compare_block))
    return frozenset(serials)


StateIdentity = tuple[int | None, int | None]


def _transition_identity(row: object) -> StateIdentity | None:
    """Return one transition row's exact state-cell identity, if present."""
    stkoff = _maybe_int(getattr(row, "state_var_stkoff", None))
    reg = _maybe_int(getattr(row, "state_var_reg", None))
    if stkoff is None and reg is None:
        return None
    return (stkoff, reg)


def select_supported_transition_identity(
    transition_resolutions: object | None,
    *,
    dispatcher_topology_serials: frozenset[int] = frozenset(),
) -> StateIdentity | None:
    """Select one state identity supported by successful handler resolutions.

    Support is deliberately derived only from the active in-memory resolution
    tuple.  A successful resolution contributes a vote when it has a concrete
    non-dispatcher target and an explicit state-cell identity.  Repeated rows
    are deduplicated before selecting; any zero-or-many supported identities is
    an abstention rather than an insertion-order tie break.
    """
    supported: set[StateIdentity] = set()
    seen_observations: set[tuple[str, str, int, StateIdentity]] = set()
    dispatcher_topology = {
        int(serial) for serial in (dispatcher_topology_serials or ())
    }
    for row in transition_resolutions or ():
        if (
            getattr(row, "resolution_reason", None)
            not in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
        ):
            continue
        target = getattr(row, "resolved_next_block_serial", None)
        if target is None or isinstance(target, bool):
            continue
        try:
            target = int(target)
        except (TypeError, ValueError):
            continue
        if target < 0 or target in dispatcher_topology:
            continue
        identity = _transition_identity(row)
        if identity is None:
            continue
        observation_key = (
            str(getattr(row, "source_block_serial", "")),
            str(getattr(row, "source_state_const_hex", "")),
            target,
            identity,
        )
        if observation_key in seen_observations:
            continue
        seen_observations.add(observation_key)
        supported.add(identity)
    if len(supported) != 1:
        return None
    return next(iter(supported))


def resolve_predecessor_dispatcher_target(
    *,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    state_const: int,
    state_dispatcher_map: StateDispatcherMap | None = None,
    range_evidence: ConditionChainAnalysisResult | None = None,
    source_state_const: int | None = None,
    transition_provenance_kind: str | None = None,
    condition_block_serial: int | None = None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
    source_instruction_ea: int | None = None,
) -> PredecessorDispatcherTargetFact | None:
    """Resolve one predecessor-carried state through exact or interval rows."""

    normalized_state = int(state_const) & 0xFFFFFFFFFFFFFFFF
    dispatcher_topology = _dispatcher_topology_serials(state_dispatcher_map)
    if state_dispatcher_map is not None:
        for row in state_dispatcher_map.rows:
            if (int(row.state_const) & 0xFFFFFFFFFFFFFFFF) != normalized_state:
                continue
            if int(row.target_block) in dispatcher_topology:
                # A dispatcher self-loop is not a handler route.  Keep looking
                # for stronger condition-chain interval/handler evidence below.
                continue
            return _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=int(row.target_block),
                resolver_kind="state_dispatcher_map_exact_row",
                row_kind=str(row.row_kind),
                dispatcher_block_serial=int(row.dispatcher_block),
                compare_block_serial=(
                    None if row.compare_block is None else int(row.compare_block)
                ),
                branch_kind=str(row.branch_kind),
                row_lo_inclusive=normalized_state,
                row_hi_exclusive=normalized_state + 1,
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                confidence=float(row.confidence),
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
            )

    if range_evidence is None:
        return None

    dispatcher = getattr(range_evidence, "dispatcher", None)
    if dispatcher is not None:
        row = dispatcher.lookup_row(normalized_state)
        if (
            row is not None
            and row.target is not None
            and int(row.target) not in dispatcher_topology
        ):
            return _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=int(row.target),
                resolver_kind="interval_dispatcher_row",
                row_kind=(
                    "interval_exact"
                    if int(row.hi) - int(row.lo) == 1
                    else "interval_range"
                ),
                dispatcher_block_serial=None,
                compare_block_serial=None,
                branch_kind=None,
                row_lo_inclusive=int(row.lo),
                row_hi_exclusive=int(row.hi),
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
            )

    for handler_serial, handler_state in getattr(
        range_evidence, "handler_state_map", {}
    ).items():
        if (int(handler_state) & 0xFFFFFFFFFFFFFFFF) != normalized_state:
            continue
        if int(handler_serial) in dispatcher_topology:
            continue
        return _build_fact(
            predecessor_block_serial=predecessor_block_serial,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_const=normalized_state,
            target_block_serial=int(handler_serial),
            resolver_kind="condition_chain_handler_state_map_exact_row",
            row_kind="exact",
            dispatcher_block_serial=None,
            compare_block_serial=None,
            branch_kind=None,
            row_lo_inclusive=normalized_state,
            row_hi_exclusive=normalized_state + 1,
            source_state_const=source_state_const,
            transition_provenance_kind=transition_provenance_kind,
            condition_block_serial=condition_block_serial,
            state_var_stkoff=state_var_stkoff,
            source_instruction_ea=source_instruction_ea,
            state_var_reg=state_var_reg,
        )

    exact_handler_serials = set(getattr(range_evidence, "handler_state_map", {}).keys())
    for handler_serial, (lo, hi) in getattr(
        range_evidence, "handler_range_map", {}
    ).items():
        if handler_serial in exact_handler_serials:
            continue
        if int(handler_serial) in dispatcher_topology:
            continue
        if lo is None or hi is None:
            continue
        lo_int = int(lo)
        hi_int = int(hi)
        if (hi_int - lo_int) >= 0xFFFF0000:
            continue
        if lo_int <= normalized_state <= hi_int:
            return _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=int(handler_serial),
                resolver_kind="condition_chain_handler_range_map_row",
                row_kind="range",
                dispatcher_block_serial=None,
                compare_block_serial=None,
                branch_kind=None,
                row_lo_inclusive=lo_int,
                row_hi_exclusive=hi_int + 1,
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
            )

    return None


def collect_predecessor_dispatcher_target_facts(
    *,
    transition_result: object | None,
    dispatcher_entry_serial: int,
    state_dispatcher_map: StateDispatcherMap | None = None,
    range_evidence: ConditionChainAnalysisResult | None = None,
    transition_resolutions: object | None = None,
    transition_report: object | None = None,
    dag: object | None = None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
) -> tuple[PredecessorDispatcherTargetFact, ...]:
    """Resolve transition target states into predecessor-target facts."""

    facts: list[PredecessorDispatcherTargetFact] = []
    seen: set[str] = set()
    blocked_resolution_keys: set[tuple[int, int]] = set()
    dispatcher_topology = set(_dispatcher_topology_serials(state_dispatcher_map))
    dispatcher_topology.add(int(dispatcher_entry_serial))
    if range_evidence is not None:
        dispatcher_topology.update(
            int(serial)
            for serial in getattr(range_evidence, "condition_chain_blocks", ()) or ()
        )
        decision_dag = getattr(range_evidence, "decision_dag", None)
        if decision_dag is not None:
            dispatcher_topology.update(
                int(serial) for serial in getattr(decision_dag, "nodes", ()) or ()
            )
    supported_identity = select_supported_transition_identity(
        transition_resolutions,
        dispatcher_topology_serials=frozenset(dispatcher_topology),
    )
    for row in transition_resolutions or ():
        predecessor = getattr(row, "source_block_serial", None)
        source_state_hex = getattr(row, "source_state_const_hex", None)
        resolution_reason = getattr(row, "resolution_reason", None)
        if predecessor is None or source_state_hex is None:
            continue
        try:
            source_state = int(source_state_hex, 16)
            resolution_key = (int(predecessor), source_state)
        except (TypeError, ValueError):
            continue
        prior_target = getattr(row, "resolved_next_block_serial", None)
        if resolution_reason not in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS and (
            resolution_reason != "target_is_dispatcher_block"
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        if (
            resolution_reason in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
            and prior_target is None
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        # A target-is-dispatcher resolution deliberately carries no target
        # serial.  Its source state is still useful when the condition-chain
        # interval evidence can identify the real handler, but only when the
        # native anchor is retained for the later current-MBA binding.
        if (
            resolution_reason == "target_is_dispatcher_block"
            and getattr(row, "source_instruction_ea", None) is None
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        target_candidate_identity = _transition_identity(row)
        if resolution_reason == "target_is_dispatcher_block":
            if (
                supported_identity is None
                or target_candidate_identity is None
                or target_candidate_identity != supported_identity
            ):
                blocked_resolution_keys.add(resolution_key)
                continue
            candidate_state_var_stkoff = target_candidate_identity[0]
            candidate_state_var_reg = target_candidate_identity[1]
        else:
            candidate_state_var_stkoff = (
                state_var_stkoff
                if getattr(row, "state_var_stkoff", None) is None
                else _maybe_int(getattr(row, "state_var_stkoff"))
            )
            candidate_state_var_reg = (
                state_var_reg
                if getattr(row, "state_var_reg", None) is None
                else _maybe_int(getattr(row, "state_var_reg"))
            )
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=source_state,
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=source_state,
                transition_provenance_kind=_maybe_str(
                    getattr(row, "resolution_kind", None)
                ),
                condition_block_serial=None,
                state_var_stkoff=candidate_state_var_stkoff,
                state_var_reg=candidate_state_var_reg,
                source_instruction_ea=_maybe_int(
                    getattr(row, "source_instruction_ea", None)
                ),
            )
        except (TypeError, ValueError):
            blocked_resolution_keys.add(resolution_key)
            continue
        if fact is None or fact.fact_id in seen:
            if fact is None:
                blocked_resolution_keys.add(resolution_key)
            continue
        if resolution_reason in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS:
            try:
                if int(prior_target) != int(fact.target_block_serial):
                    blocked_resolution_keys.add(resolution_key)
                    continue
            except (TypeError, ValueError):
                blocked_resolution_keys.add(resolution_key)
                continue
        seen.add(fact.fact_id)
        facts.append(fact)

    for transition in getattr(transition_result, "transitions", ()) or ():
        to_state = getattr(transition, "to_state", None)
        predecessor = getattr(transition, "from_block", None)
        if to_state is None or predecessor is None:
            continue
        try:
            if (int(predecessor), int(to_state)) in blocked_resolution_keys:
                continue
        except (TypeError, ValueError):
            continue
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=int(to_state),
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=_maybe_int(getattr(transition, "from_state", None)),
                transition_provenance_kind=_maybe_str(
                    getattr(transition, "provenance_kind", None)
                ),
                condition_block_serial=_maybe_int(
                    getattr(transition, "condition_block", None)
                ),
                state_var_stkoff=state_var_stkoff,
                state_var_reg=(
                    state_var_reg
                    if getattr(transition, "state_var_reg", None) is None
                    else _maybe_int(getattr(transition, "state_var_reg"))
                ),
                source_instruction_ea=_maybe_int(
                    getattr(transition, "source_instruction_ea", None)
                ),
            )
        except (TypeError, ValueError):
            continue
        if fact is None or fact.fact_id in seen:
            continue
        seen.add(fact.fact_id)
        facts.append(fact)

    for row in getattr(transition_report, "rows", ()) or ():
        next_state = getattr(row, "next_state", None)
        predecessor = getattr(row, "handler_serial", None)
        if predecessor is None:
            continue
        if next_state is not None:
            try:
                if (int(predecessor), int(next_state)) in blocked_resolution_keys:
                    continue
            except (TypeError, ValueError):
                continue
            try:
                fact = resolve_predecessor_dispatcher_target(
                    predecessor_block_serial=int(predecessor),
                    dispatcher_entry_serial=int(dispatcher_entry_serial),
                    state_const=int(next_state),
                    state_dispatcher_map=state_dispatcher_map,
                    range_evidence=range_evidence,
                    source_state_const=_maybe_int(getattr(row, "state_const", None)),
                    transition_provenance_kind="transition_report",
                    condition_block_serial=None,
                    state_var_stkoff=state_var_stkoff,
                    state_var_reg=(
                        state_var_reg
                        if getattr(row, "state_var_reg", None) is None
                        else _maybe_int(getattr(row, "state_var_reg"))
                    ),
                    source_instruction_ea=_maybe_int(
                        getattr(row, "source_instruction_ea", None)
                    ),
                )
            except (TypeError, ValueError):
                fact = None
            if fact is not None and fact.fact_id not in seen:
                seen.add(fact.fact_id)
                facts.append(fact)

        for conditional_state in getattr(row, "conditional_states", ()) or ():
            try:
                if (
                    int(predecessor), int(conditional_state)
                ) in blocked_resolution_keys:
                    continue
            except (TypeError, ValueError):
                continue
            try:
                conditional_fact = resolve_predecessor_dispatcher_target(
                    predecessor_block_serial=int(predecessor),
                    dispatcher_entry_serial=int(dispatcher_entry_serial),
                    state_const=int(conditional_state),
                    state_dispatcher_map=state_dispatcher_map,
                    range_evidence=range_evidence,
                    source_state_const=_maybe_int(getattr(row, "state_const", None)),
                    transition_provenance_kind="transition_report_conditional",
                    condition_block_serial=None,
                    state_var_stkoff=state_var_stkoff,
                    state_var_reg=(
                        state_var_reg
                        if getattr(row, "state_var_reg", None) is None
                        else _maybe_int(getattr(row, "state_var_reg"))
                    ),
                    source_instruction_ea=_maybe_int(
                        getattr(row, "source_instruction_ea", None)
                    ),
                )
            except (TypeError, ValueError):
                continue
            if conditional_fact is None or conditional_fact.fact_id in seen:
                continue
            seen.add(conditional_fact.fact_id)
            facts.append(conditional_fact)

    for edge in getattr(dag, "edges", ()) or ():
        kind_name = str(getattr(getattr(edge, "kind", None), "name", ""))
        if kind_name not in {"TRANSITION", "CONDITIONAL_TRANSITION"}:
            continue
        next_state = getattr(edge, "target_state", None)
        if next_state is None:
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        predecessor = _maybe_int(getattr(source_anchor, "block_serial", None))
        source_key = getattr(edge, "source_key", None)
        if predecessor is None:
            predecessor = _maybe_int(getattr(source_key, "handler_serial", None))
        if predecessor is None:
            continue
        try:
            if (int(predecessor), int(next_state)) in blocked_resolution_keys:
                continue
        except (TypeError, ValueError):
            continue
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=int(next_state),
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=_maybe_int(getattr(source_key, "state_const", None)),
                transition_provenance_kind=f"state_dag_{kind_name.lower()}",
                condition_block_serial=None,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=(
                    state_var_reg
                    if getattr(edge, "state_var_reg", None) is None
                    else _maybe_int(getattr(edge, "state_var_reg"))
                ),
                source_instruction_ea=_maybe_int(
                    getattr(edge, "source_instruction_ea", None)
                ),
            )
        except (TypeError, ValueError):
            continue
        if fact is None or fact.fact_id in seen:
            continue
        seen.add(fact.fact_id)
        facts.append(fact)
    return tuple(facts)


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS",
    "PredecessorDispatcherTargetFact",
    "StateIdentity",
    "collect_predecessor_dispatcher_target_facts",
    "resolve_predecessor_dispatcher_target",
    "select_supported_transition_identity",
]
