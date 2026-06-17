"""Resolve predecessor-carried states through dispatcher row evidence."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.condition_chain_model import ConditionChainAnalysisResult
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap


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
    )


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
) -> PredecessorDispatcherTargetFact | None:
    """Resolve one predecessor-carried state through exact or interval rows."""

    normalized_state = int(state_const) & 0xFFFFFFFFFFFFFFFF
    if state_dispatcher_map is not None:
        for row in state_dispatcher_map.rows:
            if (int(row.state_const) & 0xFFFFFFFFFFFFFFFF) != normalized_state:
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
            )

    if range_evidence is None:
        return None

    dispatcher = getattr(range_evidence, "dispatcher", None)
    if dispatcher is not None:
        row = dispatcher.lookup_row(normalized_state)
        if row is not None and row.target is not None:
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
            )

    for handler_serial, handler_state in getattr(
        range_evidence, "handler_state_map", {}
    ).items():
        if (int(handler_state) & 0xFFFFFFFFFFFFFFFF) != normalized_state:
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
        )

    exact_handler_serials = set(getattr(range_evidence, "handler_state_map", {}).keys())
    for handler_serial, (lo, hi) in getattr(
        range_evidence, "handler_range_map", {}
    ).items():
        if handler_serial in exact_handler_serials:
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
            )

    return None


def collect_predecessor_dispatcher_target_facts(
    *,
    transition_result: object | None,
    dispatcher_entry_serial: int,
    state_dispatcher_map: StateDispatcherMap | None = None,
    range_evidence: ConditionChainAnalysisResult | None = None,
    transition_report: object | None = None,
    dag: object | None = None,
    state_var_stkoff: int | None = None,
) -> tuple[PredecessorDispatcherTargetFact, ...]:
    """Resolve transition target states into predecessor-target facts."""

    facts: list[PredecessorDispatcherTargetFact] = []
    seen: set[str] = set()
    for transition in getattr(transition_result, "transitions", ()) or ():
        to_state = getattr(transition, "to_state", None)
        predecessor = getattr(transition, "from_block", None)
        if to_state is None or predecessor is None:
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
                )
            except (TypeError, ValueError):
                fact = None
            if fact is not None and fact.fact_id not in seen:
                seen.add(fact.fact_id)
                facts.append(fact)

        for conditional_state in getattr(row, "conditional_states", ()) or ():
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
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=int(next_state),
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=_maybe_int(
                    getattr(source_key, "state_const", None)
                ),
                transition_provenance_kind=f"state_dag_{kind_name.lower()}",
                condition_block_serial=None,
                state_var_stkoff=state_var_stkoff,
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
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "PredecessorDispatcherTargetFact",
    "collect_predecessor_dispatcher_target_facts",
    "resolve_predecessor_dispatcher_target",
]
