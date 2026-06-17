"""Strategy-agnostic transition builder models for flattening analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core import getLogger
from d810.core.typing import Dict, List, Optional, Protocol

from d810.analyses.control_flow.condition_chain_model import ConditionChainAnalysisResult

logger = getLogger(__name__)


@dataclass
class StateTransition:
    """Represents a state transition in the Hodur state machine."""

    from_state: int | None
    to_state: int
    from_block: int
    condition_block: Optional[int] = None
    is_conditional: bool = False
    provenance_chain: List["tuple[int, int]"] = field(default_factory=list)
    provenance_kind: Optional[str] = None
    provenance_ea: Optional[int] = None


@dataclass
class StateUpdateSite:
    """Represents an instruction that writes the dispatcher state variable."""

    block_serial: int
    instruction: object


@dataclass
class StateHandler:
    """Represents a handler for a specific state value."""

    state_value: int
    check_block: int
    handler_blocks: List[int] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)


@dataclass
class TransitionResult:
    """Strategy-agnostic container for discovered state machine transitions."""

    transitions: List[StateTransition] = field(default_factory=list)
    handlers: Dict[int, StateHandler] = field(default_factory=dict)
    assignment_map: Dict[int, list] = field(default_factory=dict)
    initial_state: Optional[int] = None
    pre_header_serial: Optional[int] = None
    strategy_name: str = ""
    resolved_count: int = 0


def build_transition_result_from_state_machine(
    sm,
    *,
    pre_header_serial: Optional[int] = None,
    strategy_name: str = "",
) -> TransitionResult:
    """Factory: package a live ``StateMachine`` into a ``TransitionResult``.

    Replaces the inline ``TransitionResult(transitions=list(sm.transitions), ...)``
    construction formerly sitting inside ``StateWriteReconstructionStrategy.plan``.
    Pure data transform: no IDA calls, no flow-graph access.
    """
    return TransitionResult(
        transitions=list(sm.transitions),
        handlers=dict(sm.handlers),
        assignment_map=dict(sm.assignment_map),
        initial_state=sm.initial_state,
        pre_header_serial=pre_header_serial,
        strategy_name=strategy_name,
        resolved_count=len(sm.transitions),
    )


def transition_result_from_resolutions(
    resolutions, *, strategy_name: str = "unflat", dispatch_map=None
) -> TransitionResult:
    """Package unflatten ``StateTransitionResolution``s into a ``TransitionResult`` (DAG-builder input).

    Each resolved transition (``source_state -> resolved_next_state`` at ``source_block``) becomes a
    ``StateTransition``. Unresolved rows (no next state) are dropped. Pure data transform.

    When ``dispatch_map`` (the #1 ``StateDispatcherMap``) is supplied, also populate
    ``TransitionResult.handlers`` keyed by ``state_const`` with ``check_block = target_block`` — the
    entire report -> DAG -> region pipeline derives its rows from ``handlers``
    (``build_transition_analysis_from_graph`` iterates ``transition_result.handlers``), so without
    this the DAG has zero nodes and #3 ``plan_semantic_regions`` is empty even with N transitions.
    Mirrors the legacy ``_convert_condition_chain_to_result`` handler construction.
    """
    handlers: Dict[int, StateHandler] = {}
    if dispatch_map is not None:
        for dmap_row in getattr(dispatch_map, "rows", ()):
            state_const = int(dmap_row.state_const)
            target_block = int(dmap_row.target_block)
            handlers[state_const] = StateHandler(
                state_value=state_const,
                check_block=target_block,
                handler_blocks=[target_block],
                transitions=[],
            )
    transitions: List[StateTransition] = []
    for row in resolutions:
        next_state = getattr(row, "resolved_next_state_const_u64", None)
        if next_state is None:
            continue
        hexv = getattr(row, "source_state_const_hex", None)
        try:
            from_state = int(hexv, 16) if hexv else None
        except (TypeError, ValueError):
            from_state = None
        transition = StateTransition(
            from_state=from_state,
            to_state=int(next_state),
            from_block=int(getattr(row, "source_block_serial", 0)),
        )
        transitions.append(transition)
        if from_state is not None and from_state in handlers:
            handlers[from_state].transitions.append(transition)
    return TransitionResult(
        transitions=transitions,
        handlers=handlers,
        strategy_name=strategy_name,
        resolved_count=len(transitions),
    )


class TransitionBuilderStrategy(Protocol):
    """Protocol for pluggable transition-building strategies."""

    @property
    def name(self) -> str:
        ...

    def build(self, mba, detector) -> Optional[TransitionResult]:
        ...


def _get_state_var_stkoff(detector) -> Optional[int]:
    """Extract stack offset from detector state variable when available."""
    sm = getattr(detector, "state_machine", None)
    if sm is None or sm.state_var is None:
        return None
    stkoff = getattr(sm.state_var, "stkoff", None)
    if stkoff is not None:
        return int(stkoff)
    stack_ref = getattr(sm.state_var, "s", None)
    stack_off = getattr(stack_ref, "off", None)
    return int(stack_off) if stack_off is not None else None


def _convert_condition_chain_to_result(
    condition_chain: ConditionChainAnalysisResult,
) -> TransitionResult:
    """Convert a ConditionChainAnalysisResult into a TransitionResult.

    Uses the IntervalDispatcher (when available) as the primary source
    for state-to-handler resolution, falling back to handler_state_map
    for coverage.  This ensures that handlers reachable only through
    wide condition-chain range intervals are included.
    """
    state_to_handler_blk: Dict[int, int] = {
        state: blk
        for blk, state in condition_chain.handler_state_map.items()
        if blk not in condition_chain.condition_chain_blocks
    }

    # Backfill from IntervalDispatcher: wide-range intervals that map
    # to handler blocks not already present in handler_state_map are
    # added so that the resulting TransitionResult covers ALL handlers
    # the condition chain can route to. Targets appearing in multiple dispatcher
    # rows are catch-all / default blocks and are excluded.
    if condition_chain.dispatcher is not None:
        from collections import Counter as _Counter
        _target_freq: dict[int, int] = _Counter(
            r.target for r in condition_chain.dispatcher._rows
        )
        # Ground-truth genuine states: those a handler explicitly writes
        # (handler_state_map) plus exact equality-leaf constants (lo == hi rows,
        # which the dispatcher literally compares ``==`` against).  A WIDE
        # interval's ``lo`` is a SYNTHETIC partition boundary -- typically
        # ``previous_state + 1`` -- and is NOT a value the program ever occupies.
        # Enrolling it as a representative state fabricates a phantom handler that
        # seeds forward-eval drift (e.g. state 0x11cd1da4 = 0x11cd1da3 + 1, which
        # then routes interval-interior back onto a real handler and manufactures
        # spurious self/transition edges).  Prefer a genuine state that falls
        # inside the interval; if none exists the target is unreachable by any
        # real state and the row is skipped (it is, by construction, never the
        # sole enrolment path for a live handler -- those arrive via the
        # handler_state_map point-match above).
        genuine_states: set[int] = set(condition_chain.handler_state_map.values())
        genuine_states.update(
            r.lo for r in condition_chain.dispatcher._rows if r.lo == r.hi
        )
        for row in condition_chain.dispatcher._rows:
            target = row.target
            if target in condition_chain.condition_chain_blocks:
                continue
            if _target_freq[target] > 1:
                continue  # catch-all / default block
            # Only add if this target block has no entry yet (avoid
            # overwriting point-match entries with a range representative).
            if target in {blk for blk in state_to_handler_blk.values()}:
                continue
            if row.lo == row.hi:
                representative_state = row.lo
            else:
                in_range = sorted(
                    state for state in genuine_states if row.lo <= state <= row.hi
                )
                if not in_range:
                    logger.debug(
                        "convert_condition_chain: skip interval row lo=0x%x hi=0x%x target=%d "
                        "(no genuine state in range; refusing to enrol synthetic "
                        "boundary as a state)",
                        row.lo,
                        row.hi,
                        target,
                    )
                    continue
                representative_state = in_range[0]
            state_to_handler_blk[representative_state] = target

    handlers: Dict[int, StateHandler] = {}
    for state, handler_serial in state_to_handler_blk.items():
        handlers[state] = StateHandler(
            state_value=state,
            check_block=handler_serial,
            handler_blocks=[handler_serial],
            transitions=[],
        )

    transitions: List[StateTransition] = []
    for from_state, to_state in condition_chain.transitions.items():
        if to_state is None:
            continue
        from_blk = state_to_handler_blk.get(from_state)
        if from_blk is None:
            continue
        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            from_block=from_blk,
            condition_block=None,
            is_conditional=False,
        )
        transitions.append(transition)
        if from_state in handlers:
            handlers[from_state].transitions.append(transition)

    for from_state, to_states in condition_chain.conditional_transitions.items():
        from_blk = state_to_handler_blk.get(from_state)
        if from_blk is None:
            continue
        for to_state in to_states:
            transition = StateTransition(
                from_state=from_state,
                to_state=to_state,
                from_block=from_blk,
                condition_block=from_blk,
                is_conditional=True,
            )
            transitions.append(transition)
            if from_state in handlers:
                handlers[from_state].transitions.append(transition)

    return TransitionResult(
        transitions=transitions,
        handlers=handlers,
        assignment_map={},
        initial_state=condition_chain.initial_state,
        pre_header_serial=condition_chain.pre_header_serial,
        strategy_name="bst_walker",
        resolved_count=len(transitions),
    )


class TransitionBuilder:
    """Try provided strategies in order; return best resolved result."""

    def __init__(self, strategies: Optional[List[TransitionBuilderStrategy]] = None) -> None:
        self.strategies: List[TransitionBuilderStrategy] = list(strategies or [])

    def build(self, mba, detector) -> Optional[TransitionResult]:
        results: List[TransitionResult] = []
        for strategy in self.strategies:
            result = strategy.build(mba, detector)
            if result is not None:
                results.append(result)

        if not results:
            return None
        return max(results, key=lambda r: r.resolved_count)


__all__ = [
    "StateTransition",
    "StateUpdateSite",
    "StateHandler",
    "TransitionResult",
    "TransitionBuilderStrategy",
    "TransitionBuilder",
    "_get_state_var_stkoff",
    "_convert_condition_chain_to_result",
]
