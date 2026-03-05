"""Strategy-agnostic transition builder models for flattening analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Dict, List, Optional, Protocol, TYPE_CHECKING

from d810.recon.flow.bst_model import BSTAnalysisResult

if TYPE_CHECKING:
    import ida_hexrays


@dataclass
class StateTransition:
    """Represents a state transition in the Hodur state machine."""

    from_state: int
    to_state: int
    from_block: int
    condition_block: Optional[int] = None
    is_conditional: bool = False


@dataclass
class StateUpdateSite:
    """Represents an instruction that writes the dispatcher state variable."""

    block_serial: int
    instruction: "ida_hexrays.minsn_t"


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


class TransitionBuilderStrategy(Protocol):
    """Protocol for pluggable transition-building strategies."""

    @property
    def name(self) -> str:
        ...

    def build(self, mba, detector) -> Optional[TransitionResult]:
        ...


def _get_state_var_stkoff(detector) -> Optional[int]:
    """Extract stack offset from detector state variable when available."""
    import ida_hexrays as _ida

    sm = getattr(detector, "state_machine", None)
    if sm is None or sm.state_var is None:
        return None
    if sm.state_var.t == _ida.mop_S:
        return sm.state_var.s.off
    return None


def _convert_bst_to_result(bst: BSTAnalysisResult) -> TransitionResult:
    """Convert a BSTAnalysisResult into a TransitionResult."""
    state_to_handler_blk: Dict[int, int] = {
        state: blk
        for blk, state in bst.handler_state_map.items()
        if blk not in bst.bst_node_blocks
    }

    handlers: Dict[int, StateHandler] = {}
    for state, handler_serial in state_to_handler_blk.items():
        handlers[state] = StateHandler(
            state_value=state,
            check_block=handler_serial,
            handler_blocks=[handler_serial],
            transitions=[],
        )

    transitions: List[StateTransition] = []
    for from_state, to_state in bst.transitions.items():
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

    for from_state, to_states in bst.conditional_transitions.items():
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
        initial_state=bst.initial_state,
        pre_header_serial=bst.pre_header_serial,
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
    "_convert_bst_to_result",
]

