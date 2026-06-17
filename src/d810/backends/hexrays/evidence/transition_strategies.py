"""Hodur-specific transition builder strategies."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Optional

from d810.backends.hexrays.evidence.condition_chain_analysis import analyze_condition_chain_dispatcher
from d810.analyses.control_flow.transition_builder import (
    TransitionBuilderStrategy,
    TransitionResult,
    _convert_condition_chain_to_result,
    _get_state_var_stkoff,
)

if TYPE_CHECKING:
    import ida_hexrays

    from d810.backends.hexrays.evidence.analysis import (
        HodurStateMachineDetector,
    )


class ConditionChainWalkerStrategy:
    """Walk condition-chain dispatcher tree to discover transitions."""

    @property
    def name(self) -> str:
        return "condition_chain_walker"

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        entry_serial = 0
        sm = detector.state_machine
        if sm is not None and sm.handlers:
            first_handler = next(iter(sm.handlers.values()))
            entry_serial = first_handler.check_block

        stkoff = _get_state_var_stkoff(detector)
        try:
            condition_chain = analyze_condition_chain_dispatcher(
                mba,
                dispatcher_entry_serial=entry_serial,
                state_var_stkoff=stkoff,
            )
        except Exception:
            return None

        if not condition_chain.handler_state_map:
            return None
        return _convert_condition_chain_to_result(condition_chain)


class BFSWithMopTrackerStrategy:
    """Reuse already-discovered detector transitions as fallback."""

    @property
    def name(self) -> str:
        return "bfs_moptracker"

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        sm = detector.state_machine
        if sm is None or not sm.transitions:
            return None

        resolved = sum(1 for transition in sm.transitions if transition.to_state is not None)
        return TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=None,
            strategy_name="bfs_moptracker",
            resolved_count=resolved,
        )


def default_hodur_transition_strategies() -> list[TransitionBuilderStrategy]:
    """Default ordered strategy set for Hodur transition discovery."""
    return [ConditionChainWalkerStrategy(), BFSWithMopTrackerStrategy()]


__all__ = [
    "ConditionChainWalkerStrategy",
    "BFSWithMopTrackerStrategy",
    "default_hodur_transition_strategies",
]
