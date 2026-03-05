"""Hodur-specific transition builder strategies."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Optional

from d810.recon.flow.bst_analysis import analyze_bst_dispatcher
from d810.recon.flow.transition_builder import (
    TransitionBuilderStrategy,
    TransitionResult,
    _convert_bst_to_result,
    _get_state_var_stkoff,
)

if TYPE_CHECKING:
    import ida_hexrays

    from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
        HodurStateMachineDetector,
    )


class BSTWalkerStrategy:
    """Walk BST dispatcher tree to discover transitions."""

    @property
    def name(self) -> str:
        return "bst_walker"

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
            bst = analyze_bst_dispatcher(
                mba,
                dispatcher_entry_serial=entry_serial,
                state_var_stkoff=stkoff,
            )
        except Exception:
            return None

        if not bst.handler_state_map:
            return None
        return _convert_bst_to_result(bst)


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
    return [BSTWalkerStrategy(), BFSWithMopTrackerStrategy()]


__all__ = [
    "BSTWalkerStrategy",
    "BFSWithMopTrackerStrategy",
    "default_hodur_transition_strategies",
]

