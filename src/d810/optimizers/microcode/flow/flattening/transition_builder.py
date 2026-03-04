"""Strategy pattern for building Hodur state machine transitions.

Provides pluggable strategies for discovering state transitions from
microcode block arrays. Strategies are tried in order; the one that
resolves the most transitions wins.

Typical usage::

    from d810.optimizers.microcode.flow.flattening.transition_builder import (
        TransitionBuilder,
    )

    builder = TransitionBuilder()
    result = builder.build(mba, detector)
    if result is not None:
        print(f"Strategy '{result.strategy_name}' found {result.resolved_count} transitions")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING, Dict, List, Optional, Protocol

from d810.recon.flow.bst_analysis import analyze_bst_dispatcher
from d810.recon.flow.bst_model import BSTAnalysisResult

if TYPE_CHECKING:
    import ida_hexrays

    from d810.optimizers.microcode.flow.flattening.unflattener_hodur import (
        HodurStateMachineDetector,
    )


# ---------------------------------------------------------------------------
# Shared dataclasses (used by both transition_builder and unflattener_hodur)
# ---------------------------------------------------------------------------


@dataclass
class StateTransition:
    """Represents a state transition in the Hodur state machine."""

    from_state: int
    to_state: int
    from_block: int  # Block serial where transition originates
    condition_block: Optional[int] = None  # Block serial with state check (if conditional)
    is_conditional: bool = False  # True if this is a conditional transition


@dataclass
class StateUpdateSite:
    """Represents an instruction that writes the dispatcher state variable."""

    block_serial: int
    instruction: "ida_hexrays.minsn_t"


@dataclass
class StateHandler:
    """Represents a handler for a specific state value."""

    state_value: int
    check_block: int  # Block with jnz state, CONSTANT
    handler_blocks: List[int] = field(default_factory=list)  # Blocks executed when state matches
    transitions: List[StateTransition] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class TransitionResult:
    """Strategy-agnostic container for discovered state machine transitions.

    Attributes:
        transitions: All discovered state transitions.
        handlers: Mapping from state_value to its StateHandler.
        assignment_map: Mapping from block_serial to raw minsn_t assignment
            instructions. May be empty when the strategy does not collect
            raw instructions (e.g. BSTWalkerStrategy).
        initial_state: The initial state constant, or None if unknown.
        pre_header_serial: Block serial of the pre-header block that writes
            the initial state, or None if unavailable.
        strategy_name: Name of the strategy that produced this result.
        resolved_count: Number of fully resolved (known to_state) transitions.
    """

    transitions: List[StateTransition] = field(default_factory=list)
    handlers: Dict[int, StateHandler] = field(default_factory=dict)
    assignment_map: Dict[int, list] = field(default_factory=dict)
    initial_state: Optional[int] = None
    pre_header_serial: Optional[int] = None
    strategy_name: str = ""
    resolved_count: int = 0


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class TransitionBuilderStrategy(Protocol):
    """Protocol for pluggable transition-building strategies."""

    @property
    def name(self) -> str:
        """Human-readable identifier for this strategy."""
        ...

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        """Attempt to build transitions.

        Args:
            mba: The microcode block array.
            detector: The detector instance (may have partially populated
                ``state_machine`` from the detection phase).

        Returns:
            A :class:`TransitionResult` on success, or ``None`` if this
            strategy cannot handle the given function.
        """
        ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_state_var_stkoff(
    detector: "HodurStateMachineDetector",
) -> Optional[int]:
    """Extract the stack offset from the detector's state variable.

    Returns the ``s.off`` field when the state variable is a stack operand
    (``mop_S``), otherwise returns ``None`` so that ``analyze_bst_dispatcher``
    will auto-detect it.
    """
    import ida_hexrays as _ida

    sm = detector.state_machine
    if sm is None or sm.state_var is None:
        return None
    if sm.state_var.t == _ida.mop_S:
        return sm.state_var.s.off
    return None


def _convert_bst_to_result(bst: BSTAnalysisResult) -> TransitionResult:
    """Convert a :class:`BSTAnalysisResult` into a :class:`TransitionResult`.

    Mapping rules:

    * ``handler_state_map`` is inverted (blk→state → state→blk).
    * ``bst.transitions`` (state→next_state dict) is expanded into
      :class:`StateTransition` objects with ``is_conditional=False``.
    * ``bst.conditional_transitions`` (state→set of next_states) is expanded
      into additional :class:`StateTransition` objects with
      ``is_conditional=True``.
    * ``handler_blocks`` is initialised to ``[handler_serial]`` — the minimal
      body we know from BST analysis alone.
    * ``assignment_map`` is left empty (BST does not track raw instructions).
    """
    # 1. Invert: blk_serial -> state  becomes  state -> blk_serial
    # Filter out BST comparison node blocks — they are not handler entries.
    state_to_handler_blk: Dict[int, int] = {
        state: blk
        for blk, state in bst.handler_state_map.items()
        if blk not in bst.bst_node_blocks
    }

    # 2. Build handlers dict
    handlers: Dict[int, StateHandler] = {}
    for state, handler_serial in state_to_handler_blk.items():
        handlers[state] = StateHandler(
            state_value=state,
            check_block=handler_serial,
            handler_blocks=[handler_serial],
            transitions=[],
        )

    # 3. Unconditional transitions
    transitions: List[StateTransition] = []
    for from_state, to_state in bst.transitions.items():
        if to_state is None:
            continue
        from_blk = state_to_handler_blk.get(from_state)
        if from_blk is None:
            continue
        t = StateTransition(
            from_state=from_state,
            to_state=to_state,
            from_block=from_blk,
            condition_block=None,
            is_conditional=False,
        )
        transitions.append(t)
        if from_state in handlers:
            handlers[from_state].transitions.append(t)

    # 4. Conditional transitions
    for from_state, to_states in bst.conditional_transitions.items():
        from_blk = state_to_handler_blk.get(from_state)
        if from_blk is None:
            continue
        for to_state in to_states:
            t = StateTransition(
                from_state=from_state,
                to_state=to_state,
                from_block=from_blk,
                condition_block=from_blk,
                is_conditional=True,
            )
            transitions.append(t)
            if from_state in handlers:
                handlers[from_state].transitions.append(t)

    resolved = len(transitions)

    return TransitionResult(
        transitions=transitions,
        handlers=handlers,
        assignment_map={},
        initial_state=bst.initial_state,
        pre_header_serial=bst.pre_header_serial,
        strategy_name="bst_walker",
        resolved_count=resolved,
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


class BSTWalkerStrategy:
    """Walk the BST dispatcher tree to discover transitions.

    Best suited for BST-structured dispatchers where the state machine
    comparison tree is a balanced binary search tree.
    """

    @property
    def name(self) -> str:
        return "bst_walker"

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        """Run BST analysis and convert the result.

        Passes ``state_var_stkoff`` when the detector already knows the stack
        variable; otherwise lets ``analyze_bst_dispatcher`` auto-detect it.
        Falls back to ``None`` on any exception or if the BST analysis finds
        no handlers.

        Args:
            mba: The microcode block array.
            detector: Detector instance with (optionally) a populated
                ``state_machine``.

        Returns:
            :class:`TransitionResult` on success, ``None`` on failure.
        """
        # Need at least one block identified to pick an entry point.
        # Use block 0 as the BST root entry when no better information is
        # available — analyze_bst_dispatcher will walk from there.
        entry_serial = 0
        sm = detector.state_machine
        if sm is not None and sm.handlers:
            # Use the check_block of the first handler as the entry point.
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
    """Extract results from the existing BFS + MopTracker detection.

    This strategy does NOT re-run ``_build_transitions``; it assumes the
    caller has already run ``detector.detect()`` and reads the results that
    were written into ``detector.state_machine``.  Use this as a fallback
    when BST analysis cannot find enough transitions.
    """

    @property
    def name(self) -> str:
        return "bfs_moptracker"

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        """Extract transitions already discovered by the detector.

        Args:
            mba: The microcode block array (unused here, kept for protocol
                compatibility).
            detector: Detector instance whose ``state_machine`` has been
                populated by ``detect()``.

        Returns:
            :class:`TransitionResult` wrapping the detector's current
            state machine, or ``None`` if no transitions were found.
        """
        sm = detector.state_machine
        if sm is None or not sm.transitions:
            return None

        resolved = sum(1 for t in sm.transitions if t.to_state is not None)

        return TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=None,
            strategy_name="bfs_moptracker",
            resolved_count=resolved,
        )


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


class TransitionBuilder:
    """Try multiple strategies in order; return the best result.

    "Best" is defined as the result with the highest ``resolved_count``.
    If no strategy produces a result, returns ``None``.

    Args:
        strategies: Ordered list of strategies to try.  Defaults to
            ``[BSTWalkerStrategy(), BFSWithMopTrackerStrategy()]``.

    Example::

        builder = TransitionBuilder()
        result = builder.build(mba, detector)
        if result:
            print(result.strategy_name, result.resolved_count)
    """

    def __init__(
        self,
        strategies: Optional[List[TransitionBuilderStrategy]] = None,
    ) -> None:
        self.strategies: List[TransitionBuilderStrategy] = strategies or [
            BSTWalkerStrategy(),
            BFSWithMopTrackerStrategy(),
        ]

    def build(
        self,
        mba: "ida_hexrays.mbl_array_t",
        detector: "HodurStateMachineDetector",
    ) -> Optional[TransitionResult]:
        """Run all strategies and return the one with most resolved transitions.

        Args:
            mba: The microcode block array.
            detector: The detector instance.

        Returns:
            The best :class:`TransitionResult`, or ``None`` if every strategy
            failed.
        """
        results: List[TransitionResult] = []
        for strategy in self.strategies:
            result = strategy.build(mba, detector)
            if result is not None:
                results.append(result)

        if not results:
            return None

        return max(results, key=lambda r: r.resolved_count)
