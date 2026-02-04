"""Composable services for control-flow flattening removal.

This module decomposes the monolithic GenericDispatcherUnflatteningRule into
smaller, single-responsibility services that can be composed together.

Following the composition-over-inheritance principle, these services are:
- Easier to test in isolation
- Easier to understand (each does one thing)
- Easier to reuse in different contexts
- Easier to modify without breaking other functionality
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Protocol, Tuple

import ida_hexrays

from d810.optimizers.core import OptimizationContext


@dataclass(frozen=True)
class Dispatcher:
    """Structured data representing a discovered control-flow flattening dispatcher.

    This immutable dataclass replaces the mutable GenericDispatcherInfo class,
    making dispatcher information explicit and easier to work with.

    A dispatcher is the central switch/dispatch block in a control-flow
    flattening obfuscation. It reads a state variable and jumps to different
    blocks based on that value.

    Attributes:
        entry_block: The microcode block that serves as the dispatcher entry.
        state_variable: The mop (microcode operand) used for dispatching decisions.
        comparison_values: List of constant values the state variable is compared against.
        internal_blocks: Blocks that are part of the dispatcher's internal logic.
        exit_blocks: Blocks that the dispatcher can transfer control to.
        mba: The microcode array containing this dispatcher.
    """
    entry_block: ida_hexrays.mblock_t
    state_variable: ida_hexrays.mop_t
    comparison_values: List[int] = field(default_factory=list)
    internal_blocks: List[ida_hexrays.mblock_t] = field(default_factory=list)
    exit_blocks: List[ida_hexrays.mblock_t] = field(default_factory=list)
    mba: ida_hexrays.mba_t | None = None

    def __str__(self) -> str:
        """Return a human-readable representation of this dispatcher."""
        return (
            f"Dispatcher(entry={self.entry_block.serial}, "
            f"state_var={self.state_variable}, "
            f"values={len(self.comparison_values)}, "
            f"exits={len(self.exit_blocks)})"
        )


class DispatcherFinder(Protocol):
    """Protocol for services that find dispatchers in microcode.

    Different obfuscation schemes (O-LLVM, Tigress, etc.) use different
    dispatcher patterns. By defining this as a protocol, we can have
    multiple implementations without coupling to a specific pattern.

    Example implementations:
    - OLLVMDispatcherFinder: Finds O-LLVM style dispatchers
    - TigressDispatcherFinder: Finds Tigress style dispatchers
    - GenericDispatcherFinder: Uses DispatcherCache for unknown obfuscators
    """

    def find(self, context: OptimizationContext) -> List[Dispatcher]:
        """Find all dispatchers in the given microcode.

        This method analyzes the control flow graph to identify blocks
        that act as dispatchers in a control-flow flattening scheme.

        Args:
            context: The optimization context containing the mba and configuration.

        Returns:
            A list of Dispatcher objects representing found dispatchers.
            Empty list if no dispatchers are found.

        Example:
            >>> finder = OLLVMDispatcherFinder()
            >>> dispatchers = finder.find(context)
            >>> for dispatcher in dispatchers:
            ...     print(f"Found dispatcher at block {dispatcher.entry_block.serial}")
        """
        ...


@dataclass(frozen=True)
class EmulationResult:
    """Result of emulating a dispatcher with tracked state values.

    Attributes:
        target_block: The target block reached after emulation, or None if failed.
        executed_instructions: Instructions executed during emulation.
        success: Whether emulation completed successfully.
        error_message: Error message if emulation failed.
    """
    target_block: ida_hexrays.mblock_t | None
    executed_instructions: List[ida_hexrays.minsn_t] = field(default_factory=list)
    success: bool = True
    error_message: str | None = None


class PathEmulator:
    """Emulates microcode execution paths to resolve state variables.

    This service wraps the complex MopTracker and MicroCodeInterpreter logic
    into a simple, testable interface. It's responsible for determining what
    value a state variable will have when reaching a dispatcher.

    The emulation is key to unflattening: we need to know which dispatcher
    exit block will be taken for each predecessor block.

    Example:
        >>> emulator = PathEmulator()
        >>> target = emulator.resolve_target(context, pred_block, dispatcher)
        >>> print(f"Block {pred_block.serial} will jump to {target.serial}")
    """

    def resolve_target(
        self,
        context: OptimizationContext,
        from_block: ida_hexrays.mblock_t,
        dispatcher: Dispatcher
    ) -> ida_hexrays.mblock_t | None:
        """Emulate execution from from_block through the dispatcher.

        This method:
        1. Tracks the dispatcher's state variable backwards from from_block
        2. Determines its constant value (if resolvable)
        3. Emulates the dispatcher logic with that value
        4. Returns the actual target block (bypassing the dispatcher)

        Args:
            context: The optimization context.
            from_block: The predecessor block jumping to the dispatcher.
            dispatcher: The dispatcher to emulate through.

        Returns:
            The actual target block that from_block should jump to directly.
            None if the target cannot be resolved (e.g., state variable depends on input).

        Raises:
            ValueError: If emulation fails unexpectedly.

        Example:
            >>> # Before: block_5 -> dispatcher -> block_42
            >>> # After:  block_5 -> block_42 (dispatcher bypassed)
            >>> target = emulator.resolve_target(context, block_5, dispatcher)
            >>> assert target == block_42
        """
        result = self.emulate_with_history(context, from_block, dispatcher)
        return result.target_block

    def emulate_with_history(
        self,
        context: OptimizationContext,
        from_block: ida_hexrays.mblock_t,
        dispatcher: Dispatcher,
        mop_history: "MopHistory | None" = None
    ) -> EmulationResult:
        """Emulate dispatcher execution with tracked state values.

        This is the core emulation method that wraps the existing
        MicroCodeInterpreter and MicroCodeEnvironment logic.

        Args:
            context: The optimization context.
            from_block: The predecessor block to emulate from.
            dispatcher: The dispatcher to emulate through.
            mop_history: Optional pre-computed MopHistory. If None, tracking
                        is performed automatically from from_block.

        Returns:
            EmulationResult containing the target block and execution details.
        """
        from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
        from d810.hexrays.helper import format_minsn_t, format_mop_t
        from d810.hexrays.tracker import MopHistory, MopTracker

        context.logger.debug(
            "Emulating dispatcher %s from block %s",
            dispatcher.entry_block.serial,
            from_block.serial
        )

        # Step 1: Get or create MopHistory by tracking from from_block
        if mop_history is None:
            if dispatcher.state_variable is None:
                return EmulationResult(
                    target_block=None,
                    success=False,
                    error_message="Dispatcher has no state variable"
                )
            # Track the state variable backwards from from_block
            tracker = MopTracker([dispatcher.state_variable], context.mba)
            mop_history = tracker.search_backward(from_block)
            if mop_history is None:
                return EmulationResult(
                    target_block=None,
                    success=False,
                    error_message=f"Could not track state variable from block {from_block.serial}"
                )

        # Step 2: Setup the microcode environment with state variable values
        microcode_interpreter = MicroCodeInterpreter(symbolic_mode=False)
        microcode_environment = MicroCodeEnvironment()

        # Get value of the state variable from the tracked history
        state_value = mop_history.get_mop_constant_value(dispatcher.state_variable)
        if state_value is None:
            return EmulationResult(
                target_block=None,
                success=False,
                error_message=f"State variable value not resolvable from block {from_block.serial}"
            )

        # Initialize the environment with the state variable value
        microcode_environment.define(dispatcher.state_variable, state_value)

        context.logger.debug(
            "Executing dispatcher %s with: %s = %x",
            dispatcher.entry_block.serial,
            format_mop_t(dispatcher.state_variable),
            state_value
        )

        # Step 3: Emulate the dispatcher blocks
        exit_block_serials = {blk.serial for blk in dispatcher.exit_blocks}
        internal_block_serials = {blk.serial for blk in dispatcher.internal_blocks}
        all_dispatcher_serials = {dispatcher.entry_block.serial} | internal_block_serials

        instructions_executed = []
        cur_blk = dispatcher.entry_block
        cur_ins = cur_blk.head

        # Continue while in dispatcher blocks (not at an exit block)
        max_iterations = 1000  # Safety limit
        iteration = 0
        while (
            cur_blk is not None
            and cur_blk.serial in all_dispatcher_serials
            and iteration < max_iterations
        ):
            iteration += 1
            context.logger.debug(
                "  Executing: %s.%s",
                cur_blk.serial,
                format_minsn_t(cur_ins) if cur_ins else "None"
            )

            if cur_ins is None:
                break

            # Evaluate the current instruction
            is_ok = microcode_interpreter.eval_instruction(
                cur_blk, cur_ins, microcode_environment
            )
            if not is_ok:
                # Emulation could not continue - return current block
                return EmulationResult(
                    target_block=cur_blk,
                    executed_instructions=instructions_executed,
                    success=True
                )

            instructions_executed.append(cur_ins)
            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins

        if iteration >= max_iterations:
            return EmulationResult(
                target_block=None,
                executed_instructions=instructions_executed,
                success=False,
                error_message="Emulation exceeded maximum iterations"
            )

        # Return the first block that is not part of the dispatcher
        return EmulationResult(
            target_block=cur_blk,
            executed_instructions=instructions_executed,
            success=True
        )


class CFGPatcher:
    """Applies changes to the control-flow graph.

    This service encapsulates all CFG modification logic, making it easy to:
    - Test in isolation (mocking is straightforward)
    - Audit for correctness (all graph changes in one place)
    - Extend with new types of patches

    All methods are static because they don't need instance state - they
    operate purely on the provided mba and blocks.

    Implementation notes:
        This class wraps the low-level functions from d810.hexrays.cfg_utils,
        providing a clean interface that fits the composition-based architecture.
        The underlying implementations handle all the complex bookkeeping
        (predecessor/successor lists, block types, verification).
    """

    @staticmethod
    def redirect_edge(
        context: OptimizationContext,
        from_block: ida_hexrays.mblock_t,
        to_block: ida_hexrays.mblock_t
    ) -> int:
        """Redirect a block's outgoing edge to a new target.

        This is the fundamental operation for control-flow unflattening:
        changing a block that jumps to the dispatcher to instead jump
        directly to its actual target.

        Args:
            context: The optimization context.
            from_block: The block whose outgoing edge will be changed.
            to_block: The new target block.

        Returns:
            The number of changes made (typically 1 if successful, 0 if no-op).

        Raises:
            RuntimeError: If the CFG modification fails verification.

        Example:
            >>> # Unflatten: block_5 -> dispatcher -> block_42
            >>> # Becomes:   block_5 -> block_42
            >>> changes = CFGPatcher.redirect_edge(context, block_5, block_42)
        """
        from d810.hexrays.cfg_utils import (
            change_0way_block_successor,
            change_1way_block_successor,
            make_2way_block_goto,
        )

        context.logger.debug(
            "Redirecting block %s to %s",
            from_block.serial,
            to_block.serial
        )

        nsucc = from_block.nsucc()

        if nsucc == 0:
            # Block has no successors (e.g., ends with indirect jump or return)
            # We can still redirect by adding a goto
            success = change_0way_block_successor(from_block, to_block.serial)
        elif nsucc == 1:
            # Single successor - most common case
            success = change_1way_block_successor(from_block, to_block.serial)
        elif nsucc == 2:
            # Conditional block - convert to unconditional goto
            success = make_2way_block_goto(from_block, to_block.serial)
        else:
            context.logger.warning(
                "Cannot redirect block %s with %d successors",
                from_block.serial,
                nsucc
            )
            return 0

        return 1 if success else 0

    @staticmethod
    def insert_intermediate_block(
        context: OptimizationContext,
        before_block: ida_hexrays.mblock_t,
        after_block: ida_hexrays.mblock_t,
        instructions: List[ida_hexrays.minsn_t]
    ) -> ida_hexrays.mblock_t | None:
        """Insert a new block between two existing blocks.

        Sometimes the dispatcher performs computations that need to be
        preserved when unflattening. This method creates a new block
        containing those instructions and inserts it in the CFG.

        Args:
            context: The optimization context.
            before_block: The block that will jump to the new block.
            after_block: The block that the new block will jump to.
            instructions: The instructions to place in the new block.

        Returns:
            The newly created block, or None if creation failed.

        Raises:
            RuntimeError: If the CFG modification fails verification.

        Example:
            >>> # The dispatcher does: x = x + 1; jump to block_42
            >>> # We need to preserve that computation
            >>> new_blk = CFGPatcher.insert_intermediate_block(
            ...     context, block_5, block_42, [add_instruction])
        """
        from d810.hexrays.cfg_utils import (
            change_1way_block_successor,
            create_block,
        )

        context.logger.debug(
            "Inserting intermediate block between %s and %s with %d instructions",
            before_block.serial,
            after_block.serial,
            len(instructions)
        )

        # Create a new block with the instructions
        # The new block will initially point to the next block after before_block
        new_block = create_block(before_block, instructions, is_0_way=False)

        if new_block is None:
            context.logger.error(
                "Failed to create intermediate block between %s and %s",
                before_block.serial,
                after_block.serial
            )
            return None

        # Redirect the new block to point to after_block
        success = change_1way_block_successor(new_block, after_block.serial)
        if not success:
            context.logger.error(
                "Failed to redirect new block %s to %s",
                new_block.serial,
                after_block.serial
            )
            return None

        context.logger.debug(
            "Created intermediate block %s between %s and %s",
            new_block.serial,
            before_block.serial,
            after_block.serial
        )

        return new_block

    @staticmethod
    def ensure_unconditional_predecessor(
        context: OptimizationContext,
        father_block: ida_hexrays.mblock_t,
        child_block: ida_hexrays.mblock_t
    ) -> int:
        """Ensure a predecessor block has an unconditional jump to child.

        Some optimizations require that predecessor blocks end with
        unconditional jumps (goto) rather than conditional jumps.
        This method transforms the CFG to meet that requirement by
        inserting an intermediate block if necessary.

        Args:
            context: The optimization context.
            father_block: The predecessor block to check/modify.
            child_block: The child block that father should jump to unconditionally.

        Returns:
            The number of changes made (0 if already unconditional, 1 if modified).

        Raises:
            RuntimeError: If the CFG modification fails verification.

        Example:
            >>> # Before: block_5 ends with conditional jump to dispatcher
            >>> # After:  block_5 -> new_block (unconditional) -> dispatcher
            >>> changes = CFGPatcher.ensure_unconditional_predecessor(
            ...     context, block_5, dispatcher_block)
        """
        from d810.hexrays.cfg_utils import ensure_child_has_an_unconditional_father

        if father_block is None:
            return 0

        context.logger.debug(
            "Ensuring block %s has unconditional jump to block %s",
            father_block.serial,
            child_block.serial
        )

        return ensure_child_has_an_unconditional_father(father_block, child_block)

    @staticmethod
    def duplicate_block(
        context: OptimizationContext,
        block: ida_hexrays.mblock_t
    ) -> Tuple[ida_hexrays.mblock_t, ida_hexrays.mblock_t | None]:
        """Duplicate a block in the CFG.

        Creates a copy of a block at the end of the block array. If the
        original block ends with a conditional jump, also creates a
        default successor block.

        Args:
            context: The optimization context.
            block: The block to duplicate.

        Returns:
            A tuple of (duplicated_block, default_block).
            default_block is None if the original wasn't conditional.

        Raises:
            RuntimeError: If the CFG modification fails verification.

        Example:
            >>> dup, default = CFGPatcher.duplicate_block(context, dispatcher_block)
            >>> # dup is the new copy of dispatcher_block
        """
        from d810.hexrays.cfg_utils import duplicate_block

        context.logger.debug("Duplicating block %s", block.serial)

        dup_block, dup_default = duplicate_block(block)

        context.logger.debug(
            "Duplicated block %s -> %s (default: %s)",
            block.serial,
            dup_block.serial,
            dup_default.serial if dup_default else None
        )

        return dup_block, dup_default

    @staticmethod
    def clean_cfg(
        context: OptimizationContext,
        mba: ida_hexrays.mba_t,
        merge_blocks: bool = False
    ) -> int:
        """Clean up the CFG by removing empty blocks and simple gotos.

        After unflattening, the CFG may contain unnecessary blocks
        (empty blocks, simple goto chains). This method cleans them up.

        Args:
            context: The optimization context.
            mba: The microcode block array to clean.
            merge_blocks: Whether to merge consecutive blocks (can be unstable).

        Returns:
            The number of changes made.

        Note:
            The merge_blocks option calls mba.merge_blocks() which can cause
            crashes in some scenarios. Use with caution.

        Example:
            >>> changes = CFGPatcher.clean_cfg(context, mba)
        """
        from d810.hexrays.cfg_utils import mba_deep_cleaning

        context.logger.debug(
            "Cleaning CFG (merge_blocks=%s, maturity=%s)",
            merge_blocks,
            mba.maturity
        )

        return mba_deep_cleaning(mba, call_mba_combine_block=merge_blocks)


class OLLVMDispatcherFinder:
    """Finds O-LLVM style dispatchers in microcode.

    This service implements the DispatcherFinder protocol for O-LLVM style
    control-flow flattening. O-LLVM dispatchers have distinctive characteristics:

    - A central "dispatcher" block with many predecessors
    - State variable compared against multiple constant values
    - High entropy in comparison values (pseudo-random)
    - Internal blocks that only compute next state + jump back

    This implementation wraps the existing OllvmDispatcherInfo class using
    the Strangler Fig pattern, providing a clean interface while reusing
    proven logic.

    Example:
        >>> finder = OLLVMDispatcherFinder()
        >>> dispatchers = finder.find(context)
        >>> for d in dispatchers:
        ...     print(f"Found: {d}")
    """

    # Entropy thresholds for O-LLVM detection
    # Values are pseudo-random, so entropy should be ~0.5
    DEFAULT_MIN_ENTROPY = 0.3
    DEFAULT_MAX_ENTROPY = 0.7

    def __init__(
        self,
        min_entropy: float | None = None,
        max_entropy: float | None = None,
        use_dispatcher_cache: bool = True
    ):
        """Initialize the finder with optional configuration.

        Args:
            min_entropy: Minimum entropy threshold (default 0.3).
            max_entropy: Maximum entropy threshold (default 0.7).
            use_dispatcher_cache: Whether to use DispatcherCache for early filtering.
        """
        self._min_entropy = min_entropy or self.DEFAULT_MIN_ENTROPY
        self._max_entropy = max_entropy or self.DEFAULT_MAX_ENTROPY
        self._use_dispatcher_cache = use_dispatcher_cache

    def find(self, context: OptimizationContext) -> List[Dispatcher]:
        """Find all O-LLVM dispatchers in the given microcode.

        This method:
        1. Uses DispatcherCache to filter candidate blocks (if enabled)
        2. Guesses the outermost dispatcher using predecessor count
        3. Explores each candidate to validate it's a real dispatcher
        4. Converts validated dispatchers to immutable Dispatcher objects

        Args:
            context: The optimization context containing the mba.

        Returns:
            A list of Dispatcher objects. Empty if no dispatchers found.
        """
        # Lazy import to avoid circular dependencies
        from d810.optimizers.microcode.flow.flattening.unflattener import (
            OllvmDispatcherInfo,
        )
        from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
            DispatcherCache,
        )

        mba = context.mba
        dispatchers: List[Dispatcher] = []

        # Use the existing OllvmDispatcherInfo for analysis
        # This wraps the proven logic while providing a clean interface
        disp_info = OllvmDispatcherInfo(mba)

        # Step 1: Guess the outermost dispatcher block
        outmost_dispatch_num = disp_info.guess_outmost_dispatcher_blk()
        if outmost_dispatch_num == -1:
            context.logger.debug(
                "No dispatcher candidates found (guess_outmost_dispatcher_blk)"
            )
            return dispatchers

        context.logger.debug(
            f"Guessed outermost dispatcher at block {outmost_dispatch_num}"
        )

        # Step 2: Get candidate blocks using DispatcherCache
        if self._use_dispatcher_cache:
            cache = DispatcherCache.get_or_create(mba)
            analysis = cache.analyze()
            # Convert dispatcher serials to blocks
            candidate_blocks = [
                mba.get_mblock(serial) for serial in analysis.dispatchers
                if mba.get_mblock(serial) is not None
            ]
        else:
            # Brute force: check all blocks
            candidate_blocks = [
                mba.get_mblock(i) for i in range(mba.qty)
                if mba.get_mblock(i) is not None
            ]

        # Step 3: Explore each candidate to validate and extract info
        for blk in candidate_blocks:
            if blk is None:
                continue

            # Reset and explore from this block
            disp_info.outmost_dispatch_num = outmost_dispatch_num
            disp_info.last_num_in_first_blks = disp_info.get_last_blk_in_first_blks()

            # Explore validates and populates dispatcher info
            is_valid = disp_info.explore(
                blk,
                min_entropy=self._min_entropy,
                max_entropy=self._max_entropy
            )

            if is_valid:
                # Convert to immutable Dispatcher dataclass
                dispatcher = self._convert_to_dispatcher(disp_info, mba)
                if dispatcher:
                    dispatchers.append(dispatcher)
                    context.logger.info(
                        f"Found dispatcher: entry={dispatcher.entry_block.serial}, "
                        f"internal={len(dispatcher.internal_blocks)}, "
                        f"exits={len(dispatcher.exit_blocks)}"
                    )

        context.logger.info(f"Found {len(dispatchers)} O-LLVM dispatcher(s)")
        return dispatchers

    def _convert_to_dispatcher(
        self,
        disp_info: "OllvmDispatcherInfo",
        mba: ida_hexrays.mba_t
    ) -> Dispatcher | None:
        """Convert mutable OllvmDispatcherInfo to immutable Dispatcher.

        Args:
            disp_info: The dispatcher info from exploration.
            mba: The microcode array.

        Returns:
            An immutable Dispatcher dataclass, or None if conversion fails.
        """
        # Guard against invalid state
        if not disp_info.entry_block:
            return None

        entry_block = disp_info.entry_block.blk

        # Extract the state variable (mop_compared from entry block)
        state_variable = disp_info.mop_compared
        if state_variable is None:
            return None

        # Convert internal blocks from OllvmDispatcherBlockInfo to mblock_t
        internal_blocks = [
            block_info.blk
            for block_info in disp_info.dispatcher_internal_blocks
            if block_info.blk is not None
        ]

        # Convert exit blocks
        exit_blocks = [
            block_info.blk
            for block_info in disp_info.dispatcher_exit_blocks
            if block_info.blk is not None
        ]

        return Dispatcher(
            entry_block=entry_block,
            state_variable=state_variable,
            comparison_values=list(disp_info.comparison_values),
            internal_blocks=internal_blocks,
            exit_blocks=exit_blocks,
            mba=mba
        )

    def find_single(
        self,
        context: OptimizationContext,
        start_block: ida_hexrays.mblock_t
    ) -> Dispatcher | None:
        """Find a single dispatcher starting from a specific block.

        This is useful when you already know which block to analyze,
        avoiding the full scan.

        Args:
            context: The optimization context.
            start_block: The block to analyze as potential dispatcher entry.

        Returns:
            A Dispatcher if found, None otherwise.
        """
        from d810.optimizers.microcode.flow.flattening.unflattener import (
            OllvmDispatcherInfo,
        )

        mba = context.mba
        disp_info = OllvmDispatcherInfo(mba)

        # Setup and explore
        disp_info.outmost_dispatch_num = disp_info.guess_outmost_dispatcher_blk()
        disp_info.last_num_in_first_blks = disp_info.get_last_blk_in_first_blks()

        is_valid = disp_info.explore(
            start_block,
            min_entropy=self._min_entropy,
            max_entropy=self._max_entropy
        )

        if is_valid:
            return self._convert_to_dispatcher(disp_info, mba)

        return None
