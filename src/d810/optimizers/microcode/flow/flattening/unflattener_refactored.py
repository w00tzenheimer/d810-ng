"""Refactored control-flow unflattening using composable services.

This module demonstrates the composition-based approach to control-flow
unflattening. Instead of a 700-line God object that does everything, we
have a clean coordinator that delegates to specialized services.

Compare this to the original GenericDispatcherUnflatteningRule to see
the dramatic improvement in clarity and testability.
"""

from __future__ import annotations

from typing import List

import ida_hexrays

from d810.core import getLogger
from d810.optimizers.core import OptimizationContext, OptimizationRule
from d810.optimizers.microcode.flow.flattening.services import (
    CFGPatcher,
    Dispatcher,
    DispatcherFinder,
    PathEmulator,
)

logger = getLogger("D810.unflat_refactored")


class UnflattenerRule:
    """Removes control-flow flattening using composable services.

    This class is a **coordinator** - it doesn't do the work itself, but
    orchestrates specialized services to accomplish the unflattening.

    Key differences from the original GenericDispatcherUnflatteningRule:
    - **Composition over inheritance**: Uses services instead of inheriting behavior
    - **Dependency injection**: Services are provided in __init__, enabling testing
    - **Single responsibility**: Only coordinates; doesn't find, emulate, or patch
    - **Stateless**: Uses OptimizationContext instead of instance variables
    - **Testable**: Easy to mock dependencies and verify behavior

    Architecture:
        UnflattenerRule (coordinator)
            |
            +-- DispatcherFinder (finds flattened dispatchers)
            |
            +-- PathEmulator (resolves state variables via emulation)
            |
            +-- CFGPatcher (modifies the control flow graph)

    Example:
        >>> finder = OLLVMDispatcherFinder()
        >>> emulator = PathEmulator()
        >>> patcher = CFGPatcher()
        >>> rule = UnflattenerRule(finder, emulator, patcher)
        >>>
        >>> # Apply the rule
        >>> changes = rule.apply(context, entry_block)
    """

    name = "ControlFlowUnflattener"
    description = "Removes O-LLVM style control-flow flattening obfuscation"

    def __init__(
        self,
        finder: DispatcherFinder,
        emulator: PathEmulator | None = None,
        patcher: CFGPatcher | None = None
    ):
        """Initialize the unflattener with its dependencies.

        Args:
            finder: The service responsible for finding dispatchers.
            emulator: The service for resolving state variables (default: PathEmulator()).
            patcher: The service for modifying the CFG (default: CFGPatcher()).

        Example:
            >>> # Production code uses real implementations
            >>> rule = UnflattenerRule(OLLVMDispatcherFinder())
            >>>
            >>> # Test code can inject mocks
            >>> mock_finder = Mock(spec=DispatcherFinder)
            >>> rule = UnflattenerRule(mock_finder)
        """
        self._finder = finder
        self._emulator = emulator or PathEmulator()
        self._patcher = patcher or CFGPatcher()

    def apply(self, context: OptimizationContext, blk: ida_hexrays.mblock_t) -> int:
        """Apply control-flow unflattening to the microcode.

        This is the main entry point. The logic is simple and readable:
        1. Find all dispatchers
        2. For each dispatcher, unflatten all predecessor blocks
        3. Return the total number of changes

        Args:
            context: The optimization context.
            blk: The microcode block (typically the entry block).

        Returns:
            The number of changes made (edges redirected).

        Example:
            >>> changes = rule.apply(context, mba.get_mblock(0))
            >>> print(f"Unflattened {changes} control flow edges")
        """
        # Only process at the entry block to avoid redundant work
        if blk.serial != 0:
            return 0

        total_changes = 0

        # Step 1: Find all dispatchers
        dispatchers = self._finder.find(context)

        if not dispatchers:
            logger.info("No dispatchers found - function not flattened")
            return 0

        logger.info(f"Found {len(dispatchers)} dispatcher(s)")

        # Step 2: Process each dispatcher
        for dispatcher in dispatchers:
            changes = self._unflatten_dispatcher(context, dispatcher)
            total_changes += changes
            logger.info(
                f"Dispatcher at block {dispatcher.entry_block.serial}: "
                f"{changes} edges unflattened"
            )

        logger.info(f"Total: {total_changes} control flow edges simplified")
        return total_changes

    def _unflatten_dispatcher(
        self,
        context: OptimizationContext,
        dispatcher: Dispatcher
    ) -> int:
        """Unflatten a single dispatcher by redirecting all its predecessors.

        For each block that jumps to the dispatcher:
        1. Resolve where it will actually go (emulate through dispatcher)
        2. Redirect it to jump there directly (bypass dispatcher)

        Args:
            context: The optimization context.
            dispatcher: The dispatcher to unflatten.

        Returns:
            The number of edges redirected for this dispatcher.
        """
        changes = 0

        # Get all blocks that jump to this dispatcher
        predecessor_serials = list(dispatcher.entry_block.predset)

        for pred_serial in predecessor_serials:
            pred_block = context.mba.get_mblock(pred_serial)

            try:
                # Ensure the predecessor is in a form we can work with
                changes += self._patcher.ensure_unconditional_predecessor(
                    context,
                    dispatcher.entry_block
                )

                # Emulate to find where this predecessor actually goes
                target_block = self._emulator.resolve_target(
                    context,
                    pred_block,
                    dispatcher
                )

                if target_block is None:
                    logger.warning(
                        f"Could not resolve target for block {pred_serial} "
                        f"through dispatcher at {dispatcher.entry_block.serial}"
                    )
                    continue

                # Redirect the edge to bypass the dispatcher
                changes += self._patcher.redirect_edge(
                    context,
                    pred_block,
                    target_block
                )

                logger.debug(
                    f"Unflattened: block {pred_serial} now jumps directly to "
                    f"block {target_block.serial} (bypassing dispatcher)"
                )

            except Exception as e:
                logger.warning(
                    f"Failed to unflatten block {pred_serial}: {e}",
                    exc_info=True
                )
                continue

        return changes


# Example of how to create a concrete implementation
class OLLVMDispatcherFinderStub:
    """Stub implementation of DispatcherFinder for O-LLVM patterns.

    This is a placeholder showing the structure. The real implementation
    would use the logic from GenericDispatcherCollector and GenericDispatcherInfo.

    TODO: Extract the actual dispatcher finding logic from the monolithic
    GenericDispatcherUnflatteningRule into this class.
    """

    def find(self, context: OptimizationContext) -> List[Dispatcher]:
        """Find O-LLVM style dispatchers.

        O-LLVM dispatchers typically have:
        - A switch/jtbl instruction
        - A state variable being compared
        - Multiple exit blocks
        - A specific pattern of predecessors

        Returns:
            List of found dispatchers (currently empty - stub implementation).
        """
        logger.debug("Searching for O-LLVM style dispatchers...")
        # TODO: Implement using logic from GenericDispatcherCollector
        return []


# Comparison to show the improvement
"""
BEFORE (GenericDispatcherUnflatteningRule):
- 700+ lines in one class
- Mixes finding, emulating, patching, and orchestration
- Uses mutable instance variables (self.mba, self.cur_maturity, etc.)
- Hard to test (need real IDA environment)
- Hard to understand (too much happening in one place)
- Hard to extend (adding new dispatcher patterns is complex)

AFTER (UnflattenerRule):
- ~100 lines in the coordinator
- Each service has a single responsibility
- Uses immutable OptimizationContext
- Easy to test (inject mocks for services)
- Easy to understand (each method does one thing)
- Easy to extend (implement a new DispatcherFinder for different obfuscators)

Testing the old way:
- Need a full IDA environment
- Need actual obfuscated binaries
- Tests are slow and brittle
- Can't test individual components

Testing the new way:
- Mock the DispatcherFinder to return test dispatchers
- Mock the PathEmulator to return specific targets
- Mock the CFGPatcher to verify correct calls
- Fast, isolated unit tests
- Can test edge cases easily

Example test:
    def test_unflatten_single_dispatcher():
        # Arrange: Create mocks
        mock_dispatcher = Dispatcher(entry_block=..., ...)
        mock_finder = Mock(spec=DispatcherFinder)
        mock_finder.find.return_value = [mock_dispatcher]

        mock_emulator = Mock(spec=PathEmulator)
        mock_emulator.resolve_target.return_value = target_block

        mock_patcher = Mock(spec=CFGPatcher)
        mock_patcher.redirect_edge.return_value = 1

        # Act: Run the rule
        rule = UnflattenerRule(mock_finder, mock_emulator, mock_patcher)
        changes = rule.apply(context, entry_block)

        # Assert: Verify behavior
        assert changes == 1
        mock_emulator.resolve_target.assert_called_once()
        mock_patcher.redirect_edge.assert_called_once()
"""
