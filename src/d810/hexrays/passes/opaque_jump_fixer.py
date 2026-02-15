"""CFGPass that fixes opaque predicates by converting conditionals to unconditional gotos.

This pass migrates the CFG-level jump fixing logic from JumpFixer
(src/d810/optimizers/microcode/flow/jumps/handler.py) into the CFGPass framework.

The individual rules (JnzRule1-8, JbRule1, etc.) are instruction-level pattern
matchers that identify opaque predicates. Those stay as InstructionOptimizationRule.
This pass handles the **structural** CFG transformation: converting 2-way conditional
blocks to 1-way unconditional gotos when the condition is provably opaque.

Two modes:
1. **Pre-computed fixes**: Pass a dict mapping block_serial → correct_target_serial.
   The pass emits ConvertToGoto for each entry.
2. **Structural detection** (future): Detect constant-foldable conditions on PortableCFG.

Example:
    >>> # Pre-computed mode: rule analysis determined block 10 should goto 20
    >>> fixes = {10: 20}
    >>> pass_instance = OpaqueJumpFixerPass(fixes=fixes)
    >>> mods = pass_instance.transform(cfg)
    >>> len(mods)
    1
    >>> mods[0].block_serial
    10
    >>> mods[0].goto_target
    20
"""
from __future__ import annotations

from d810.hexrays.cfg_pass import CFGPass
from d810.hexrays.graph_modification import ConvertToGoto, GraphModification
from d810.hexrays.portable_cfg import PortableCFG


class OpaqueJumpFixerPass(CFGPass):
    """Convert 2-way blocks with opaque predicates to 1-way unconditional gotos.

    This pass applies pre-computed opaque predicate fixes (determined by
    instruction-level analysis) as CFG modifications.

    The existing JumpFixer (src/d810/optimizers/microcode/flow/jumps/handler.py)
    combines:
    1. Instruction-level pattern matching (JumpOptimizationRule subclasses)
    2. CFG-level edge rewiring (make_2way_block_goto)

    This pass extracts the CFG-level orchestration (#2). The instruction-level
    analysis (#1) remains in JumpOptimizationRule for now, but can be migrated
    to a separate analysis pass in the future.

    Attributes:
        name: Unique identifier "opaque_jump_fixer".
        tags: Frozen set containing "deobfuscation" and "jump" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
        >>> # Block 5 is a 2-way conditional with opaque predicate
        >>> blk5 = BlockSnapshot(
        ...     serial=5, block_type=2, succs=(10, 20), preds=(),
        ...     flags=0, start_ea=0x1000, insn_snapshots=()
        ... )
        >>> blk10 = BlockSnapshot(
        ...     serial=10, block_type=1, succs=(99,), preds=(5,),
        ...     flags=0, start_ea=0x2000, insn_snapshots=()
        ... )
        >>> blk20 = BlockSnapshot(
        ...     serial=20, block_type=1, succs=(99,), preds=(5,),
        ...     flags=0, start_ea=0x3000, insn_snapshots=()
        ... )
        >>> cfg = PortableCFG(
        ...     blocks={5: blk5, 10: blk10, 20: blk20},
        ...     entry_serial=5, func_ea=0x1000
        ... )
        >>> # Analysis determined block 5's condition is always-true (jump taken)
        >>> fixes = {5: 10}
        >>> pass_instance = OpaqueJumpFixerPass(fixes=fixes)
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].block_serial
        5
        >>> mods[0].goto_target
        10
    """
    name = "opaque_jump_fixer"
    tags = frozenset({"deobfuscation", "jump"})

    def __init__(self, fixes: dict[int, int] | None = None):
        """Initialize with pre-computed fixes mapping block_serial → correct target.

        Args:
            fixes: Mapping from block serial to target serial. When a 2-way
                conditional block has an opaque predicate, this maps the block
                serial to the single correct target (removing the dead branch).
                If None, pass does structural detection (not yet implemented).

        Example:
            >>> # Block 10 should always goto 25 (condition is always-true)
            >>> pass_instance = OpaqueJumpFixerPass(fixes={10: 25})
            >>> pass_instance._fixes
            {10: 25}
        """
        self._fixes = fixes or {}

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return ConvertToGoto for opaque conditional jumps.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of ConvertToGoto modifications for blocks where:
            - Block serial exists in pre-computed fixes
            - Block exists in the CFG
            Empty list if no fixes or all fixes reference nonexistent blocks.

        Example:
            >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
            >>> blk5 = BlockSnapshot(
            ...     serial=5, block_type=2, succs=(10, 20), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
            >>> # Fix for existing block
            >>> pass_instance = OpaqueJumpFixerPass(fixes={5: 10})
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            1
            >>> mods[0].block_serial
            5
            >>> mods[0].goto_target
            10
            >>> # Fix for nonexistent block is skipped
            >>> pass_instance2 = OpaqueJumpFixerPass(fixes={99: 10})
            >>> mods2 = pass_instance2.transform(cfg)
            >>> len(mods2)
            0
        """
        mods = []
        for serial, target in self._fixes.items():
            # Skip fixes for blocks that don't exist in the CFG snapshot
            if serial in cfg.blocks:
                mods.append(ConvertToGoto(block_serial=serial, goto_target=target))
        return mods

    def is_applicable(self, cfg: PortableCFG) -> bool:
        """Check if this pass should run on the given CFG.

        Args:
            cfg: Portable CFG snapshot to check.

        Returns:
            True if there are any pre-computed fixes, False otherwise.

        Example:
            >>> from d810.hexrays.portable_cfg import PortableCFG
            >>> cfg = PortableCFG(blocks={}, entry_serial=0, func_ea=0x1000)
            >>> # Empty fixes: not applicable
            >>> pass_instance = OpaqueJumpFixerPass(fixes={})
            >>> pass_instance.is_applicable(cfg)
            False
            >>> # Non-empty fixes: applicable
            >>> pass_instance2 = OpaqueJumpFixerPass(fixes={5: 10})
            >>> pass_instance2.is_applicable(cfg)
            True
        """
        return bool(self._fixes)


__all__ = ["OpaqueJumpFixerPass"]
