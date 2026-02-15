"""CFGPass that fixes fake/opaque jumps by redirecting edges to correct targets.

This pass migrates the CFG-level edge redirection logic from UnflattenerFakeJump
(src/d810/optimizers/microcode/flow/flattening/unflattener_fake_jump.py) into
the CFGPass framework.

UnflattenerFakeJump uses MopTracker symbolic execution to determine if conditional
jumps are always/never taken, then redirects predecessors to the correct target.
This pass handles the **structural** CFG transformation: redirecting edges based
on pre-computed analysis results.

Two types of redirects:
1. **2-way blocks**: Redirect one branch of a conditional to the correct target
   (e.g., block 10 has succs (20, 30), analysis shows it always goes to 20,
   so redirect edge 10→30 to 10→20)
2. **1-way blocks**: Redirect unconditional goto to correct target
   (e.g., block 5 has succ (10), analysis shows it should go to 20,
   so redirect edge 5→10 to 5→20)

Example:
    >>> # Pre-computed mode: MopTracker determined block 10 always goes to 20
    >>> fixes = {10: 20}  # block_serial → correct_target
    >>> pass_instance = FakeJumpFixerPass(fixes=fixes)
    >>> mods = pass_instance.transform(cfg)
    >>> len(mods)
    1
    >>> isinstance(mods[0], RedirectEdge)
    True
"""
from __future__ import annotations

from d810.hexrays.cfg_pass import CFGPass
from d810.hexrays.graph_modification import GraphModification, RedirectEdge
from d810.hexrays.portable_cfg import PortableCFG


class FakeJumpFixerPass(CFGPass):
    """Redirect edges for fake/opaque jumps based on pre-computed analysis.

    This pass applies pre-computed fake jump fixes (determined by MopTracker
    symbolic execution) as CFG edge redirections.

    The existing UnflattenerFakeJump combines:
    1. MopTracker symbolic execution (analysis phase)
    2. CFG-level edge rewiring (change_1way_block_successor)

    This pass extracts the CFG-level orchestration (#2). The analysis phase (#1)
    remains in the IDA-specific orchestrator.

    Attributes:
        name: Unique identifier "fake_jump_fixer".
        tags: Frozen set containing "unflattening" and "cleanup" tags.

    Example:
        >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
        >>> # Block 5 is a 2-way conditional with fake/opaque jump
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
        >>> # Analysis determined block 5's condition always goes to 10 (never 20)
        >>> fixes = {5: 10}
        >>> pass_instance = FakeJumpFixerPass(fixes=fixes)
        >>> mods = pass_instance.transform(cfg)
        >>> len(mods)
        1
        >>> mods[0].from_serial
        5
        >>> mods[0].new_target
        10
    """
    name = "fake_jump_fixer"
    tags = frozenset({"unflattening", "cleanup"})

    def __init__(self, fixes: dict[int, int] | None = None):
        """Initialize with pre-computed fixes mapping block_serial → correct target.

        Args:
            fixes: Mapping from block serial to correct target serial. When a
                block has a fake/opaque jump, this maps the block serial to the
                single correct target (redirecting the fake edge).
                If None, pass does nothing.

        Example:
            >>> # Block 10 always goes to 25 (never 30)
            >>> pass_instance = FakeJumpFixerPass(fixes={10: 25})
            >>> pass_instance._fixes
            {10: 25}
        """
        self._fixes = fixes or {}

    def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        """Analyze CFG and return RedirectEdge for fake/opaque jumps.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of RedirectEdge modifications for blocks where:
            - Block serial exists in pre-computed fixes
            - Block exists in the CFG
            - Block has an edge that needs redirection
            Empty list if no fixes or all fixes reference nonexistent blocks.

        Example:
            >>> from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
            >>> blk5 = BlockSnapshot(
            ...     serial=5, block_type=2, succs=(10, 20), preds=(),
            ...     flags=0, start_ea=0x1000, insn_snapshots=()
            ... )
            >>> cfg = PortableCFG(blocks={5: blk5}, entry_serial=5, func_ea=0x1000)
            >>> # Fix for existing block
            >>> pass_instance = FakeJumpFixerPass(fixes={5: 10})
            >>> mods = pass_instance.transform(cfg)
            >>> len(mods)
            1
            >>> mods[0].from_serial
            5
            >>> mods[0].new_target
            10
            >>> # Fix for nonexistent block is skipped
            >>> pass_instance2 = FakeJumpFixerPass(fixes={99: 20})
            >>> mods2 = pass_instance2.transform(cfg)
            >>> len(mods2)
            0
        """
        mods: list[GraphModification] = []
        for block_serial, correct_target in self._fixes.items():
            blk = cfg.blocks.get(block_serial)
            if blk is None:
                continue

            # Determine old target to redirect from
            if blk.nsucc == 2:
                # 2-way: redirect the branch that doesn't match correct_target
                for old_target in blk.succs:
                    if old_target != correct_target:
                        mods.append(RedirectEdge(block_serial, old_target, correct_target))
                        break
            elif blk.nsucc == 1 and blk.succs[0] != correct_target:
                # 1-way: redirect if current target differs from correct_target
                mods.append(RedirectEdge(block_serial, blk.succs[0], correct_target))

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
            >>> pass_instance = FakeJumpFixerPass(fixes={})
            >>> pass_instance.is_applicable(cfg)
            False
            >>> # Non-empty fixes: applicable
            >>> pass_instance2 = FakeJumpFixerPass(fixes={5: 10})
            >>> pass_instance2.is_applicable(cfg)
            True
        """
        return bool(self._fixes)


__all__ = ["FakeJumpFixerPass"]
