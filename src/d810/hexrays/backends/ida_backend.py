"""IDA-specific CFGBackend implementation.

Wraps existing IDA infrastructure:
- lift() → Phase 3's lift(mba) from portable_cfg
- lower() → translates GraphModification → DeferredGraphModifier queue calls
- verify() → calls safe_verify(mba)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from d810.hexrays.graph_modification import (
    GraphModification,
    RedirectEdge,
    ConvertToGoto,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
)
from d810.hexrays.portable_cfg import PortableCFG, lift

if TYPE_CHECKING:
    import ida_hexrays
    from d810.hexrays.deferred_modifier import DeferredGraphModifier as DeferredGraphModifierType
    from d810.hexrays.cfg_verify import safe_verify as safe_verify_type

logger = logging.getLogger(__name__)


class IDABackend:
    """CFGBackend implementation for IDA Pro's Hex-Rays microcode.

    Translates between the portable CFG representation and IDA's
    mblock_t/mba_t structures using DeferredGraphModifier.

    Example:
        >>> backend = IDABackend()
        >>> cfg = backend.lift(mba)
        >>> modifications = [ConvertToGoto(block_serial=3, goto_target=5)]
        >>> count = backend.lower(modifications, mba)
        >>> backend.verify(mba)
        True
    """

    @property
    def name(self) -> str:
        """Unique identifier for the backend."""
        return "ida"

    def lift(self, mba: "ida_hexrays.mba_t") -> PortableCFG:
        """Convert IDA's mba_t to PortableCFG snapshot.

        Args:
            mba: IDA microcode block array to snapshot.

        Returns:
            Portable CFG snapshot capturing current topology.
        """
        return lift(mba)

    def lower(self, modifications: list[GraphModification], mba: "ida_hexrays.mba_t") -> int:
        """Apply GraphModifications to mba via DeferredGraphModifier.

        Maps each GraphModification type to the corresponding DeferredGraphModifier
        queue method:
        - RedirectEdge → queue_goto_change
        - ConvertToGoto → queue_convert_to_goto
        - InsertBlock → queue_create_and_redirect
        - RemoveEdge → (not yet implemented, logs warning and skips)
        - NopInstructions → queue_insn_nop

        Args:
            modifications: List of modification intents to apply.
            mba: IDA microcode block array to modify.

        Returns:
            Count of successfully applied modifications.

        Example:
            >>> mods = [
            ...     RedirectEdge(from_serial=10, old_target=20, new_target=30),
            ...     ConvertToGoto(block_serial=15, goto_target=25),
            ... ]
            >>> count = backend.lower(mods, mba)
            >>> count
            2
        """
        # Import here to make it patchable in tests
        from d810.hexrays import deferred_modifier

        modifier = deferred_modifier.DeferredGraphModifier(mba)

        for mod in modifications:
            match mod:
                case RedirectEdge(from_serial=src, old_target=old, new_target=new):
                    # Map to BLOCK_GOTO_CHANGE — redirect edge from old to new target
                    # Note: RedirectEdge doesn't distinguish between 1-way/2-way blocks,
                    # so we use queue_goto_change which handles 1-way blocks.
                    # For 2-way blocks, the pass should use ConvertToGoto or create
                    # a more specific modification type.
                    modifier.queue_goto_change(src, new, description=f"redirect {src}: {old}→{new}")

                case ConvertToGoto(block_serial=serial, goto_target=target):
                    # Map to BLOCK_CONVERT_TO_GOTO
                    modifier.queue_convert_to_goto(serial, target, description=f"convert {serial} to goto {target}")

                case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
                    # Map to BLOCK_CREATE_WITH_REDIRECT
                    # Note: DeferredGraphModifier expects a list of minsn_t, but InsertBlock
                    # has InsnSnapshot tuples. We need to convert them.
                    # For now, we log a warning and skip this modification type.
                    # TODO: Implement InsnSnapshot → minsn_t conversion
                    logger.warning(
                        "InsertBlock(%d→%d) requires InsnSnapshot→minsn_t conversion (not yet implemented), skipping",
                        pred, succ,
                    )
                    continue

                case RemoveEdge(from_serial=src, to_serial=dst):
                    # RemoveEdge not yet in DeferredGraphModifier
                    logger.warning(
                        "RemoveEdge(%d→%d) not implemented in DeferredGraphModifier, skipping",
                        src, dst,
                    )
                    continue

                case NopInstructions(block_serial=serial, insn_eas=eas):
                    # Map to INSN_NOP — queue_insn_nop processes one EA at a time
                    for ea in eas:
                        modifier.queue_insn_nop(serial, ea, description=f"nop {hex(ea)} in block {serial}")

                case _:
                    logger.warning("Unknown GraphModification type: %s", type(mod).__name__)
                    continue

        # Apply all queued modifications with snapshot rollback enabled
        return modifier.apply(enable_snapshot_rollback=True)

    def verify(self, mba: "ida_hexrays.mba_t") -> bool:
        """Verify mba consistency after modifications.

        Args:
            mba: IDA microcode block array to verify.

        Returns:
            True if verification passed, False if corruption detected.

        Raises:
            RuntimeError: If verification fails (propagated from safe_verify).
        """
        # Import here to make it patchable in tests
        from d810.hexrays import cfg_verify

        try:
            cfg_verify.safe_verify(mba, "IDABackend.verify()")
            return True
        except RuntimeError:
            return False


__all__ = ["IDABackend"]
