"""PoisonInjectionStrategy -- UNUSED/DORMANT strategy preserved for future reference.

This strategy was extracted from DirectHandlerLinearizationStrategy (commit 4e7637b5)
where it replaced plain NOP of state variable writes with zero-writes (``m_mov #0,
state_var``) and injected terminal-path poison to kill entry-state liveness.

The approach was reverted because replacing one wrong value (the obfuscated state
constant) with another wrong value (zero) is semantically incorrect -- it trades
leaked dispatcher constants for leaked zeros.  The correct fix is transitive NOP of
downstream state variable reads (future work).

This module is NOT registered in ``ALL_STRATEGIES`` and has no effect on execution.
It is preserved so the zero-write + poison infrastructure can be re-activated if
a correct liveness-kill strategy is designed.

Infrastructure dependencies (kept intact, dead unless called):
- ``ZeroStateWrite`` in ``d810.cfg.graph_modification``
- ``PatchZeroStateWrite`` in ``d810.cfg.plan``
- ``INSN_ZERO_STATE_WRITE`` / ``queue_zero_state_write`` / ``_apply_zero_state_write``
  in ``d810.hexrays.mutation.deferred_modifier``
- ``PatchZeroStateWrite`` translator case in ``d810.hexrays.mutation.ir_translator``
- ``zero_state_write()`` bridge method in ``hodur._modification_bridge``
"""
from __future__ import annotations

import ida_hexrays
from d810.core import logging

logger = logging.getLogger("D810.hodur.strategy.poison_injection")

__all__ = ["PoisonInjectionStrategy"]


class PoisonInjectionStrategy:
    """DORMANT: Zero-write state variable writes and inject terminal-path poison.

    This strategy was designed to:

    1. Replace state variable NOP instructions with ``m_mov #0, state_var``
       (zero-writes) so that IDA's later passes see a defined value instead of
       a dead instruction, preventing entry-state constant propagation into
       return expressions.

    2. Inject ``m_mov #0, state_var`` (poison) before the tail of terminal
       blocks on early-exit paths where the handler never writes a new state
       value, killing liveness of the state variable.

    Both approaches were found to be semantically incorrect: they replace
    leaked obfuscated constants with leaked zeros, which is no better.

    The methods below are preserved verbatim from the original implementation
    for reference and potential future adaptation.
    """

    @staticmethod
    def append_zero_state_write(
        builder: object,
        modifications: list,
        source_block: int,
        instruction_ea: int,
    ) -> None:
        """Replace state variable write source with #0 instead of NOPing.

        Args:
            builder: A ``ModificationBuilder`` instance.
            modifications: Accumulator list for graph modifications.
            source_block: Serial number of the block containing the write.
            instruction_ea: EA of the instruction to zero.
        """
        modifications.append(
            builder.zero_state_write(  # type: ignore[attr-defined]
                source_block=source_block,
                instruction_ea=instruction_ea,
            )
        )

    @staticmethod
    def inject_state_var_poison(
        mba: object,
        state_var_stkoff: int,
        exit_serial: int,
        handler_serial: int,
        incoming_state: int,
        poisoned_blocks: set[int],
        ordered_path: list[int] | None = None,
    ) -> bool:
        """Inject ``m_mov #0, state_var`` before the tail of a terminal block.

        This kills the liveness of the state variable on early-exit paths
        where the handler never writes a new state value.  Without this,
        IDA's later passes propagate the handler's entry-state constant
        (e.g. 0x41FB8FBB) into ``return`` expressions.

        If the exit block has no tail (shared epilogue corridor), walk
        backward through *ordered_path* to find the last block with a
        valid tail instruction and inject there instead.

        Args:
            mba: The ``mba_t`` object for the current function.
            state_var_stkoff: Stack offset of the state variable.
            exit_serial: Serial of the exit block.
            handler_serial: Serial of the handler entry block.
            incoming_state: The handler's entry state constant.
            poisoned_blocks: Mutable set tracking already-poisoned block serials.
            ordered_path: Optional DFS path for fallback injection target.

        Returns:
            True if the poison was injected, False otherwise.
        """
        target_serial = exit_serial
        target_blk = None
        try:
            target_blk = mba.get_mblock(target_serial)  # type: ignore[attr-defined]
        except Exception:
            target_blk = None

        if (target_blk is None or target_blk.tail is None) and ordered_path:
            for blk_serial in reversed(ordered_path):
                try:
                    candidate = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
                except Exception:
                    continue
                if candidate is not None and candidate.tail is not None:
                    target_serial = blk_serial
                    target_blk = candidate
                    break

        if target_serial in poisoned_blocks:
            return False

        if target_blk is None or target_blk.tail is None:
            logger.warning(
                "STATE_VAR_POISON: handler=blk[%d] exit=blk[%d] — "
                "no block with tail found in path",
                handler_serial, exit_serial,
            )
            return False

        if target_serial != exit_serial:
            logger.info(
                "STATE_VAR_POISON: handler=blk[%d] path_block=blk[%d] "
                "(exit=blk[%d] had no tail)",
                handler_serial, target_serial, exit_serial,
            )

        ea = target_blk.tail.ea
        poison = ida_hexrays.minsn_t(ea)
        poison.opcode = ida_hexrays.m_mov
        poison.l = ida_hexrays.mop_t()
        poison.l.make_number(0, 4, ea)
        poison.d = ida_hexrays.mop_t()
        poison.d.erase()
        poison.d._make_stkvar(mba, state_var_stkoff)  # type: ignore[attr-defined]
        poison.d.size = 4

        target_blk.insert_into_block(poison, target_blk.tail)
        poisoned_blocks.add(target_serial)
        logger.info(
            "STATE_VAR_POISON: handler=blk[%d] exit=blk[%d] "
            "entry_state=0x%x — injected m_mov #0 to kill liveness",
            handler_serial, exit_serial, incoming_state,
        )
        return True
