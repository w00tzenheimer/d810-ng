"""IDA-specific CFGBackend implementation.

Wraps existing IDA infrastructure:
- lift() -> flowgraph snapshot lift(mba)
- lower() -> materializes PatchPlan -> DeferredGraphModifier queue calls
- verify() -> calls safe_verify(mba)
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING

from d810.cfg.graph_modification import (
    GraphModification,
    RedirectGoto,
    RedirectBranch,
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
)
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
from d810.cfg.plan import (
    LegacyBlockOperation,
    PatchConvertToGoto,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRemoveEdge,
    PatchStep,
)
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.mop_snapshot import MopSnapshot

if TYPE_CHECKING:
    import ida_hexrays
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier as DeferredGraphModifierType
    from d810.hexrays.mutation.cfg_verify import safe_verify as safe_verify_type

logger = getLogger(__name__)

import ida_hexrays


def lift_block(blk: "ida_hexrays.mblock_t") -> BlockSnapshot:
    serial = blk.serial
    block_type = blk.type
    flags = blk.flags
    start_ea = blk.start

    succs = get_succ_serials(blk)
    preds = get_pred_serials(blk)

    insn_snapshots = []
    insn = blk.head
    while insn:
        opcode = insn.opcode
        ea = insn.ea

        operands = tuple(
            MopSnapshot.from_mop(mop)
            for mop in (insn.l, insn.r, insn.d)
            if mop.t != ida_hexrays.mop_z  # type: ignore[attr-defined]
        )

        insn_snapshots.append(InsnSnapshot(opcode=opcode, ea=ea, operands=operands))
        insn = insn.next

    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=flags,
        start_ea=start_ea,
        insn_snapshots=tuple(insn_snapshots),
    )


def lift(mba: "ida_hexrays.mba_t") -> FlowGraph:
    blocks = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        blocks[blk.serial] = lift_block(blk)

    return FlowGraph(
        blocks=blocks,
        entry_serial=0,
        func_ea=mba.entry_ea,
        metadata={"maturity": mba.maturity},
    )



class IDAIRTranslator:
    """CFGBackend implementation for IDA Pro's Hex-Rays microcode.

    Translates between the FlowGraph representation and IDA's
    mblock_t/mba_t structures using DeferredGraphModifier.

    Example:
        >>> backend = IDAIRTranslator()
        >>> cfg = backend.lift(mba)
        >>> modifications = [ConvertToGoto(block_serial=3, goto_target=5)]
        >>> count = backend.lower(modifications, mba)
        >>> backend.verify(mba)
        True
    """

    def __init__(self, *, allow_legacy_block_creation: bool = True) -> None:
        self.allow_legacy_block_creation = allow_legacy_block_creation

    @property
    def name(self) -> str:
        """Unique identifier for the backend."""
        return "ida"

    def lift(self, mba: "ida_hexrays.mba_t") -> FlowGraph:
        """Convert IDA's mba_t to FlowGraph snapshot.

        Args:
            mba: IDA microcode block array to snapshot.

        Returns:
            FlowGraph snapshot capturing current topology.
        """
        return lift(mba)

    def lower(self, patch_plan: PatchPlan, mba: "ida_hexrays.mba_t") -> int:
        """Apply a PatchPlan to mba via DeferredGraphModifier.

        ``PatchPlan`` concrete operations are lowered directly. Block-creating
        edits remain explicit legacy fallback steps until symbolic block
        materialization is implemented. Those steps can be rejected before any
        live mutation when ``allow_legacy_block_creation`` is disabled.

        Args:
            patch_plan: Finalized backend execution plan.
            mba: IDA microcode block array to modify.

        Returns:
            Count of successfully applied modifications.

        Example:
            >>> patch_plan = PatchPlan(
            ...     steps=(PatchRedirectGoto(from_serial=10, old_target=20, new_target=30),)
            ... )
            >>> count = backend.lower(patch_plan, mba)
            >>> count
            1
        """
        # Import here to make it patchable in tests
        from d810.hexrays.mutation import deferred_modifier

        if not isinstance(patch_plan, PatchPlan):
            raise TypeError(
                "IDAIRTranslator.lower() now requires PatchPlan; "
                "compile GraphModification lists before lowering"
            )
        if patch_plan.contains_block_creation and not self.allow_legacy_block_creation:
            logger.warning(
                "PatchPlan contains %d block-creating steps but legacy block creation is disabled",
                len(patch_plan.legacy_block_operations),
            )
            return 0

        modifier = deferred_modifier.DeferredGraphModifier(mba)

        if patch_plan.contains_block_creation:
            logger.info(
                "Lowering PatchPlan with %d concrete ops and %d legacy block-creating steps",
                len(patch_plan.concrete_operations),
                len(patch_plan.legacy_block_operations),
            )

        for step in patch_plan.steps:
            self._queue_patch_step(modifier, step)

        # Apply all queued modifications with snapshot rollback enabled
        result_count = modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=True,
            rollback_on_verify_failure=True,
            continue_on_verify_failure=True,
            enable_snapshot_rollback=True,
        )

        # If verify failed (even after rollback attempt), signal the pipeline
        # to stop by returning 0. A positive result with verify_failed=True
        # means rollback also failed - the MBA may be corrupted.
        if modifier.verify_failed:
            logger.warning(
                "DeferredGraphModifier.verify_failed is set after apply; "
                "returning 0 to prevent pipeline from treating changes as successful"
            )
            return 0

        return result_count

    def _queue_patch_step(
        self,
        modifier: "DeferredGraphModifierType",
        step: PatchStep,
    ) -> None:
        match step:
            case PatchRedirectGoto(from_serial=src, old_target=old, new_target=new):
                modifier.queue_goto_change(
                    src,
                    new,
                    description=f"redirect goto {src}: {old}->{new}",
                )

            case PatchRedirectBranch(from_serial=src, old_target=old, new_target=new):
                modifier.queue_conditional_target_change(
                    src,
                    new,
                    description=f"redirect branch {src}: {old}->{new}",
                )

            case PatchConvertToGoto(block_serial=serial, goto_target=target):
                modifier.queue_convert_to_goto(
                    serial,
                    target,
                    description=f"convert {serial} to goto {target}",
                )

            case PatchRemoveEdge(from_serial=src, to_serial=dst):
                logger.warning(
                    "PatchRemoveEdge(%d->%d) not implemented in DeferredGraphModifier, skipping",
                    src,
                    dst,
                )

            case PatchNopInstructions(block_serial=serial, insn_eas=eas):
                for ea in eas:
                    modifier.queue_insn_nop(
                        serial,
                        ea,
                        description=f"nop {hex(ea)} in block {serial}",
                    )

            case LegacyBlockOperation(modification=mod):
                self._queue_legacy_block_operation(modifier, mod)

            case _:
                logger.warning("Unknown PatchPlan step type: %s", type(step).__name__)

    def _queue_legacy_block_operation(
        self,
        modifier: "DeferredGraphModifierType",
        modification: GraphModification,
    ) -> None:
        match modification:
            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                rule_priority=priority,
            ):
                modifier.queue_edge_redirect(
                    src_block=src,
                    old_target=old,
                    new_target=new,
                    via_pred=pred,
                    rule_priority=priority,
                    description=f"edge redirect via pred split: pred={pred} src={src} {old}->{new}",
                )

            case CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=cond_target,
                fallthrough_target=fallthrough_target,
            ):
                modifier.queue_create_conditional_redirect(
                    source_blk_serial=src,
                    ref_blk_serial=ref,
                    conditional_target_serial=cond_target,
                    fallthrough_target_serial=fallthrough_target,
                    description=(
                        f"create conditional redirect src={src} ref={ref} "
                        f"cond={cond_target} fallthrough={fallthrough_target}"
                    ),
                )

            case DuplicateBlock(source_block=src, target_block=target, pred_serial=pred):
                logger.warning(
                    "DuplicateBlock(source=%d, target=%s, pred=%s) not implemented, skipping",
                    src,
                    target,
                    pred,
                )

            case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
                logger.warning(
                    "InsertBlock(%d->%d) requires InsnSnapshot->minsn_t conversion (not yet implemented), skipping",
                    pred,
                    succ,
                )

            case _:
                logger.warning("Unsupported legacy block operation: %s", type(modification).__name__)

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
        from d810.hexrays.mutation import cfg_verify

        try:
            cfg_verify.safe_verify(mba, "IDAIRTranslator.verify()")
            return True
        except RuntimeError:
            return False


__all__ = ["IDAIRTranslator", "lift", "lift_block"]
