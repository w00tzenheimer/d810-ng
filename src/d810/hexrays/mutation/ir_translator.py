"""IDA-specific CFGBackend implementation.

Wraps existing IDA infrastructure:
- lift() -> flowgraph snapshot lift(mba)
- lower() -> materializes PatchPlan -> DeferredGraphModifier queue calls
- verify() -> calls safe_verify(mba)
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING, Callable

from d810.cfg.contracts.ida_contract import CfgContractViolationError, IDACfgContract

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
from d810.cfg.flowgraph import MopSnapshot as CfgMopSnapshot
from d810.cfg.plan import (
    LegacyBlockOperation,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchNopInstructions,
    PatchZeroStateWrite,
    PatchPlan,
    PatchPrivateTerminalSuffix,
    PatchPrivateTerminalSuffixGroup,
    PatchDirectTerminalLoweringGroup,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRemoveEdge,
    PatchStep,
)
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.mutation.insn_snapshot_materializer import validate_insn_snapshots

if TYPE_CHECKING:
    import ida_hexrays
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier as DeferredGraphModifierType
    from d810.hexrays.mutation.cfg_verify import safe_verify as safe_verify_type

logger = getLogger(__name__)

import ida_hexrays


def capture_mop_snapshot(mop: "ida_hexrays.mop_t") -> CfgMopSnapshot | None:
    """Capture a lightweight ``CfgMopSnapshot`` from a live ``mop_t``.

    Returns ``None`` for empty (``mop_z``) operands.
    """
    if mop is None or mop.t == 0:  # mop_z = empty
        return None
    t = mop.t
    size = mop.size
    if t == 2:  # mop_n
        nnn = mop.nnn
        return CfgMopSnapshot(t=t, size=size, value=int(nnn.value) if nnn is not None else 0)
    if t == 3:  # mop_S / mop_str (stack var)
        s = mop.s
        return CfgMopSnapshot(t=t, size=size, stkoff=s.off if s is not None else None)
    if t == 1:  # mop_r (register)
        return CfgMopSnapshot(t=t, size=size, reg=mop.r)
    if t == 7:  # mop_b (block ref)
        return CfgMopSnapshot(t=t, size=size, block_ref=mop.b)
    return CfgMopSnapshot(t=t, size=size)


def capture_insn_snapshot(insn: "ida_hexrays.minsn_t") -> InsnSnapshot:
    """Capture a rich ``InsnSnapshot`` from a live ``minsn_t``.

    Populates both the legacy ``operands``/``operand_slots`` fields and the
    new typed ``l``/``r``/``d`` fields.
    """
    opcode = insn.opcode
    ea = insn.ea

    operand_slots = tuple(
        (slot_name, MopSnapshot.from_mop(mop))
        for slot_name, mop in (
            ("l", insn.l),
            ("r", insn.r),
            ("d", insn.d),
        )
        if mop.t != ida_hexrays.mop_z  # type: ignore[attr-defined]
    )
    operands = tuple(operand for _, operand in operand_slots)

    return InsnSnapshot(
        opcode=opcode,
        ea=ea,
        operands=operands,
        operand_slots=operand_slots,
        l=capture_mop_snapshot(insn.l),
        r=capture_mop_snapshot(insn.r),
        d=capture_mop_snapshot(insn.d),
    )


def lift_block(blk: "ida_hexrays.mblock_t") -> BlockSnapshot:
    serial = blk.serial
    block_type = blk.type
    flags = blk.flags
    start_ea = blk.start

    succs = get_succ_serials(blk)
    preds = get_pred_serials(blk)

    insn_snapshots: list[InsnSnapshot] = []
    insn = blk.head
    while insn:
        insn_snapshots.append(capture_insn_snapshot(insn))
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


def _unsupported_insert_block_reason(step: PatchInsertBlock) -> str | None:
    reason = validate_insn_snapshots(step.instructions)
    if reason is not None:
        return (
            f"PatchInsertBlock({step.pred_serial}->{step.succ_serial}) "
            f"cannot rebuild instructions: {reason}"
        )
    return None


def _unsupported_duplicate_block_reason(step: PatchDuplicateBlock) -> str | None:
    if step.pred_serial is None:
        return f"PatchDuplicateBlock(source={step.source_serial}) missing predecessor"
    if step.pred_redirect_kind not in {"one_way", "conditional"}:
        return (
            f"PatchDuplicateBlock(source={step.source_serial}, pred={step.pred_serial}) "
            f"unsupported predecessor edge kind: {step.pred_redirect_kind}"
        )
    if len(step.source_successors) > 2:
        return (
            f"PatchDuplicateBlock(source={step.source_serial}) "
            f"unsupported successor count: {len(step.source_successors)}"
        )
    if len(step.source_successors) == 2:
        if step.fallthrough_serial is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated fallthrough serial"
            )
        if step.fallthrough_target is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated fallthrough target"
            )
        if step.target_serial is None and step.conditional_target is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated conditional target"
            )
    return None



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

    def __init__(
        self,
        *,
        allow_legacy_block_creation: bool = True,
        contract: IDACfgContract | None = None,
    ) -> None:
        self.allow_legacy_block_creation = allow_legacy_block_creation
        self._contract = contract
        self._last_lowering_phase: str | None = None

    @property
    def contract(self) -> IDACfgContract | None:
        return self._contract

    @contract.setter
    def contract(self, value: IDACfgContract | None) -> None:
        self._contract = value

    @property
    def last_lowering_phase(self) -> str | None:
        """Phase of last failure from lower(), or None if lower() succeeded."""
        return self._last_lowering_phase

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

    def lower(
        self,
        patch_plan: PatchPlan,
        mba: "ida_hexrays.mba_t",
        *,
        post_apply_hook=None,
    ) -> int:
        """Apply a PatchPlan to mba via DeferredGraphModifier.

        ``PatchPlan`` concrete operations are lowered directly. Supported
        block-creating steps are materialized through backend queue/apply
        operations. Unsupported block creation remains explicit legacy fallback
        and can be rejected before any live mutation when
        ``allow_legacy_block_creation`` is disabled.

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

        self._last_lowering_phase = None

        if not isinstance(patch_plan, PatchPlan):
            raise TypeError(
                "IDAIRTranslator.lower() now requires PatchPlan; "
                "compile GraphModification lists before lowering"
            )
        if patch_plan.legacy_block_operations and not self.allow_legacy_block_creation:
            logger.warning(
                "PatchPlan contains %d legacy block-creating steps but legacy block creation is disabled",
                len(patch_plan.legacy_block_operations),
            )
            self._last_lowering_phase = "lowering"
            return 0
        unsupported_reasons = self._unsupported_patch_plan_reasons(patch_plan)
        if unsupported_reasons:
            logger.warning(
                "PatchPlan contains unsupported lowering step(s): %s",
                ", ".join(unsupported_reasons),
            )
            self._last_lowering_phase = "lowering"
            return 0

        modifier = deferred_modifier.DeferredGraphModifier(mba)

        # Build effective post-apply hook: caller hook + contract check
        effective_hook: Callable[[], None] | None = None
        if self.contract is not None or post_apply_hook is not None:

            def _combined_post_apply_hook() -> None:
                if post_apply_hook is not None:
                    post_apply_hook()
                if self.contract is not None:
                    self.contract.verify(mba, plan=patch_plan, phase="post")

            effective_hook = _combined_post_apply_hook

        if patch_plan.contains_block_creation:
            logger.info(
                "Lowering PatchPlan with %d concrete ops and %d legacy block-creating steps",
                len(patch_plan.concrete_operations),
                len(patch_plan.legacy_block_operations),
            )

        verify_each_mod = not patch_plan.contains_block_creation

        for step in patch_plan.steps:
            self._queue_patch_step(modifier, step)

        # Apply all queued modifications with snapshot rollback enabled
        result_count = modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=verify_each_mod,
            rollback_on_verify_failure=verify_each_mod,
            continue_on_verify_failure=verify_each_mod,
            enable_snapshot_rollback=True,
            post_apply_hook=effective_hook,
        )

        # If verify failed (even after rollback attempt), signal the pipeline
        # to stop by returning 0. A positive result with verify_failed=True
        # means rollback also failed - the MBA may be corrupted.
        if modifier.verify_failed:
            logger.warning(
                "DeferredGraphModifier.verify_failed is set after apply; "
                "returning 0 to prevent pipeline from treating changes as successful"
            )
            self._last_lowering_phase = "native_verify"
            return 0

        return result_count

    def _unsupported_patch_plan_reasons(self, patch_plan: PatchPlan) -> list[str]:
        reasons: list[str] = []
        for step in patch_plan.steps:
            match step:
                case PatchRedirectGoto() | PatchRedirectBranch() | PatchConvertToGoto():
                    continue
                case PatchNopInstructions() | PatchZeroStateWrite() | PatchEdgeSplitTrampoline() | PatchConditionalRedirect():
                    continue
                case PatchPrivateTerminalSuffix():
                    continue
                case PatchPrivateTerminalSuffixGroup():
                    continue
                case PatchDirectTerminalLoweringGroup():
                    continue
                case PatchInsertBlock() as insert_step:
                    reason = _unsupported_insert_block_reason(insert_step)
                    if reason is not None:
                        reasons.append(reason)
                case PatchDuplicateBlock() as duplicate_step:
                    reason = _unsupported_duplicate_block_reason(duplicate_step)
                    if reason is not None:
                        reasons.append(reason)
                case PatchRemoveEdge():
                    continue
                case LegacyBlockOperation(modification=CreateConditionalRedirect()):
                    continue
                case LegacyBlockOperation(modification=EdgeRedirectViaPredSplit()):
                    continue
                case LegacyBlockOperation(
                    modification=InsertBlock(pred_serial=pred, succ_serial=succ)
                ):
                    reasons.append(f"InsertBlock({pred}->{succ})")
                case LegacyBlockOperation(
                    modification=DuplicateBlock(
                        source_block=src,
                        target_block=target,
                        pred_serial=pred,
                    )
                ):
                    reasons.append(
                        f"DuplicateBlock(source={src}, target={target}, pred={pred})"
                    )
                case LegacyBlockOperation(modification=mod):
                    reasons.append(type(mod).__name__)
                case _:
                    reasons.append(type(step).__name__)
        return reasons


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
                modifier.queue_remove_edge(
                    src,
                    dst,
                    description=f"remove edge {src}->{dst}",
                )

            case PatchNopInstructions(block_serial=serial, insn_eas=eas):
                for ea in eas:
                    modifier.queue_insn_nop(
                        serial,
                        ea,
                        description=f"nop {hex(ea)} in block {serial}",
                    )

            case PatchZeroStateWrite(block_serial=serial, insn_ea=ea):
                modifier.queue_zero_state_write(
                    serial,
                    ea,
                    description=f"zero state write {hex(ea)} in block {serial}",
                )

            case PatchEdgeSplitTrampoline(
                source_serial=src,
                via_pred=pred,
                apply_old_target=old,
                new_target=new,
                assigned_serial=assigned,
            ):
                modifier.queue_edge_split_trampoline(
                    source_block=src,
                    via_pred=pred,
                    old_target=old,
                    new_target=new,
                    expected_serial=assigned,
                    description=(
                        f"edge-split trampoline pred={pred} src={src} "
                        f"{old}->{new} via {assigned}"
                    ),
                )

            case PatchConditionalRedirect(
                source_serial=src,
                ref_block=ref,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
            ):
                modifier.queue_create_conditional_redirect(
                    source_blk_serial=src,
                    ref_blk_serial=ref,
                    conditional_target_serial=conditional_target,
                    fallthrough_target_serial=fallthrough_target,
                    expected_conditional_serial=assigned,
                    expected_fallthrough_serial=fallthrough_serial,
                    description=(
                        f"conditional redirect src={src} ref={ref} "
                        f"cond={conditional_target} ft={fallthrough_target} "
                        f"via {assigned}/{fallthrough_serial}"
                    ),
                )

            case PatchInsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                assigned_serial=assigned,
                instructions=instructions,
            ):
                modifier.queue_create_and_redirect(
                    source_block_serial=pred,
                    final_target_serial=succ,
                    instructions_to_copy=list(instructions),
                    is_0_way=False,
                    expected_serial=assigned,
                    description=(
                        f"insert block {pred}->{assigned}->{succ} "
                        f"with {len(instructions)} instructions"
                    ),
                )

            case PatchDuplicateBlock(
                source_serial=src,
                pred_serial=pred,
                target_serial=target,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
            ):
                modifier.queue_duplicate_block(
                    source_block_serial=src,
                    pred_serial=pred,
                    target_serial=target,
                    expected_serial=assigned,
                    expected_secondary_serial=fallthrough_serial,
                    description=(
                        f"duplicate block src={src} pred={pred} "
                        f"target={target} via {assigned}"
                    ),
                )

            case PatchPrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                clone_assigned_serials=clone_serials,
            ):
                modifier.queue_private_terminal_suffix(
                    anchor_serial=anchor,
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix,
                    clone_expected_serials=clone_serials,
                    description=(
                        f"private terminal suffix anchor={anchor} "
                        f"shared_entry={shared_entry} return={return_block} "
                        f"suffix={suffix} clones={clone_serials}"
                    ),
                )

            case PatchPrivateTerminalSuffixGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix_serials,
                anchors=anchors,
                per_anchor_clone_assigned_serials=per_anchor_serials,
            ):
                modifier.queue_private_terminal_suffix_group(
                    anchors=anchors,
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix_serials,
                    per_anchor_clone_expected_serials=per_anchor_serials,
                )

            case PatchDirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix_serials,
                sites=sites,
            ):
                modifier.queue_direct_terminal_lowering_group(
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix_serials,
                    sites=sites,
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


__all__ = [
    "IDAIRTranslator",
    "capture_insn_snapshot",
    "capture_mop_snapshot",
    "lift",
    "lift_block",
]
