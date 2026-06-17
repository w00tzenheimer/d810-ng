"""Hex-Rays materialization for dispatcher cleanup plans."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.transforms.dispatcher_residue_cleanup_planning import (
    DispatcherResidueCleanupPlan,
    UnreachableRegionCleanupPlan,
)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


@dataclass(frozen=True)
class DispatcherResidueCleanupApplyResult:
    severed_1way: int = 0
    converted_2way: int = 0
    dispatcher_outgoing_severed: int = 0

    @property
    def handler_edge_changes(self) -> int:
        return self.severed_1way + self.converted_2way


@dataclass(frozen=True)
class UnreachableRegionCleanupApplyResult:
    gutted: int = 0
    redirected: int = 0


def _observe_cfg(
    *,
    pass_name: str,
    action: str,
    block_serial: int,
    target_serial: int | None,
    reason: str,
    mba: ida_hexrays.mba_t,
    extra: dict | None = None,
) -> None:
    try:
        from d810.core.observability_cfg import observe_cfg_provenance

        observe_cfg_provenance(
            pass_name=pass_name,
            action=action,
            block_serial=block_serial,
            target_serial=target_serial,
            reason=reason,
            extra=extra,
            mba=mba,
        )
    except Exception:
        pass


def _apply_deferred(
    modifier: DeferredGraphModifier,
    *,
    logger,
    description: str,
) -> int:
    queued = len(getattr(modifier, "modifications", ()) or ())
    if queued == 0:
        return 0
    applied = int(
        modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            verify_each_mod=False,
            rollback_on_verify_failure=False,
            defer_post_apply_maintenance=True,
        )
    )
    if applied != queued:
        logger.warning(
            "%s: DeferredGraphModifier applied %d/%d queued modifications",
            description,
            applied,
            queued,
        )
    return applied


def _insn_eas_before_tail(blk: ida_hexrays.mblock_t) -> tuple[int, ...]:
    eas: list[int] = []
    tail = blk.tail
    insn = blk.head
    while insn is not None and insn != tail:
        eas.append(int(insn.ea))
        insn = insn.next
    return tuple(eas)


def apply_dispatcher_residue_cleanup_plan(
    mba: ida_hexrays.mba_t,
    plan: DispatcherResidueCleanupPlan,
    *,
    logger,
) -> DispatcherResidueCleanupApplyResult:
    """Materialize dispatcher-residue cleanup through DeferredGraphModifier."""

    dispatcher_serial = int(plan.dispatcher_serial)
    disp_blk = mba.get_mblock(dispatcher_serial)
    if disp_blk is None:
        return DispatcherResidueCleanupApplyResult()

    first_batch = DeferredGraphModifier(mba)
    sever_candidates: list[int] = []
    for serial in plan.one_way_edge_severs:
        blk = mba.get_mblock(int(serial))
        if blk is None or blk.nsucc() != 1 or blk.succ(0) != dispatcher_serial:
            continue
        first_batch.queue_remove_edge(
            int(blk.serial),
            dispatcher_serial,
            description=(
                "dispatcher residue cleanup: sever "
                f"{int(blk.serial)}->{dispatcher_serial}"
            ),
        )
        sever_candidates.append(int(blk.serial))
        logger.info(
            "DispatcherResidueCleanup: queued 1-way blk[%d] -> dispatcher edge sever",
            blk.serial,
        )
        _observe_cfg(
            pass_name="dispatcher_residue_cleanup",
            action="SEVER_EDGE",
            block_serial=int(blk.serial),
            target_serial=dispatcher_serial,
            reason="sever_1way_handler_to_dispatcher",
            mba=mba,
        )

    conversion_candidates: list[int] = []
    for conversion in plan.two_way_conversions:
        serial = int(conversion.block_serial)
        keep_serial = int(conversion.keep_successor)
        blk = mba.get_mblock(serial)
        if blk is None or blk.nsucc() != 2:
            continue
        logger.info(
            "DispatcherResidueCleanup: converting 2-way blk[%d] "
            "(succs=%d,%d) to goto blk[%d]",
            serial,
            conversion.old_successors[0],
            conversion.old_successors[1],
            keep_serial,
        )
        first_batch.queue_convert_to_goto(
            serial,
            keep_serial,
            description=(
                "dispatcher residue cleanup: convert "
                f"{serial} to goto {keep_serial}"
            ),
        )
        conversion_candidates.append(serial)
        _observe_cfg(
            pass_name="dispatcher_residue_cleanup",
            action="REDIRECT_EDGE",
            block_serial=serial,
            target_serial=keep_serial,
            reason="convert_2way_to_goto_drop_dispatcher_arm",
            extra={"old_succs": [int(s) for s in conversion.old_successors]},
            mba=mba,
        )

    first_applied = _apply_deferred(
        first_batch,
        logger=logger,
        description="DispatcherResidueCleanup handler-edge batch",
    )
    severed = min(first_applied, len(sever_candidates))
    converted = min(
        max(first_applied - len(sever_candidates), 0),
        len(conversion_candidates),
    )

    outgoing_severed = 0
    disp_blk = mba.get_mblock(dispatcher_serial)
    if disp_blk is None:
        return DispatcherResidueCleanupApplyResult(
            severed_1way=severed,
            converted_2way=converted,
        )
    if disp_blk.npred() == 0:
        planned_succs = tuple(int(s) for s in plan.dispatcher_outgoing_successors)
        succ_serials = (
            planned_succs
            if planned_succs
            else tuple(int(disp_blk.succ(i)) for i in range(disp_blk.nsucc()))
        )
        outgoing_batch = DeferredGraphModifier(mba)
        for succ_serial in succ_serials:
            if not any(
                int(disp_blk.succ(i)) == succ_serial
                for i in range(disp_blk.nsucc())
            ):
                continue
            outgoing_batch.queue_remove_edge(
                dispatcher_serial,
                succ_serial,
                description=(
                    "dispatcher residue cleanup: sever dispatcher "
                    f"{dispatcher_serial}->{succ_serial}"
                ),
            )
            _observe_cfg(
                pass_name="dispatcher_residue_cleanup",
                action="SEVER_EDGE",
                block_serial=dispatcher_serial,
                target_serial=succ_serial,
                reason="dispatcher_outgoing_to_condition_chain_comparison",
                mba=mba,
            )
        outgoing_severed = _apply_deferred(
            outgoing_batch,
            logger=logger,
            description="DispatcherResidueCleanup dispatcher-outgoing batch",
        )
        if outgoing_severed:
            logger.info(
                "DispatcherResidueCleanup: severed %d outgoing dispatcher edges to %s",
                outgoing_severed,
                succ_serials,
            )

    return DispatcherResidueCleanupApplyResult(
        severed_1way=severed,
        converted_2way=converted,
        dispatcher_outgoing_severed=outgoing_severed,
    )


def apply_unreachable_region_cleanup_plan(
    mba: ida_hexrays.mba_t,
    plan: UnreachableRegionCleanupPlan,
    *,
    logger,
) -> UnreachableRegionCleanupApplyResult:
    """Materialize unreachable-region cleanup via DeferredGraphModifier."""

    cleanup_modifier = DeferredGraphModifier(mba)
    accepted_cleanup_blocks: set[int] = set()
    gutted = 0
    for block in plan.blocks:
        serial = int(block.block_serial)
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        nsucc = blk.nsucc()
        if nsucc == 0:
            continue
        if nsucc > 2:
            logger.warning(
                "UnreachableRegionCleanup: skipping blk[%d] with unsupported "
                "successor count %d",
                serial,
                nsucc,
            )
            continue

        accepted_cleanup_blocks.add(serial)
        for ea in _insn_eas_before_tail(blk):
            cleanup_modifier.queue_insn_nop(
                serial,
                ea,
                description=(
                    "unreachable region cleanup: nop "
                    f"{hex(ea)} in block {serial}"
                ),
            )

        if nsucc == 2:
            keep_succ = blk.succ(0)
            cleanup_modifier.queue_convert_to_goto(
                serial,
                keep_succ,
                description=(
                    "unreachable region cleanup: convert "
                    f"{serial} to goto {int(keep_succ)}"
                ),
            )

        gutted += 1
        _observe_cfg(
            pass_name="unreachable_region_cleanup",
            action="SOFT_KILL",
            block_serial=serial,
            target_serial=(blk.succ(0) if blk.nsucc() > 0 else None),
            reason="unreachable_after_condition_chain_cleanup",
            extra={"original_nsucc": int(nsucc)},
            mba=mba,
        )

    if not accepted_cleanup_blocks:
        return UnreachableRegionCleanupApplyResult()

    _apply_deferred(
        cleanup_modifier,
        logger=logger,
        description="UnreachableRegionCleanup cleanup batch",
    )

    redirect_modifier = DeferredGraphModifier(mba)
    redirect_candidates = 0
    for redirect in plan.forward_redirects:
        serial = int(redirect.block_serial)
        if serial not in accepted_cleanup_blocks:
            continue
        blk = mba.get_mblock(serial)
        if blk is None or blk.nsucc() != 1:
            continue
        old_target = int(redirect.old_target)
        stop_serial = int(redirect.new_target)
        if blk.succ(0) != old_target:
            continue
        if old_target == stop_serial or old_target not in accepted_cleanup_blocks:
            continue

        redirect_modifier.queue_goto_change(
            serial,
            stop_serial,
            description=(
                "unreachable region cleanup: redirect "
                f"{serial} from {old_target} to {stop_serial}"
            ),
        )
        redirect_candidates += 1
        _observe_cfg(
            pass_name="unreachable_region_cleanup",
            action="REDIRECT_EDGE",
            block_serial=serial,
            target_serial=stop_serial,
            reason="forward_redirect_to_blt_stop",
            extra={"old_target": int(old_target)},
            mba=mba,
        )

    redirected = _apply_deferred(
        redirect_modifier,
        logger=logger,
        description="UnreachableRegionCleanup redirect batch",
    )
    redirected = min(redirected, redirect_candidates)
    logger.info(
        "UnreachableRegionCleanup: soft-killed %d unreachable blocks "
        "as 1-way goto shells"
        " (%d redirected forward to BLT_STOP)",
        gutted,
        redirected,
    )
    return UnreachableRegionCleanupApplyResult(gutted=gutted, redirected=redirected)


__all__ = [
    "DispatcherResidueCleanupApplyResult",
    "UnreachableRegionCleanupApplyResult",
    "apply_dispatcher_residue_cleanup_plan",
    "apply_unreachable_region_cleanup_plan",
]
