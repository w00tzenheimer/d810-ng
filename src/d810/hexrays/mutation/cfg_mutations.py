"""Edge/block mutation functions for CFG manipulation.

This module contains all functions that modify control flow graph structure,
including edge rewiring, block creation, and CFG cleanup. Split from cfg_utils.py
as part of the CFG Pass Pipeline refactor (Phase 1).
"""
from __future__ import annotations

import ida_hexrays
import ida_pro
import idaapi

from d810.core import getLogger
from d810.errors import ControlFlowException
from d810.hexrays.mutation.cfg_verify import safe_verify, log_block_info
from d810.hexrays.ir.cfg_queries import _serial_in_predset

helper_logger = getLogger(__name__)


def _rewire_edge(
    blk: "ida_hexrays.mblock_t",
    old_succs: list[int],
    new_succs: list[int],
    new_block_type: int | None = None,
    new_flags: int | None = None,
    verify: bool = True,
) -> bool:
    """Shared edge rewiring bookkeeping.

    Handles succset/predset updates, dirty marking, and optional verify.
    Callers handle instruction-specific logic before calling this.

    Args:
        blk: Block whose edges are being rewired.
        old_succs: List of old successor serials to remove.
        new_succs: List of new successor serials to add.
        new_block_type: If not None, set blk.type to this value.
        new_flags: If not None, OR these flags into blk.flags.
        verify: If True, run mba.verify() after rewiring.

    Returns:
        True if successful (and verify passed if enabled).

    Raises:
        RuntimeError: If verify is True and mba.verify() fails.
    """
    mba = blk.mba

    # Update block type/flags if specified
    if new_block_type is not None:
        blk.type = new_block_type
    if new_flags is not None:
        blk.flags |= new_flags

    # Remove old successors
    for old_succ in old_succs:
        blk.succset._del(old_succ)
        old_blk = mba.get_mblock(old_succ)
        old_blk.predset._del(blk.serial)
        if old_blk.serial != mba.qty - 1:
            old_blk.mark_lists_dirty()

    # Add new successors
    for new_succ in new_succs:
        blk.succset.push_back(new_succ)
        new_blk = mba.get_mblock(new_succ)
        # Add blk to new successor's predset (without duplicates)
        if not _serial_in_predset(new_blk, blk.serial):
            new_blk.predset.push_back(blk.serial)
        if new_blk.serial != mba.qty - 1:
            new_blk.mark_lists_dirty()

    blk.mark_lists_dirty()
    mba.mark_chains_dirty()

    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in edge rewiring for block %d: %s", blk.serial, e)
        log_block_info(blk, helper_logger.error)
        for new_succ in new_succs:
            log_block_info(mba.get_mblock(new_succ), helper_logger.error)
        raise


def insert_goto_instruction(
    blk: ida_hexrays.mblock_t, goto_blk_serial: int, nop_previous_instruction=False
):
    # Use mba.entry_ea for synthesized goto instructions to guarantee the EA
    # is within the decompiled function's address range (prevents INTERR 50863).
    safe_ea = blk.mba.entry_ea
    goto_ins = ida_hexrays.minsn_t(safe_ea)
    goto_ins.ea = safe_ea

    if nop_previous_instruction and blk.tail is not None:
        blk.make_nop(blk.tail)
    blk.insert_into_block(goto_ins, blk.tail)

    # We nop instruction before setting it to goto to avoid error 52123
    blk.make_nop(blk.tail)
    goto_ins.opcode = ida_hexrays.m_goto
    goto_ins.l = ida_hexrays.mop_t()
    goto_ins.l.make_blkref(goto_blk_serial)
    # A valid m_goto must not carry stale right/destination operands.
    goto_ins.r = ida_hexrays.mop_t()
    goto_ins.r.erase()
    goto_ins.d = ida_hexrays.mop_t()
    goto_ins.d.erase()


def change_1way_call_block_successor(
    call_blk: ida_hexrays.mblock_t, call_blk_successor_serial: int, verify: bool = True
) -> bool:
    if call_blk.nsucc() != 1:
        return False

    mba = call_blk.mba

    # insert_nop_blk fully wires the NOP block between call_blk and its
    # original successor (succset/predset bookkeeping included), so we only
    # need to redirect the NOP block to the desired target afterward.
    nop_blk = insert_nop_blk(call_blk)
    insert_goto_instruction(
        nop_blk, call_blk_successor_serial, nop_previous_instruction=True
    )
    is_ok = change_1way_block_successor(nop_blk, call_blk_successor_serial, verify=verify)
    if not is_ok:
        return False

    mba.mark_chains_dirty()
    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_1way_call_block_successor: {0}".format(e))
        log_block_info(call_blk, helper_logger.error)
        log_block_info(nop_blk, helper_logger.error)
        raise e


def change_1way_block_successor(blk: ida_hexrays.mblock_t, blk_successor_serial: int, verify: bool = True) -> bool:
    if blk.nsucc() != 1 or blk.serial == 0:
        return False

    mba: ida_hexrays.mbl_array_t = blk.mba
    previous_blk_successor_serial = blk.succset[0]
    previous_blk_successor = mba.get_mblock(previous_blk_successor_serial)

    if blk.tail is None:
        # We add a goto instruction
        insert_goto_instruction(
            blk, blk_successor_serial, nop_previous_instruction=False
        )
    elif blk.tail.opcode == ida_hexrays.m_goto:
        # We change goto target directly
        blk.tail.l.make_blkref(blk_successor_serial)
    elif blk.tail.opcode == ida_hexrays.m_ijmp:
        # We replace ijmp instruction with goto instruction
        insert_goto_instruction(
            blk, blk_successor_serial, nop_previous_instruction=True
        )
    elif blk.tail.opcode == ida_hexrays.m_call:
        #  Before maturity MMAT_CALLS, we can't add a goto after a call instruction
        if mba.maturity < ida_hexrays.MMAT_CALLS:
            return change_1way_call_block_successor(blk, blk_successor_serial, verify=verify)
        else:
            insert_goto_instruction(
                blk, blk_successor_serial, nop_previous_instruction=False
            )
    else:
        # We add a goto instruction
        insert_goto_instruction(
            blk, blk_successor_serial, nop_previous_instruction=False
        )

    # Update block properties
    blk.type = ida_hexrays.BLT_1WAY
    blk.flags |= ida_hexrays.MBL_GOTO

    # Bookkeeping
    blk.succset._del(previous_blk_successor_serial)
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    previous_blk_successor.predset._del(blk.serial)
    if previous_blk_successor.serial != mba.qty - 1:
        previous_blk_successor.mark_lists_dirty()

    new_blk_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_successor.predset.push_back(blk.serial)

    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_1way_block_successor: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        log_block_info(previous_blk_successor, helper_logger.error)
        raise e


def change_0way_block_successor(blk: ida_hexrays.mblock_t, blk_successor_serial: int, verify: bool = True) -> bool:
    if blk.nsucc() != 0:
        return False
    mba = blk.mba

    if blk.tail.opcode == ida_hexrays.m_ijmp:
        # We replace ijmp instruction with goto instruction
        insert_goto_instruction(
            blk, blk_successor_serial, nop_previous_instruction=True
        )
    else:
        # We add a goto instruction
        insert_goto_instruction(
            blk, blk_successor_serial, nop_previous_instruction=False
        )

    # Update block properties
    blk.type = ida_hexrays.BLT_1WAY
    blk.flags |= ida_hexrays.MBL_GOTO

    # Bookkeeping
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    new_blk_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_successor.predset.push_back(blk.serial)
    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_0way_block_successor: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        raise e


def change_2way_block_conditional_successor(
    blk: ida_hexrays.mblock_t, blk_successor_serial: int, verify: bool = True,
    old_target: int | None = None,
) -> bool:
    if blk.nsucc() != 2:
        return False

    mba = blk.mba
    previous_blk_conditional_successor_serial = blk.tail.d.b
    if old_target is not None and previous_blk_conditional_successor_serial != old_target:
        helper_logger.warning(
            "change_2way_block_conditional_successor: blk[%d] expected old_target=%d "
            "but current branch target is %d",
            blk.serial, old_target, previous_blk_conditional_successor_serial,
        )
    previous_blk_conditional_successor = mba.get_mblock(
        previous_blk_conditional_successor_serial
    )

    blk.tail.d = ida_hexrays.mop_t()
    blk.tail.d.make_blkref(blk_successor_serial)

    # Bookkeeping
    blk.succset._del(previous_blk_conditional_successor_serial)
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    previous_blk_conditional_successor.predset._del(blk.serial)
    if previous_blk_conditional_successor.serial != mba.qty - 1:
        previous_blk_conditional_successor.mark_lists_dirty()

    new_blk_conditional_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_conditional_successor.predset.push_back(blk.serial)
    if new_blk_conditional_successor.serial != mba.qty - 1:
        new_blk_conditional_successor.mark_lists_dirty()

    # Step4: Final stuff and checks
    mba.mark_chains_dirty()
    if not verify:
        return True
    try:
        mba.verify(True)

        return True
    except RuntimeError as e:
        helper_logger.error(
            "Error in change_2way_block_conditional_successor: {0}".format(e)
        )
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_conditional_successor, helper_logger.error)
        raise e


def update_blk_successor(
    blk: ida_hexrays.mblock_t, old_successor_serial: int, new_successor_serial: int, verify: bool = True
) -> int:
    if blk.nsucc() == 1:
        change_1way_block_successor(blk, new_successor_serial, verify=verify)
    elif blk.nsucc() == 2:
        if old_successor_serial == blk.nextb.serial:
            helper_logger.info(
                "Can't update direct block successor: {0} - {1} - {2}".format(
                    blk.serial, old_successor_serial, new_successor_serial
                )
            )
            return 0
        else:
            change_2way_block_conditional_successor(blk, new_successor_serial, verify=verify)
    else:
        helper_logger.info("Can't update block successor: {0} ".format(blk.serial))
        return 0
    return 1


def make_2way_block_goto(blk: ida_hexrays.mblock_t, blk_successor_serial: int, verify: bool = True) -> bool:
    if blk.nsucc() != 2:
        return False
    mba = blk.mba
    previous_blk_successor_serials = [x for x in blk.succset]
    previous_blk_successors = [
        mba.get_mblock(x) for x in previous_blk_successor_serials
    ]

    insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=True)

    # Update block properties
    blk.type = ida_hexrays.BLT_1WAY
    blk.flags |= ida_hexrays.MBL_GOTO

    # Bookkeeping
    for prev_serial in previous_blk_successor_serials:
        blk.succset._del(prev_serial)
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    for prev_blk in previous_blk_successors:
        prev_blk.predset._del(blk.serial)
        if prev_blk.serial != mba.qty - 1:
            prev_blk.mark_lists_dirty()

    new_blk_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_successor.predset.push_back(blk.serial)
    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in make_2way_block_goto: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        raise e


def create_block(
    blk: ida_hexrays.mblock_t, blk_ins: list[ida_hexrays.minsn_t], is_0_way: bool = False, verify: bool = True
) -> ida_hexrays.mblock_t:
    mba = blk.mba
    new_blk = insert_nop_blk(blk)
    # Use mba.entry_ea for synthesized instruction EAs (prevents INTERR 50863).
    safe_ea = mba.entry_ea
    for ins in blk_ins:
        tmp_ins = ida_hexrays.minsn_t(ins)
        tmp_ins.setaddr(safe_ea)
        new_blk.insert_into_block(tmp_ins, new_blk.tail)

    if is_0_way:
        new_blk.type = ida_hexrays.BLT_0WAY
        # Remove the goto instruction left by insert_nop_blk -- a 0-way block
        # must NOT contain a goto, otherwise verify() raises INTERR 50856.
        if new_blk.tail is not None and new_blk.tail.opcode == ida_hexrays.m_goto:
            new_blk.make_nop(new_blk.tail)
        new_blk.flags &= ~ida_hexrays.MBL_GOTO
        # Bookkeeping
        prev_successor_serial = new_blk.succset[0]
        new_blk.succset._del(prev_successor_serial)
        prev_succ = mba.get_mblock(prev_successor_serial)
        prev_succ.predset._del(new_blk.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()

    new_blk.mark_lists_dirty()
    mba.mark_chains_dirty()
    if not verify:
        return new_blk
    try:
        mba.verify(True)
        return new_blk
    except RuntimeError as e:
        helper_logger.error("Error in create_block: {0}".format(e))
        log_block_info(new_blk, helper_logger.error)
        raise e


def create_standalone_block(
    ref_blk: ida_hexrays.mblock_t,
    blk_ins: list[ida_hexrays.minsn_t],
    target_serial: int | None = None,
    is_0_way: bool = False,
    verify: bool = True,
) -> ida_hexrays.mblock_t:
    """Create a standalone block without modifying ref_blk's CFG edges.

    Unlike :func:`create_block` which uses :func:`insert_nop_blk` and rewires
    ``ref_blk``'s successors/predecessors (causing INTERR 50858 when the
    caller later redirects those edges), this function uses ``copy_block``
    directly and builds the new block's CFG from scratch.

    Args:
        ref_blk: Template block used only for ``copy_block``; its CFG edges
            are **not** modified.
        blk_ins: Instructions to place in the new block.
        target_serial: If not ``None`` and ``is_0_way`` is ``False``, a goto
            to this serial is inserted and the block is wired as 1-way.
        is_0_way: If ``True``, the block is created with ``BLT_0WAY``, no
            goto instruction, and no successors.

    Returns:
        The newly created :class:`ida_hexrays.mblock_t`.
    """
    mba = ref_blk.mba

    # 1. Copy ref_blk to get a fresh block at the end of the MBA
    new_blk = mba.copy_block(ref_blk, mba.qty - 1)

    # 2. Clean ALL inherited successor edges (copy_block clones them)
    prev_successor_serials = [x for x in new_blk.succset]
    for prev_serial in prev_successor_serials:
        new_blk.succset._del(prev_serial)
        prev_succ = mba.get_mblock(prev_serial)
        prev_succ.predset._del(new_blk.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()

    # 3. Clean ALL inherited predecessor edges (stale from ref_blk)
    prev_predecessor_serials = [x for x in new_blk.predset]
    for prev_serial in prev_predecessor_serials:
        new_blk.predset._del(prev_serial)

    # Use mba.entry_ea for all synthesized instruction EAs to guarantee the
    # address is within the decompiled function's range (prevents INTERR 50863).
    safe_ea = mba.entry_ea

    # 4. Remove all inherited instructions to prevent NOP accumulation.
    #    When create_standalone_block is called sequentially (e.g., 376 times
    #    for BLOCK_CREATE_WITH_REDIRECT operations), the new block becomes the
    #    tail and may be used as ref_blk for the next copy_block call.  If we
    #    only NOP the inherited instructions (without removing them), each
    #    successive copy inherits all previous NOPs, causing O(n**2) growth.
    #    Block 1121 would end up with 1125 NOPs, triggering hangs.
    #
    #    Fix: collect inherited instructions, then remove them all, leaving the
    #    block empty.  A single NOP placeholder is inserted afterwards so the
    #    block has a valid tail.ea for subsequent insert_into_block calls.
    inherited_insns = []
    cur_ins = new_blk.head
    while cur_ins is not None:
        inherited_insns.append(cur_ins)
        cur_ins = cur_ins.next
    for insn in inherited_insns:
        new_blk.make_nop(insn)
        new_blk.remove_from_block(insn)

    # Ensure the block has at least one NOP so tail.ea is valid.
    nop_ins = ida_hexrays.minsn_t(safe_ea)
    nop_ins.opcode = ida_hexrays.m_nop
    new_blk.insert_into_block(nop_ins, new_blk.head)

    # 5. Copy the desired instructions into the block
    for ins in blk_ins:
        tmp_ins = ida_hexrays.minsn_t(ins)
        tmp_ins.setaddr(safe_ea)
        new_blk.insert_into_block(tmp_ins, new_blk.tail)

    # 6. Set block type and wire edges
    if is_0_way:
        new_blk.type = ida_hexrays.BLT_0WAY
        new_blk.flags &= ~ida_hexrays.MBL_GOTO
    else:
        new_blk.type = ida_hexrays.BLT_1WAY
        if target_serial is not None:
            # Add goto instruction to the target
            insert_goto_instruction(new_blk, target_serial, nop_previous_instruction=False)
            new_blk.flags |= ida_hexrays.MBL_GOTO
            # Wire successor edge: new_blk -> target
            new_blk.succset.push_back(target_serial)
            target_blk = mba.get_mblock(target_serial)
            target_blk.predset.push_back(new_blk.serial)
            if target_blk.serial != mba.qty - 1:
                target_blk.mark_lists_dirty()

    new_blk.mark_lists_dirty()
    mba.mark_chains_dirty()
    if not verify:
        return new_blk
    try:
        mba.verify(True)
        return new_blk
    except RuntimeError as e:
        helper_logger.error("Error in create_standalone_block: {0}".format(e))
        log_block_info(new_blk, helper_logger.error)
        raise e


def update_block_successors(blk: ida_hexrays.mblock_t, blk_succ_serial_list: list[int]):
    mba = blk.mba
    if len(blk_succ_serial_list) == 0:
        blk.type = ida_hexrays.BLT_0WAY
    elif len(blk_succ_serial_list) == 1:
        blk.type = ida_hexrays.BLT_1WAY
    elif len(blk_succ_serial_list) == 2:
        blk.type = ida_hexrays.BLT_2WAY
    else:
        raise

    # Remove old successors
    prev_successor_serials = [x for x in blk.succset]
    for prev_successor_serial in prev_successor_serials:
        blk.succset._del(prev_successor_serial)
        prev_succ = mba.get_mblock(prev_successor_serial)
        prev_succ.predset._del(blk.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()
    # Add new successors
    for blk_succ_serial in blk_succ_serial_list:
        blk.succset.push_back(blk_succ_serial)
        new_blk_successor = mba.get_mblock(blk_succ_serial)
        new_blk_successor.predset.push_back(blk.serial)
        if new_blk_successor.serial != mba.qty - 1:
            new_blk_successor.mark_lists_dirty()

    blk.mark_lists_dirty()


def _update_jtbl_case_targets(
    mba: ida_hexrays.mba_t,
    old_target: int,
    new_target: int,
) -> int:
    """Scan all blocks for m_jtbl instructions and update stale case targets.

    When a NOP block is inserted between two blocks, any m_jtbl instruction
    whose ``mcases_t.targets[]`` references *old_target* must be patched to
    reference *new_target*.  Without this, the jump-table operand holds a stale
    block serial that may point to a NOP sled or, after further CFG surgery,
    to freed memory -- causing a segfault in later Hex-Rays passes.

    Args:
        mba: The microcode block array.
        old_target: Block serial that may appear in mcases_t.targets.
        new_target: Replacement block serial.

    Returns:
        Number of individual case-target entries that were updated.
    """
    if old_target == new_target:
        return 0

    updated = 0
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.tail is None:
            continue
        if blk.tail.opcode != ida_hexrays.m_jtbl:
            continue
        # m_jtbl: ins.r is mop_c (cases operand), ins.r.c is mcases_t
        if blk.tail.r is None or blk.tail.r.t != ida_hexrays.mop_c:
            continue
        cases = blk.tail.r.c
        if cases is None:
            continue
        targets = cases.targets  # intvec_t of block serials
        n = targets.size()
        for j in range(n):
            if targets[j] == old_target:
                targets[j] = new_target
                updated += 1
                helper_logger.debug(
                    "Updated m_jtbl case target in block %d: %d -> %d (index %d)",
                    blk.serial, old_target, new_target, j,
                )
    if updated:
        helper_logger.info(
            "Updated %d m_jtbl case target(s): %d -> %d",
            updated, old_target, new_target,
        )
    return updated


def coalesce_jtbl_cases(blk: "ida_hexrays.mblock_t") -> int:
    """Coalesce duplicate target entries in a jtbl block's mcases_t.

    IDA's mba.verify() (INTERR 50753) requires each target block serial to
    appear at most once in ``cases.targets[]``.  In the valid IDA representation,
    multiple case values for the same target go into a single ``values[]`` entry.

    This function can be called independently of any retargeting — it fixes
    pre-existing duplicates introduced by the unflattener or other passes.

    Args:
        blk: Dispatcher block whose tail must be ``m_jtbl``.

    Returns:
        Number of duplicate target entries coalesced (0 if already unique).
    """
    tail = getattr(blk, "tail", None)
    if tail is None or tail.opcode != ida_hexrays.m_jtbl:
        return 0
    if tail.r is None or tail.r.t != ida_hexrays.mop_c or tail.r.c is None:
        return 0

    cases = tail.r.c
    if cases.targets is None:
        return 0

    old_unique_succs: set[int] = set(int(s) for s in blk.succset)

    n = cases.targets.size()

    # Phase 1: Extract ALL data to pure Python (no SWIG proxies held)
    from collections import defaultdict
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        tgt = int(cases.targets[i])
        for val in cases.values[i]:
            groups[tgt].append(int(val))

    coalesced = n - len(groups)
    if coalesced == 0:
        return 0

    # Phase 2: Rebuild mcases_t from pure Python data.
    # casevec_t is qvector<svalvec_t>; each entry is an svalvec_t (svalvec_t =
    # qvector<sval_t>).  In IDA Python 9.x this is ida_pro.svalvec_t().
    new_mc = ida_hexrays.mcases_t()
    for tgt in sorted(groups):
        new_mc.targets.push_back(tgt)
        uv = ida_pro.svalvec_t()
        for val in groups[tgt]:
            uv.push_back(val)
        new_mc.values.push_back(uv)
    cases.swap(new_mc)

    helper_logger.debug(
        "Coalesced %d -> %d unique jtbl entries in block %d",
        n, len(groups), blk.serial,
    )

    blk.succset.clear()
    for i in range(cases.targets.size()):
        blk.succset.add_unique(int(cases.targets[i]))

    mba = blk.mba
    blk_serial = int(blk.serial)
    new_unique_succs: set[int] = set(int(cases.targets[i]) for i in range(cases.targets.size()))

    for removed_target in sorted(old_unique_succs - new_unique_succs):
        removed_blk = mba.get_mblock(removed_target)
        if removed_blk is None:
            continue
        if _serial_in_predset(removed_blk, blk_serial):
            removed_blk.predset._del(blk_serial)
            removed_blk.mark_lists_dirty()

    for added_target in sorted(new_unique_succs - old_unique_succs):
        added_blk = mba.get_mblock(added_target)
        if added_blk is None:
            continue
        if not _serial_in_predset(added_blk, blk_serial):
            added_blk.predset.push_back(blk_serial)
            added_blk.mark_lists_dirty()

    blk.mark_lists_dirty()
    mba.mark_chains_dirty()
    return coalesced


def retarget_jtbl_block_cases(
    blk: "ida_hexrays.mblock_t",
    retarget_map: dict[int, int],
    *,
    deduplicate: bool = False,
) -> int:
    """Retarget one m_jtbl block's case targets and synchronize CFG edges.

    This is the central gateway for jump-table target rewrites. It updates
    ``mcases_t.targets[]`` from *retarget_map*, then mirrors the resulting
    target vector into ``succset`` and fixes affected ``predset`` memberships.

    Note: deduplication of case entries was removed. Duplicate targets after
    retargeting are left as-is so that IDA's internal verify catches structural
    inconsistencies (INTERR 50753) rather than silently masking them.
    Use :func:`coalesce_jtbl_cases` explicitly when deduplication is needed.

    Args:
        blk: Dispatcher block whose tail must be ``m_jtbl``.
        retarget_map: Mapping ``old_target_serial -> new_target_serial``.
        deduplicate: Unused; kept for API compatibility.

    Returns:
        Number of individual case entries rewritten in ``targets[]``.
    """
    if not retarget_map:
        return 0

    tail = getattr(blk, "tail", None)
    if tail is None or tail.opcode != ida_hexrays.m_jtbl:
        return 0
    if tail.r is None or tail.r.t != ida_hexrays.mop_c or tail.r.c is None:
        return 0

    cases = tail.r.c
    targets = cases.targets
    if targets is None:
        return 0

    old_unique_succs: set[int] = set(int(s) for s in blk.succset)
    rewritten = 0

    for idx in range(targets.size()):
        old_serial = int(targets[idx])
        new_serial = int(retarget_map.get(old_serial, old_serial))
        if old_serial == new_serial:
            continue
        targets[idx] = new_serial
        rewritten += 1

    if rewritten == 0:
        return 0

    blk.succset.clear()
    for i in range(cases.targets.size()):
        blk.succset.add_unique(int(cases.targets[i]))

    mba = blk.mba
    blk_serial = int(blk.serial)
    new_unique_succs: set[int] = set(int(cases.targets[i]) for i in range(cases.targets.size()))

    for removed_target in sorted(old_unique_succs - new_unique_succs):
        removed_blk = mba.get_mblock(removed_target)
        if removed_blk is None:
            continue
        if _serial_in_predset(removed_blk, blk_serial):
            removed_blk.predset._del(blk_serial)
            removed_blk.mark_lists_dirty()

    for added_target in sorted(new_unique_succs - old_unique_succs):
        added_blk = mba.get_mblock(added_target)
        if added_blk is None:
            continue
        if not _serial_in_predset(added_blk, blk_serial):
            added_blk.predset.push_back(blk_serial)
            added_blk.mark_lists_dirty()

    blk.mark_lists_dirty()
    mba.mark_chains_dirty()
    return rewritten


def convert_jtbl_to_goto(
    blk: "ida_hexrays.mblock_t",
    new_target_serial: int,
    mba: "ida_hexrays.mba_t",
) -> bool:
    """Convert an m_jtbl tail instruction to a direct m_goto.

    Ported from the copycat project deflatten.cpp:2063-2126. Safely converts a
    switch-dispatch block to a single-target goto by:
    1. Collecting old case targets for predset cleanup
    2. Changing opcode m_jtbl -> m_goto
    3. Rewiring succset/predset
    4. Setting block type to BLT_1WAY

    Args:
        blk: Block whose tail is m_jtbl.
        new_target_serial: Serial of the single successor block.
        mba: The containing MBA for block access.

    Returns:
        True if conversion succeeded, False if tail is not m_jtbl.
    """
    tail = blk.tail
    if tail is None or tail.opcode != ida_hexrays.m_jtbl:
        return False

    # 1. Collect old case targets from mcases_t for predset cleanup
    old_targets = set()
    if tail.r is not None and tail.r.t == ida_hexrays.mop_c:
        cases = tail.r.c
        if cases is not None:
            targets = cases.targets  # intvec_t of block serials
            n = targets.size()
            for j in range(n):
                old_targets.add(targets[j])

    # 2. Change opcode
    tail.opcode = ida_hexrays.m_goto

    # 3. Set l operand to block reference, clear r and d
    tail.l.make_blkref(new_target_serial)
    tail.r.erase()
    tail.d.erase()

    # 4. Use safe EA (INTERR 50863 prevention)
    tail.ea = mba.entry_ea

    # 5. Update succset: remove all old successors, add new target
    blk_serial = blk.serial
    old_succ_serials = [x for x in blk.succset]
    for old_serial in old_succ_serials:
        blk.succset._del(old_serial)
    blk.succset.push_back(new_target_serial)

    # 6. Remove blk from old targets' predsets
    for old_tgt in old_targets:
        if old_tgt == new_target_serial:
            continue  # Will be handled in step 7
        if 0 <= old_tgt < mba.qty:
            old_blk = mba.get_mblock(old_tgt)
            old_blk.predset._del(blk_serial)
            old_blk.mark_lists_dirty()

    # 7. Ensure blk is in new target's predset
    if 0 <= new_target_serial < mba.qty:
        dst = mba.get_mblock(new_target_serial)
        if not _serial_in_predset(dst, blk_serial):
            dst.predset.push_back(blk_serial)
        dst.mark_lists_dirty()

    # 8. Set block type to 1-way
    blk.type = ida_hexrays.BLT_1WAY
    blk.mark_lists_dirty()

    return True


def _get_fallthrough_successor_serial(blk: ida_hexrays.mblock_t) -> int | None:
    """Return the logical fallthrough successor for *blk* when available."""
    if blk.nsucc() == 0:
        return None
    if blk.nsucc() == 1:
        return blk.succset[0]

    # For conditional jumps, fallthrough is the non-conditional successor.
    if blk.nsucc() == 2 and blk.tail is not None and ida_hexrays.is_mcode_jcond(blk.tail.opcode):
        cond_target = blk.tail.d.b
        for succ_serial in blk.succset:
            if succ_serial != cond_target:
                return succ_serial

    # Generic fallback: prefer physical next only when it is a real successor.
    if blk.nextb is not None:
        next_serial = blk.nextb.serial
        for succ_serial in blk.succset:
            if succ_serial == next_serial:
                return next_serial
    return blk.succset[0]


def insert_nop_blk(blk: ida_hexrays.mblock_t) -> ida_hexrays.mblock_t:
    mba = blk.mba
    original_successor_serial = _get_fallthrough_successor_serial(blk)
    if original_successor_serial is None:
        raise ControlFlowException(
            f"insert_nop_blk({blk.serial}) called on block with no successors"
        )
    original_successor_blk = mba.get_mblock(original_successor_serial)
    # For 2-way/multi-way blocks, fallthrough correctness depends on physical
    # adjacency (blk.nextb). Insert directly after blk so the new NOP block can
    # be the direct successor without creating detached helper blocks.
    #
    # For 0/1-way blocks, keep append-at-end behavior to avoid broad serial
    # shifts in the middle of the MBA.
    insert_after_blk = blk.nsucc() > 1
    if insert_after_blk:
        nop_block = mba.copy_block(blk, blk.serial)
        # Mid-CFG insertion can shift serials; refresh from the original block
        # object to keep bookkeeping tied to the same logical successor.
        if original_successor_blk is not None:
            original_successor_serial = original_successor_blk.serial
    else:
        # Append the new block at the end of the MBA (before the dummy last
        # block) to avoid serial shifts for generic rewrites.
        nop_block = mba.copy_block(blk, mba.qty - 1)
    # Use mba.entry_ea for synthesized NOP instructions to guarantee the EA
    # is within the decompiled function's range (prevents INTERR 50863).
    safe_ea = mba.entry_ea
    cur_ins = nop_block.head
    if cur_ins == None:
        cur_inst = ida_hexrays.minsn_t(safe_ea)
        cur_inst.opcode = ida_hexrays.m_nop
        nop_block.insert_into_block(cur_inst, nop_block.head)
    else:
        while cur_ins is not None:
            nop_block.make_nop(cur_ins)
            cur_ins = cur_ins.next

    nop_block.type = ida_hexrays.BLT_1WAY

    # We might have cloned a block with multiple or no successors, thus we need to clean all
    prev_successor_serials = [x for x in nop_block.succset]
    for prev_successor_serial in prev_successor_serials:
        nop_block.succset._del(prev_successor_serial)
        prev_succ = mba.get_mblock(prev_successor_serial)
        prev_succ.predset._del(nop_block.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()

    # Also clean inherited predecessor set from copy_block -- the copied
    # predecessors point to blk, not to nop_block, so they are stale.
    prev_predecessor_serials = [x for x in nop_block.predset]
    for prev_predecessor_serial in prev_predecessor_serials:
        nop_block.predset._del(prev_predecessor_serial)

    # Add a goto instruction to the NOP block targeting the original successor,
    # since the NOP block is appended at the end and cannot fall through.
    insert_goto_instruction(nop_block, original_successor_serial, nop_previous_instruction=False)
    nop_block.flags |= ida_hexrays.MBL_GOTO

    # Point the NOP block's successor to the original next block of blk,
    # preserving the same logical relationship as the old mid-insertion approach.
    nop_block.succset.push_back(original_successor_serial)

    original_successor_blk = mba.get_mblock(original_successor_serial)

    # Wire the NOP block into the CFG between blk and its original successor.
    # With the old mid-insertion approach, the NOP block was physically adjacent
    # to blk (fallthrough), so this wiring happened implicitly.  Now that we
    # append at the end, we must do it explicitly.
    #
    # For 1-way blocks (and 0-way), we can fully rewire blk -> nop_block.
    # For 2-way (conditional) blocks, the fallthrough successor must remain
    # blk.nextb.serial (a physical property we cannot change by moving
    # succset entries).  In that case we leave blk's wiring untouched and
    # let the caller finish the graph update (e.g. via
    # change_2way_block_conditional_successor).

    if blk.nsucc() <= 1:
        # 1. blk now points to nop_block instead of original_successor
        blk.succset._del(original_successor_serial)
        blk.succset.push_back(nop_block.serial)
        # Update blk's tail instruction if it is a goto pointing to the old successor
        if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_goto:
            if blk.tail.l.t == ida_hexrays.mop_b and blk.tail.l.b == original_successor_serial:
                blk.tail.l.make_blkref(nop_block.serial)
        blk.mark_lists_dirty()

        # 2. original_successor now comes from nop_block, not blk
        original_successor_blk.predset._del(blk.serial)
        original_successor_blk.predset.push_back(nop_block.serial)
        if original_successor_blk.serial != mba.qty - 1:
            original_successor_blk.mark_lists_dirty()

        # 3. nop_block gets blk as predecessor
        nop_block.predset.push_back(blk.serial)
    else:
        # For multi-way blocks, re-home the direct successor edge
        # blk -> original_successor as blk -> nop_block -> original_successor.
        # This keeps succ/pred bidirectional consistency and avoids detached
        # NOP blocks (preds=[]), which trigger INTERR 50856/50858.
        blk.succset._del(original_successor_serial)
        blk.succset.push_back(nop_block.serial)
        blk.mark_lists_dirty()

        original_successor_blk.predset._del(blk.serial)
        original_successor_blk.predset.push_back(nop_block.serial)
        if original_successor_blk.serial != mba.qty - 1:
            original_successor_blk.mark_lists_dirty()

        nop_block.predset.push_back(blk.serial)

    # Update any m_jtbl case targets across the entire MBA that reference
    # the original successor.  When the NOP block is spliced between blk and
    # original_successor, any switch-table operand (mcases_t.targets[]) that
    # still references original_successor_serial on *blk* itself must be
    # patched to go through the NOP block.  We limit the scan to blk's own
    # tail instruction because other blocks' jtbl targets referencing
    # original_successor are intentional (those paths don't go through blk).
    if (
        blk.tail is not None
        and blk.tail.opcode == ida_hexrays.m_jtbl
        and blk.tail.r is not None
        and blk.tail.r.t == ida_hexrays.mop_c
        and blk.tail.r.c is not None
    ):
        cases = blk.tail.r.c
        targets = cases.targets
        n = targets.size()
        for j in range(n):
            if targets[j] == original_successor_serial:
                targets[j] = nop_block.serial
                helper_logger.debug(
                    "insert_nop_blk: Updated m_jtbl case target in block %d: "
                    "%d -> %d (index %d)",
                    blk.serial, original_successor_serial, nop_block.serial, j,
                )

    nop_block.mark_lists_dirty()
    mba.mark_chains_dirty()
    return nop_block


def ensure_last_block_is_goto(mba: ida_hexrays.mbl_array_t, verify: bool = True) -> int:
    last_blk = mba.get_mblock(mba.qty - 2)
    if last_blk.nsucc() == 1:
        change_1way_block_successor(last_blk, last_blk.succset[0], verify=verify)
        return 1
    elif last_blk.nsucc() == 0:
        return 0
    else:
        raise ControlFlowException(
            "Last block {0} is not one way (not supported yet)".format(last_blk.serial)
        )


def duplicate_block(block_to_duplicate: ida_hexrays.mblock_t, verify: bool = True) -> tuple[ida_hexrays.mblock_t, ida_hexrays.mblock_t | None]:
    mba = block_to_duplicate.mba
    duplicated_blk = mba.copy_block(block_to_duplicate, mba.qty - 1)

    # Clean inherited predecessor set -- copy_block clones predecessors
    # from block_to_duplicate, but those predecessors point to the
    # original, not the duplicate.
    prev_pred_serials = [x for x in duplicated_blk.predset]
    for prev_serial in prev_pred_serials:
        duplicated_blk.predset._del(prev_serial)

    # Fix fall-through predecessor disruption: copy_block inserts the clone
    # at qty-1 (before exit), pushing the exit up. If clone.prevb is a
    # fall-through block (no explicit goto/jcond/ijmp), its physical
    # adjacency now targets the clone. IDA's verifier checks bidirectional
    # edge consistency, so we must ensure clone.predset contains prevb.
    #
    # For non-ret fall-through: insert explicit goto to the shifted exit.
    # For m_ret: skip - can't safely redirect without being verifier-hostile.
    # Clone edges will be rewired by callers (e.g. edge-split).
    prev_blk = duplicated_blk.prevb
    if prev_blk is not None and prev_blk.serial != block_to_duplicate.serial:
        tail = prev_blk.tail
        has_explicit_target = (
            tail is not None
            and (
                tail.opcode == ida_hexrays.m_goto
                or ida_hexrays.is_mcode_jcond(tail.opcode)
                or tail.opcode == ida_hexrays.m_ijmp
            )
        )
        if not has_explicit_target and prev_blk.nsucc() == 1:
            if tail is not None and tail.opcode == ida_hexrays.m_ret:
                # m_ret: can't safely redirect. Leave as-is.
                # Clone edges will be rewired by caller (edge-split).
                helper_logger.debug(
                    "  Skipping m_ret fall-through fix for blk[%d] (verifier-hostile)",
                    prev_blk.serial,
                )
            else:
                # Normal fall-through: insert explicit goto to shifted exit.
                original_target = prev_blk.succset[0]
                exit_serial = mba.qty - 1
                if original_target == duplicated_blk.serial:
                    original_target = exit_serial
                insert_goto_instruction(
                    prev_blk, original_target, nop_previous_instruction=False
                )
                prev_blk.succset._del(duplicated_blk.serial)
                if original_target not in [
                    prev_blk.succset[i] for i in range(prev_blk.succset.size())
                ]:
                    prev_blk.succset.push_back(original_target)
                prev_blk.type = ida_hexrays.BLT_1WAY
                prev_blk.flags |= ida_hexrays.MBL_GOTO
                prev_blk.mark_lists_dirty()
                helper_logger.debug(
                    "  Fixed fall-through: blk[%d] now gotos %d (was falling through to clone %d)",
                    prev_blk.serial,
                    original_target,
                    duplicated_blk.serial,
                )

    helper_logger.debug(
        "  Duplicated {0} -> {1}".format(
            block_to_duplicate.serial, duplicated_blk.serial
        )
    )
    duplicated_blk_default = None
    if (block_to_duplicate.tail is not None) and ida_hexrays.is_mcode_jcond(
        block_to_duplicate.tail.opcode
    ):
        block_to_duplicate_default_successor = mba.get_mblock(
            block_to_duplicate.nextb.serial
        )
        duplicated_blk_default = insert_nop_blk(duplicated_blk)
        change_1way_block_successor(
            duplicated_blk_default, block_to_duplicate.nextb.serial, verify=verify
        )
        helper_logger.debug(
            "  {0} is conditional, so created a default child {1} for {2} which goto {3}".format(
                block_to_duplicate.serial,
                duplicated_blk_default.serial,
                duplicated_blk.serial,
                block_to_duplicate_default_successor.serial,
            )
        )
    elif duplicated_blk.nsucc() == 1:
        helper_logger.debug(
            "  Making {0} goto {1}".format(
                duplicated_blk.serial, block_to_duplicate.succset[0]
            )
        )
        change_1way_block_successor(duplicated_blk, block_to_duplicate.succset[0], verify=verify)
    elif duplicated_blk.nsucc() == 0:
        helper_logger.debug(
            "  Duplicated block {0} has no successor => Nothing to do".format(
                duplicated_blk.serial
            )
        )

    # Post-copy type correction: copy_block clones the source block's type,
    # so a BLT_NWAY source block produces a BLT_NWAY duplicate even when the
    # tail/successor set no longer matches that expectation.  Downgrade the
    # type to whatever IDA's verifier actually requires.
    if duplicated_blk.type == ida_hexrays.BLT_NWAY:
        tail = duplicated_blk.tail
        nsucc = duplicated_blk.nsucc()
        if tail is not None and tail.opcode == ida_hexrays.m_goto and nsucc == 1:
            new_type = ida_hexrays.BLT_1WAY
            new_type_name = "BLT_1WAY"
        elif tail is None and nsucc == 0:
            new_type = ida_hexrays.BLT_STOP
            new_type_name = "BLT_STOP"
        elif tail is None and nsucc == 1:
            new_type = ida_hexrays.BLT_1WAY
            new_type_name = "BLT_1WAY"
        elif tail is not None and tail.opcode == ida_hexrays.m_jcnd and nsucc == 2:
            new_type = ida_hexrays.BLT_2WAY
            new_type_name = "BLT_2WAY"
        else:
            new_type = None
            new_type_name = None
        if new_type is not None:
            tail_opcode = tail.opcode if tail is not None else None
            helper_logger.debug(
                "duplicate_block: block %d downgraded BLT_NWAY->%s (tail=%s nsucc=%d)",
                duplicated_blk.serial,
                new_type_name,
                tail_opcode,
                nsucc,
            )
            duplicated_blk.type = new_type
            mba.mark_chains_dirty()

    return duplicated_blk, duplicated_blk_default


def change_block_address(block: ida_hexrays.mblock_t, new_ea: int):
    # Can be used to fix error 50357
    mb_curr = block.head
    while mb_curr:
        mb_curr.ea = new_ea
        mb_curr = mb_curr.next


def mba_remove_simple_goto_blocks(mba: ida_hexrays.mbl_array_t, verify: bool = True) -> int:
    last_block_index = mba.qty - 1
    nb_change = 0
    for goto_blk_serial in range(last_block_index):
        goto_blk: ida_hexrays.mblock_t = mba.get_mblock(goto_blk_serial)
        if goto_blk.is_simple_goto_block():
            goto_blk_dst_serial = goto_blk.tail.l.b
            goto_blk_preset = [x for x in goto_blk.predset]
            for father_serial in goto_blk_preset:
                father_blk: ida_hexrays.mblock_t = mba.get_mblock(father_serial)
                nb_change += update_blk_successor(
                    father_blk, goto_blk_serial, goto_blk_dst_serial, verify=verify
                )
    return nb_change


def mba_deep_cleaning(mba: ida_hexrays.mba_t, call_mba_combine_block=True) -> int:
    if mba.maturity < ida_hexrays.MMAT_CALLS:
        # Doing this optimization before MMAT_CALLS may create blocks with call instruction (not last instruction)
        # IDA does like that and will raise a 50864 error
        return 0
    if call_mba_combine_block:
        # Ideally we want IDA to simplify the graph for us with combine_blocks
        # However, We observe several crashes when this option is activated
        # (especially when it is used during  O-LLVM unflattening)
        # TODO: investigate the root cause of this issue
        mba.merge_blocks()
    else:
        if idaapi.IDA_SDK_VERSION >= 760:
            # In IDA Pro 7.6, remove_empty_blocks is removed and replaced (?) by remove_empty_and_unreachable_blocks
            mba.remove_empty_and_unreachable_blocks()
        else:
            mba.remove_empty_blocks()  # type: ignore
    nb_change = mba_remove_simple_goto_blocks(mba)
    return nb_change


def ensure_child_has_an_unconditional_father(
    father_block: ida_hexrays.mblock_t, child_block: ida_hexrays.mblock_t, verify: bool = True
) -> int:
    if father_block is None:
        return 0
    mba = father_block.mba
    if father_block.nsucc() == 1:
        return 0
    # This helper only supports conditional 2-way fathers.
    if father_block.nsucc() != 2 or father_block.tail is None:
        return 0

    if father_block.tail.d.b == child_block.serial:
        helper_logger.debug(
            "Father {0} is a conditional jump to child {1}, creating a new father".format(
                father_block.serial, child_block.serial
            )
        )
        # Create a detached helper block that unconditionally jumps to child.
        # Do NOT use insert_nop_blk() here: it splices into an existing edge
        # and can leave orphaned append-only helper blocks in this workflow.
        new_father_block = create_standalone_block(
            father_block,
            blk_ins=[],
            target_serial=child_block.serial,
            is_0_way=False,
            verify=verify,
        )
        if new_father_block is None:
            return 0
        if not change_2way_block_conditional_successor(
            father_block, new_father_block.serial, verify=verify
        ):
            return 0
    else:
        # Default-child rewrites require re-homing a conditional fallthrough
        # edge. With append-only helper block creation, creating a detached NOP
        # block here can leave orphaned blocks (preds=[]), which then trips
        # mba.verify() (INTERR 50856). Skip this transformation for now.
        helper_logger.info(
            "Father %d is a conditional jump to child %d (default child); "
            "skipping unconditional-father rewrite to avoid orphan block creation",
            father_block.serial,
            child_block.serial,
        )
        return 0
    return 1


def downgrade_nway_null_tail_to_1way(
    blk: "ida_hexrays.mblock_t",
    dispatcher_entry_serial: int,
    verify: bool = True,
) -> bool:
    """Atomically downgrade a degenerate BLT_NWAY block (null tail) to BLT_1WAY.

    A BLT_NWAY block can end up with a null tail and exactly 2 successors when
    all jtbl cases have been resolved away but the block type was never updated.
    This leaves the CFG in an illegal state (INTERR 50860) because IDA's verifier
    requires BLT_NWAY blocks to have a valid m_jtbl tail.

    This function handles the specific case where:
    - ``blk.type == BLT_NWAY`` (type==3 or ida_hexrays.BLT_NWAY)
    - ``blk.tail is None``
    - ``blk.nsucc() == 2`` with one successor being the dispatcher entry trampoline

    It atomically:
    1. Inserts a ``m_goto`` tail pointing to the non-dispatcher successor
    2. Sets ``blk.type = BLT_1WAY``
    3. Removes the dispatcher trampoline from ``blk.succset`` and its ``predset``

    Args:
        blk: The degenerate BLT_NWAY block to downgrade.
        dispatcher_entry_serial: Serial of the dispatcher entry block (the
            successor to remove).
        verify: If True, call ``mba.verify()`` after mutation.

    Returns:
        True if the downgrade was applied, False if preconditions not met.
    """
    if blk is None:
        return False
    # Preconditions
    if blk.type != ida_hexrays.BLT_NWAY:
        return False
    if blk.tail is not None:
        return False
    if blk.nsucc() != 2:
        return False

    mba = blk.mba
    succ_serials = [int(blk.succset[i]) for i in range(blk.succset.size())]
    if dispatcher_entry_serial not in succ_serials:
        return False

    non_dispatcher_serials = [s for s in succ_serials if s != dispatcher_entry_serial]
    if len(non_dispatcher_serials) != 1:
        return False
    keep_serial = non_dispatcher_serials[0]

    helper_logger.debug(
        "downgrade_nway_null_tail_to_1way: blk %d BLT_NWAY null-tail "
        "succset=%s -> BLT_1WAY goto blk %d (dropping dispatcher trampoline %d)",
        blk.serial, succ_serials, keep_serial, dispatcher_entry_serial,
    )

    # 1. Insert m_goto tail pointing to the surviving successor
    insert_goto_instruction(blk, keep_serial, nop_previous_instruction=False)

    # 2. Atomically set block type
    blk.type = ida_hexrays.BLT_1WAY
    blk.flags |= ida_hexrays.MBL_GOTO

    # 3. Rewire succset: remove trampoline, keep only surviving successor
    blk.succset._del(dispatcher_entry_serial)
    blk.mark_lists_dirty()

    # 4. Remove blk from trampoline's predset
    trampoline_blk = mba.get_mblock(dispatcher_entry_serial)
    if trampoline_blk is not None:
        trampoline_blk.predset._del(blk.serial)
        if trampoline_blk.serial != mba.qty - 1:
            trampoline_blk.mark_lists_dirty()

    # 5. Ensure blk is in surviving successor's predset
    keep_blk = mba.get_mblock(keep_serial)
    if keep_blk is not None:
        if not _serial_in_predset(keep_blk, blk.serial):
            keep_blk.predset.push_back(blk.serial)
        if keep_blk.serial != mba.qty - 1:
            keep_blk.mark_lists_dirty()

    mba.mark_chains_dirty()

    if not verify:
        return True
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error(
            "downgrade_nway_null_tail_to_1way: verify failed for blk %d: %s",
            blk.serial, e,
        )
        log_block_info(blk, helper_logger.error)
        raise


def remove_block_edge(
    blk: ida_hexrays.mblock_t,
    to_serial: int,
    verify: bool = True,
) -> bool:
    """Remove a single edge from *blk* to *to_serial*.

    Semantics depend on the source block's current successor count:

    * **2-way → 1-way**: The conditional branch is NOP'd and replaced with an
      unconditional goto to the *remaining* successor.  Equivalent to
      ``make_2way_block_goto(blk, remaining_succ)``.
    * **1-way → 0-way**: The goto instruction (if present) is NOP'd and the
      block becomes ``BLT_0WAY``.

    Args:
        blk: Source block whose outgoing edge is removed.
        to_serial: Serial of the successor to disconnect.
        verify: If ``True``, run ``mba.verify()`` after the mutation.

    Returns:
        ``True`` on success (and verify passed if enabled).

    Example:
        >>> # Remove the conditional branch target from a 2-way block
        >>> remove_block_edge(blk, conditional_target, verify=False)
        True
    """
    mba = blk.mba
    nsucc = blk.nsucc()

    if nsucc == 2:
        # Determine the surviving successor (the one NOT being removed).
        succs = [s for s in blk.succset]
        if to_serial not in succs:
            helper_logger.warning(
                "remove_block_edge: block %d does not have successor %d "
                "(succs=%s)",
                blk.serial, to_serial, succs,
            )
            return False
        remaining = [s for s in succs if s != to_serial]
        if not remaining:
            helper_logger.warning(
                "remove_block_edge: block %d has both successors == %d; "
                "cannot determine remaining target",
                blk.serial, to_serial,
            )
            return False
        return make_2way_block_goto(blk, remaining[0], verify=verify)

    if nsucc == 1:
        if blk.succset[0] != to_serial:
            helper_logger.warning(
                "remove_block_edge: block %d successor is %d, not %d",
                blk.serial, blk.succset[0], to_serial,
            )
            return False

        # NOP the terminating goto if present.
        if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_goto:
            blk.make_nop(blk.tail)

        return _rewire_edge(
            blk,
            old_succs=[to_serial],
            new_succs=[],
            new_block_type=ida_hexrays.BLT_0WAY,
            verify=verify,
        )

    helper_logger.warning(
        "remove_block_edge: block %d has %d successors; only 1-way and "
        "2-way blocks are supported",
        blk.serial, nsucc,
    )
    return False


__all__ = [
    "_rewire_edge",
    "insert_goto_instruction",
    "change_1way_call_block_successor",
    "change_1way_block_successor",
    "change_0way_block_successor",
    "change_2way_block_conditional_successor",
    "update_blk_successor",
    "make_2way_block_goto",
    "create_block",
    "create_standalone_block",
    "update_block_successors",
    "_update_jtbl_case_targets",
    "coalesce_jtbl_cases",
    "retarget_jtbl_block_cases",
    "convert_jtbl_to_goto",
    "_get_fallthrough_successor_serial",
    "insert_nop_blk",
    "ensure_last_block_is_goto",
    "duplicate_block",
    "change_block_address",
    "mba_remove_simple_goto_blocks",
    "mba_deep_cleaning",
    "ensure_child_has_an_unconditional_father",
    "downgrade_nway_null_tail_to_1way",
    "remove_block_edge",
]
