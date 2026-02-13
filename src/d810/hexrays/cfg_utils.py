from __future__ import annotations

import contextlib
import functools
import logging

import ida_hexrays
import idaapi

from d810.core import getLogger
from d810.errors import ControlFlowException
from d810.hexrays.hexrays_formatters import block_printer
from d810.hexrays.hexrays_helpers import CONDITIONAL_JUMP_OPCODES

helper_logger = getLogger(__name__)

_VALID_MOP_SIZES = frozenset({1, 2, 4, 8, 16})


def safe_make_number(mop, value, size):
    """Create a number operand with validated size.

    If *size* is not one of the valid IDA operand sizes (1, 2, 4, 8, 16),
    it is replaced with 4 (32-bit) to prevent a zero-size ``mop_n`` from
    crashing Hex-Rays' C++ verify / optimize_local passes.
    """
    if size not in _VALID_MOP_SIZES:
        helper_logger.warning("Invalid mop size %d, defaulting to 4", size)
        size = 4
    mask = (1 << (size * 8)) - 1
    mop.make_number(value & mask, size)


def log_block_info(blk: ida_hexrays.mblock_t, logger_func=helper_logger.info, ctx: str = ""):
    if blk is None:
        logger_func("Block is None")
        return
    if ctx:
        logger_func("%s", ctx)
    vp = block_printer()
    blk._print(vp)
    logger_func(
        "Block %s with successors %s and predecessors %s:\n%s",
        blk.serial,
        list(blk.succset),
        list(blk.predset),
        vp.get_block_mc(),
    )


@functools.lru_cache(maxsize=1024)
def _get_mba_frame_size(mba: ida_hexrays.mba_t | None) -> int | None:
    """Return cached frame size for an MBA (fast C-level functools cache)."""
    if mba is None:
        return None
    for att in ("minstkref", "stacksize", "frsize", "fullsize"):
        val = getattr(mba, att, None)
        if val:
            return val
    return None


# Optional second-level cache: one name per SSA *valnum* (fast path)
_VALNUM_NAME_CACHE: dict[int, str] = {}


@functools.lru_cache(maxsize=16384)
def _cached_stack_var_name(
    mop_identity: int,  #  not used in the function but we need this bad boy for caching
    t: int,
    reg_or_off: int,
    size: int,
    valnum: int,
    frame_size: int | None,
) -> str:
    """Compute & cache printable variable names (identity-based)."""
    if t == ida_hexrays.mop_S:
        if frame_size is not None and frame_size >= reg_or_off:
            disp = frame_size - reg_or_off
            base = f"%var_{disp:X}.{size}"
        else:
            base = f"stk_{reg_or_off:X}.{size}"
    else:  # mop_r
        base = ida_hexrays.get_mreg_name(reg_or_off, size)
    return f"{base}{{{valnum}}}"


def get_stack_var_name(mop: ida_hexrays.mop_t) -> str | None:
    """Return a stable human-readable name for *mop*.

    Fast path: lookup by ``mop.valnum`` in `_VALNUM_NAME_CACHE`.  Falls back to
    identity-based LRU cache on a miss.
    """
    cached = _VALNUM_NAME_CACHE.get(mop.valnum)
    if cached is not None:
        return cached

    if mop.t == ida_hexrays.mop_S:
        frame_size = _get_mba_frame_size(getattr(mop.s, "mba", None))
        name = _cached_stack_var_name(
            id(mop), mop.t, mop.s.off, mop.size, mop.valnum, frame_size
        )
    elif mop.t == ida_hexrays.mop_r:
        name = _cached_stack_var_name(id(mop), mop.t, mop.r, mop.size, mop.valnum, None)
    else:
        return None
    return name

    _VALNUM_NAME_CACHE[mop.valnum] = name
    return name


def extract_base_and_offset(mop: ida_hexrays.mop_t) -> tuple[ida_hexrays.mop_t | None, int]:
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_add
    ):
        # (base + const)
        if mop.d.l and mop.d.l.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.r.nnn.value if mop.d.r and mop.d.r.t == ida_hexrays.mop_n else 0
            return mop.d.l, off
        if mop.d.r and mop.d.r.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.l.nnn.value if mop.d.l and mop.d.l.t == ida_hexrays.mop_n else 0
            return mop.d.r, off
    return None, 0


def safe_verify(
    mba: ida_hexrays.mba_t, ctx: str, logger_func=helper_logger.error
) -> None:
    """Run mba.verify(True) and produce helpful diagnostics on failure."""
    try:
        mba.verify(True)
    except RuntimeError as e:
        logger_func("verify failed after %s: %s", ctx, e, exc_info=True)
        # attempt to locate problematic blocks: dump the last two blocks if possible
        with contextlib.suppress(Exception):
            divider = "-" * 14
            if (num_blocks := mba.qty) != 0:
                if num_blocks >= 2:
                    log_block_info(
                        mba.get_mblock(num_blocks - 2),
                        logger_func,
                        f"{divider}[blk -2]{divider}",
                    )
                    log_block_info(
                        mba.get_mblock(num_blocks - 1),
                        logger_func,
                        f"{divider}[blk -1]{divider}",
                    )
                log_block_info(
                    mba.get_mblock(0), logger_func, f"{divider}[blk 0]{divider}"
                )
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
    blk: ida_hexrays.mblock_t, blk_successor_serial: int, verify: bool = True
) -> bool:
    if blk.nsucc() != 2:
        return False

    mba = blk.mba
    previous_blk_conditional_successor_serial = blk.tail.d.b
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


def convert_jtbl_to_goto(
    blk: "ida_hexrays.mblock_t",
    new_target_serial: int,
    mba: "ida_hexrays.mba_t",
) -> bool:
    """Convert an m_jtbl tail instruction to a direct m_goto.

    Ported from copycat deflatten.cpp:2063-2126. Safely converts a
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


def _serial_in_predset(blk: "ida_hexrays.mblock_t", serial: int) -> bool:
    """Check if *serial* is already present in *blk*'s predset."""
    for i in range(blk.predset.size()):
        if blk.predset[i] == serial:
            return True
    return False


def insert_nop_blk(blk: ida_hexrays.mblock_t) -> ida_hexrays.mblock_t:
    mba = blk.mba
    # Append the new block at the end of the MBA (before the dummy last block)
    # instead of inserting in the middle.  Inserting in the middle shifts all
    # block serials >= the insertion point by +1 but does NOT update operand
    # references (m_goto .l.b, jcond .d.b, m_jtbl case targets), leading to
    # stale serial references and segfaults in later passes.
    original_successor_serial = blk.nextb.serial
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
        # For multi-way blocks we still wire nop_block -> original_successor
        # (already done above via succset.push_back).  The original_successor
        # gains nop_block as an additional predecessor; blk remains in its
        # predset as well (the caller will clean this up).
        original_successor_blk.predset.push_back(nop_block.serial)
        if original_successor_blk.serial != mba.qty - 1:
            original_successor_blk.mark_lists_dirty()

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

    return duplicated_blk, duplicated_blk_default


def change_block_address(block: ida_hexrays.mblock_t, new_ea: int):
    # Can be used to fix error 50357
    mb_curr = block.head
    while mb_curr:
        mb_curr.ea = new_ea
        mb_curr = mb_curr.next


def is_conditional_jump(blk: ida_hexrays.mblock_t) -> bool:
    if (blk is not None) and (blk.tail is not None):
        return blk.tail.opcode in CONDITIONAL_JUMP_OPCODES
    return False


def is_indirect_jump(blk: ida_hexrays.mblock_t) -> bool:
    if (blk is not None) and (blk.tail is not None):
        return blk.tail.opcode == ida_hexrays.m_ijmp
    return False


def get_block_serials_by_address(mba: ida_hexrays.mbl_array_t, address: int) -> list[int]:
    blk_serial_list = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start == address:
            blk_serial_list.append(i)
    return blk_serial_list


def get_block_serials_by_address_range(mba: ida_hexrays.mbl_array_t, address: int) -> list[int]:
    blk_serial_list = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start <= address <= blk.end:
            blk_serial_list.append(i)
    return blk_serial_list


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
