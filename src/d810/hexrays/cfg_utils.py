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
    if blk.tail is not None:
        goto_ins = ida_hexrays.minsn_t(blk.tail)
    else:
        goto_ins = ida_hexrays.minsn_t(blk.start)

    if nop_previous_instruction:
        blk.make_nop(blk.tail)
    blk.insert_into_block(goto_ins, blk.tail)

    # We nop instruction before setting it to goto to avoid error 52123
    blk.make_nop(blk.tail)
    goto_ins.opcode = ida_hexrays.m_goto
    goto_ins.l = ida_hexrays.mop_t()
    goto_ins.l.make_blkref(goto_blk_serial)


def change_1way_call_block_successor(
    call_blk: ida_hexrays.mblock_t, call_blk_successor_serial: int
) -> bool:
    if call_blk.nsucc() != 1:
        return False

    mba = call_blk.mba
    previous_call_blk_successor_serial = call_blk.succset[0]
    previous_call_blk_successor = mba.get_mblock(previous_call_blk_successor_serial)

    nop_blk = insert_nop_blk(call_blk)
    insert_goto_instruction(
        nop_blk, call_blk_successor_serial, nop_previous_instruction=True
    )
    is_ok = change_1way_block_successor(nop_blk, call_blk_successor_serial)
    if not is_ok:
        return False

    # Bookkeeping
    call_blk.succset._del(previous_call_blk_successor_serial)
    call_blk.succset.push_back(nop_blk.serial)
    call_blk.mark_lists_dirty()

    previous_call_blk_successor.predset._del(call_blk.serial)
    if previous_call_blk_successor.serial != mba.qty - 1:
        previous_call_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_1way_block_successor: {0}".format(e))
        log_block_info(call_blk, helper_logger.error)
        log_block_info(nop_blk, helper_logger.error)
        raise e


def change_1way_block_successor(blk: ida_hexrays.mblock_t, blk_successor_serial: int) -> bool:
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
            return change_1way_call_block_successor(blk, blk_successor_serial)
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
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_1way_block_successor: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        log_block_info(previous_blk_successor, helper_logger.error)
        raise e


def change_0way_block_successor(blk: ida_hexrays.mblock_t, blk_successor_serial: int) -> bool:
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
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in change_0way_block_successor: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        raise e


def change_2way_block_conditional_successor(
    blk: ida_hexrays.mblock_t, blk_successor_serial: int
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
    blk: ida_hexrays.mblock_t, old_successor_serial: int, new_successor_serial: int
) -> int:
    if blk.nsucc() == 1:
        change_1way_block_successor(blk, new_successor_serial)
    elif blk.nsucc() == 2:
        if old_successor_serial == blk.nextb.serial:
            helper_logger.info(
                "Can't update direct block successor: {0} - {1} - {2}".format(
                    blk.serial, old_successor_serial, new_successor_serial
                )
            )
            return 0
        else:
            change_2way_block_conditional_successor(blk, new_successor_serial)
    else:
        helper_logger.info("Can't update block successor: {0} ".format(blk.serial))
        return 0
    return 1


def make_2way_block_goto(blk: ida_hexrays.mblock_t, blk_successor_serial: int) -> bool:
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
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        helper_logger.error("Error in make_2way_block_goto: {0}".format(e))
        log_block_info(blk, helper_logger.error)
        log_block_info(new_blk_successor, helper_logger.error)
        raise e


def create_block(
    blk: ida_hexrays.mblock_t, blk_ins: list[ida_hexrays.minsn_t], is_0_way: bool = False
) -> ida_hexrays.mblock_t:
    mba = blk.mba
    new_blk = insert_nop_blk(blk)
    for ins in blk_ins:
        tmp_ins = ida_hexrays.minsn_t(ins)
        tmp_ins.setaddr(new_blk.tail.ea)
        new_blk.insert_into_block(tmp_ins, new_blk.tail)

    if is_0_way:
        new_blk.type = ida_hexrays.BLT_0WAY
        # Bookkeeping
        prev_successor_serial = new_blk.succset[0]
        new_blk.succset._del(prev_successor_serial)
        prev_succ = mba.get_mblock(prev_successor_serial)
        prev_succ.predset._del(new_blk.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()

    new_blk.mark_lists_dirty()
    mba.mark_chains_dirty()
    try:
        mba.verify(True)
        return new_blk
    except RuntimeError as e:
        helper_logger.error("Error in create_block: {0}".format(e))
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


def insert_nop_blk(blk: ida_hexrays.mblock_t) -> ida_hexrays.mblock_t:
    mba = blk.mba
    nop_block = mba.copy_block(blk, blk.nextb.serial)
    cur_ins = nop_block.head
    if cur_ins == None:
        cur_inst = ida_hexrays.minsn_t(blk.start)
        cur_inst.opcode = ida_hexrays.m_nop
        nop_block.insert_into_block(cur_inst, nop_block.head)
    else:
        while cur_ins is not None:
            nop_block.make_nop(cur_ins)
            cur_ins = cur_ins.next

    nop_block.type = ida_hexrays.BLT_1WAY

    # We might have clone a block with multiple or no successor, thus we need to clean all
    prev_successor_serials = [x for x in nop_block.succset]

    # Bookkeeping
    for prev_successor_serial in prev_successor_serials:
        nop_block.succset._del(prev_successor_serial)
        prev_succ = mba.get_mblock(prev_successor_serial)
        prev_succ.predset._del(nop_block.serial)
        if prev_succ.serial != mba.qty - 1:
            prev_succ.mark_lists_dirty()

    nop_block.succset.push_back(nop_block.serial + 1)
    nop_block.mark_lists_dirty()

    new_blk_successor = mba.get_mblock(nop_block.serial + 1)
    new_blk_successor.predset.push_back(nop_block.serial)
    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    mba.mark_chains_dirty()
    try:
        mba.verify(True)
        return nop_block
    except RuntimeError as e:
        helper_logger.error("Error in insert_nop_blk: {0}".format(e))
        log_block_info(nop_block, helper_logger.error)
        raise e


def ensure_last_block_is_goto(mba: ida_hexrays.mbl_array_t) -> int:
    last_blk = mba.get_mblock(mba.qty - 2)
    if last_blk.nsucc() == 1:
        change_1way_block_successor(last_blk, last_blk.succset[0])
        return 1
    elif last_blk.nsucc() == 0:
        return 0
    else:
        raise ControlFlowException(
            "Last block {0} is not one way (not supported yet)".format(last_blk.serial)
        )


def duplicate_block(block_to_duplicate: ida_hexrays.mblock_t) -> tuple[ida_hexrays.mblock_t, ida_hexrays.mblock_t | None]:
    mba = block_to_duplicate.mba
    duplicated_blk = mba.copy_block(block_to_duplicate, mba.qty - 1)
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
            block_to_duplicate.serial + 1
        )
        duplicated_blk_default = insert_nop_blk(duplicated_blk)
        change_1way_block_successor(
            duplicated_blk_default, block_to_duplicate.serial + 1
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
        change_1way_block_successor(duplicated_blk, block_to_duplicate.succset[0])
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


def mba_remove_simple_goto_blocks(mba: ida_hexrays.mbl_array_t) -> int:
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
                    father_blk, goto_blk_serial, goto_blk_dst_serial
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
    father_block: ida_hexrays.mblock_t, child_block: ida_hexrays.mblock_t
) -> int:
    if father_block is None:
        return 0
    mba = father_block.mba
    if father_block.nsucc() == 1:
        return 0

    if father_block.tail.d.b == child_block.serial:
        helper_logger.debug(
            "Father {0} is a conditional jump to child {1}, creating a new father".format(
                father_block.serial, child_block.serial
            )
        )
        new_father_block = insert_nop_blk(mba.get_mblock(mba.qty - 2))
        change_1way_block_successor(new_father_block, child_block.serial)
        change_2way_block_conditional_successor(father_block, new_father_block.serial)
    else:
        helper_logger.info(
            "Father {0} is a conditional jump to child {1} (default child), creating a new father".format(
                father_block.serial, child_block.serial
            )
        )
        new_father_block = insert_nop_blk(father_block)
        change_1way_block_successor(new_father_block, child_block.serial)
    return 1
