from __future__ import annotations

import dataclasses
import enum
import hashlib
import logging
import typing
import weakref

from d810.hexrays_formatters import format_minsn_t  # optional, for logging
from d810.hexrays_helpers import MicrocodeHelper, MicrocodeInstruction
from d810.optimizers.flow.handler import FlowOptimizationRule

import ida_hexrays
import ida_idaapi
import ida_lines
import ida_pro
import ida_xref

logger = logging.getLogger("D810.unflattener_cf")


MIN_NUM_COMPARISONS = 2
GOTO_NOT_SINGLE = -1


class TraversalEnum(enum.IntEnum):
    CONTINUE = 0
    STOP = 1
    SKIP = 2


@dataclasses.dataclass
class mov_info_t:
    op_copy: typing.Optional[ida_hexrays.mop_t] = None
    ins_mov: typing.Optional[ida_hexrays.minsn_t] = None
    block: int = -1


def insert_op(
    blk: ida_hexrays.mblock_t, ml: ida_hexrays.mlist_t, op: ida_hexrays.mop_t
) -> bool:
    """
    Put an mop_t into an mlist_t. The op must be either a register or a stack
    variable.
    """
    if op.t not in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
        return False

    # I needed help from Hex-Rays with this line. Some of the example plugins
    # showed how to insert a register into an mlist_t. None of them showed
    # how to insert a stack variable. I figured out a way to do it by reverse
    # engineering Hex-Rays, but it seemed really janky. This is The Official
    # Method (TM).
    blk.append_use_list(ml, op, ida_hexrays.MUST_ACCESS)
    return True


def my_find_def_backwards(
    blk: ida_hexrays.mblock_t,
    ml: ida_hexrays.mlist_t,
    start: ida_hexrays.minsn_t | None,
) -> ida_hexrays.minsn_t | None:
    """
    Ilfak sent me this function in response to a similar support request. It
    walks backwards through a block, instruction-by-instruction, looking at
    what each instruction defines. It stops when it finds definitions for
    everything in the mlist_t, or when it hits the beginning of the block.
    """
    m_end = blk.head
    p = start if start else blk.tail
    while p:
        _def = blk.build_def_list(p, ida_hexrays.MAY_ACCESS | ida_hexrays.FULL_XDSU)
        if _def.includes(ml):
            return p
        p = p.prev


def my_find_def_forwards(
    blk: ida_hexrays.mblock_t,
    ml: ida_hexrays.mlist_t,
    start: ida_hexrays.minsn_t | None,
) -> ida_hexrays.minsn_t | None:
    """
    This is a nearly identical version of the function above, except it works
    in the forward direction rather than backwards.
    """
    m_end = blk.head
    p = start if start else blk.head
    while p:
        _def = blk.build_def_list(p, ida_hexrays.MAY_ACCESS | ida_hexrays.FULL_XDSU)
        if _def.includes(ml):
            return p
        p = p.next


def find_numeric_def_backwards(
    blk: ida_hexrays.mblock_t,
    op: ida_hexrays.mop_t,
    chain: list[mov_info_t],
    recursive: bool,
    allow_multi_succs: bool,
    block_stop: int,
) -> tuple[bool, ida_hexrays.mop_t | None]:
    """
    This function has way too many arguments. Basically, it's a wrapper around
    my_find_def_backwards from above. It is extended in the following ways:
    * If my_find_def_backwards identifies a definition of the variable "op"
      which is an assignment from another variable, this function then continues
      looking for numeric assignments to that variable (and recursively so, if
      that variable is in turn assigned from another variable).
    * It keeps a list of all the assignment instructions it finds along the way,
      storing them in the vector passed as the "chain" argument.
    * It has support for traversing more than one basic block in a graph, if
      the bRecursive argument is true. It won't traverse into blocks with more
      than one successor if bAllowMultiSuccs is false. In any case, it will
      never traverse past the block numbered iBlockStop, if that parameter is
      non-negative.
    """
    logger.debug(
        f"blk = {blk.serial}, op = {op.dstr()}, chain = {chain}, block_stop = {block_stop}"
    )
    mba = blk.mba
    ml = ida_hexrays.mlist_t()
    if not insert_op(blk, ml, op):
        return False, None

    # Start from the end of the block. This variable gets updated when a copy
    # is encountered, so that subsequent searches start from the right place.
    start = None
    while True:
        # Told you this function was just a wrapper around
        # my_find_def_backwards.
        _def = my_find_def_backwards(blk, ml, start)
        if _def:
            # Ensure that it's a mov instruction. We don't want, for example,
            # an "stx" instruction, which is assumed to redefine everything
            # until its aliasing information is refined.
            if _def.opcode != ida_hexrays.m_mov:
                logger.error(
                    "FindNumericDef: found %s" % MicrocodeInstruction.repr(_def)
                )
                return False, None

            # Now that we found a mov, add it to the chain.
            mi = mov_info_t()
            mi.op_copy = _def.l
            mi.block = blk.serial
            mi.ins_mov = _def
            chain.append(mi)

            # Was it a numeric assignment?
            if _def.l.t == ida_hexrays.mop_n:
                # Great! We're done.
                return True, _def.l

            tag = _def.l._print()
            assert tag
            # Otherwise, if it was not a numeric assignment, then try to track
            # whatever was assigned to it. This can only succeed if the thing
            # that was assigned was a register or stack variable.
            logger.info(f"Now tracking {ida_lines.tag_remove(tag)}")

            # Try to start tracking the other thing...
            ml.clear()
            if not insert_op(blk, ml, _def.l):
                return False, None
            start = _def
        else:
            # Otherwise, we did not find a definition of the currently-tracked
            # variable on this block. Try to continue if the parameters allow.

            # If recursion was disallowed, or we reached the topmost legal
            # block, then quit.
            if not recursive or blk.serial == block_stop:
                return False, None

            # If the block has more than one predecessor, then we can't
            # continue.
            if blk.npred() != 1:
                return False, None

            # Recurse into sole predecessor block
            pred = blk.pred(0)
            blk = mba.get_mblock(pred)

            # If the predecessor has more than one successor, check to see
            # whether the arguments allow that.
            if not allow_multi_succs and blk.nsucc() != 1:
                return False, None

            # Resume the search at the end of the new block.
            start = None
    return False, None


def find_forward_numeric_def(
    blk: ida_hexrays.mblock_t, mop: ida_hexrays.mop_t
) -> tuple[bool, ida_hexrays.mop_t | None, ida_hexrays.minsn_t | None]:
    """
    This function is just a thin wrapper around find_forward_numeric_def, which
    also inserts the mov into the "chain" argument.
    """
    ml = ida_hexrays.mlist_t()
    if not insert_op(blk, ml, mop):
        return False, None, None

    # Find a forward definition
    assign_insn = my_find_def_forwards(blk, ml, None)
    if not assign_insn:
        return False, None, None
    tag = assign_insn._print()
    assert tag
    # We only want MOV instructions with numeric left-hand sides
    logger.info(f"Forward search found {ida_lines.tag_remove(tag)}")
    if assign_insn.opcode != ida_hexrays.m_mov or assign_insn.l.t != ida_hexrays.mop_n:
        return False, None, None

        # Return the numeric operand if we found it
        return True, assign_insn.l, assign_insn
        return True, assign_insn.l, assign_insn
    return False, None, None
    return True, assign_insn.l, assign_insn
    return False, None, None


def find_forward_stack_var_def(
    cluster_head: ida_hexrays.mblock_t,
    op_copy: ida_hexrays.mop_t,
    chain: list[mov_info_t],
) -> ida_hexrays.mop_t | None:
    """
    This function is just a thin wrapper around find_forward_numeric_def, which
    also inserts the mov into the "chain" argument.
    """
    if not op_copy or op_copy.t != ida_hexrays.mop_S:
        return None

    # Find the definition
    ok, num, ins = find_forward_numeric_def(cluster_head, op_copy)
    if not ok:
        return None

    assert num
    tag = num._print()
    assert tag
    logger.info(f"Forward method found {ida_lines.tag_remove(tag)}!")

    # If the found definition was suitable, add the assignment to the chain
    mi = mov_info_t()
    mi.op_copy = num
    mi.block = cluster_head.serial
    mi.ins_mov = ins
    chain.append(mi)
    # Return the number
    return num


def append_goto_onto_non_empty_block(blk, block_dest):
    """
    Append a goto onto a non-empty block, which is assumed not to already have
    a goto at the end of it.
    """
    # Allocate a new instruction, using the tail address
    new_goto = ida_hexrays.minsn_t(blk.tail.ea)

    # Create a goto instruction to the specified block
    new_goto.opcode = ida_hexrays.m_goto
    new_mop = ida_hexrays.mop_t()
    new_mop.t = ida_hexrays.mop_b
    new_mop.b = block_dest
    new_mop.size = ida_hexrays.NOSIZE
    new_goto.l = new_mop

    # Add it onto the block
    blk.insert_into_block(new_goto, blk.tail)


def change_single_target(blk, old, new):
    """
    For a block with a single successor, change its target from some old block
    to a new block. This is only on the graph level, not in terms of gotos.
    """
    mba = blk.mba

    # Overwrite the successor with the new target
    blk.succset[0] = new

    # Add this block to the predecessor set of the target
    mba.get_mblock(new).predset.push_back(blk.serial)

    # Remove this block from the predecessor set of the old target
    mba.get_mblock(old).predset._del(blk.serial)


def remove_single_gotos(mba):
    """
    This function eliminates transfers to blocks with a single goto on them.
    Either if a given block has a goto at the end of it, where the destination
    is a block with a single goto on it, or if the block doesn't end in a goto,
    but simply falls through to a block with a single goto on it. Also, this
    process happens recursively; i.e., if A goes to B, and B goes to C, and C
    goes to D, then after we've done our tranformations, A will go to D.
    """
    # This information determines, ultimately, to which block a goto will go.
    # As mentioned in the function comment, this accounts for gotos-to-gotos.
    forwarder_info = [0] * mba.qty

    # For each block
    for i in range(mba.qty):
        # Begin by initializing its information to say that it does not
        # consist of a single goto. Update later if it does.
        forwarder_info[i] = GOTO_NOT_SINGLE
        b = mba.get_mblock(i)

        # Get the block and skip any "assert" instructions.
        m2 = ida_hexrays.getf_reginsn(b.head)

        # Is the first non-assert instruction a goto?
        if not m2 or m2.opcode != ida_hexrays.m_goto or m2.l.t != ida_hexrays.mop_b:
            continue

        logger.debug(f"[+] Single goto found for block num = {b.serial}")
        # If it was a goto, record the destination block number
        forwarder_info[i] = m2.l.b

    rc = 0

    # Now, actually replace transfer-to-goto blocks with their destinations.
    for i in range(mba.qty):
        blk = mba.get_mblock(i)

        # FYI, don't screw with blocks that have calls at the end of them.
        # You'll get an INTERR. Also, if this block has more than one
        # successor, then it couldn't possibly be a transfer to a goto.
        # (blk->is_call_block() || blk->nsucc() != 1)
        if blk.is_call_block() or blk.nsucc() != 1:
            continue

        # Get the last instruction on the block
        mgoto = blk.tail
        if not mgoto:
            continue

        # Now, look up the block number of the destination.
        was_goto = mgoto.opcode == ida_hexrays.m_goto

        # If the last instruction was a goto, get the information from there.
        # Otherwise, take the number of the only successor block.
        original_goto_target = mgoto.l.b if was_goto else blk.succ(0)
        goto_target = original_goto_target
        should_replace = False
        visited = []

        # Keep looping while we still find goto-to-gotos.
        while True:
            # Keep track of the blocks we've seen so far, so we don't end up
            # in an infinite loop if the goto blocks form a cycle in the
            # graph.
            if goto_target in visited:
                should_replace = False
                break
            else:
                visited.append(goto_target)

            # Once we find the first non-single-goto block, stop.
            if forwarder_info[goto_target] == GOTO_NOT_SINGLE:
                break

            # If we find at least one single goto at the destination, then
            # indicate that we should replace. Keep looping, though, to find
            # the ultimate destination.
            should_replace = True
            logger.debug("[+] Replacing single goto target")

            # Now check: did the single-goto block also target a single-goto
            # block?
            goto_target = forwarder_info[goto_target]

        # If the target wasn't a single-goto block, or there was an infinite
        # loop in the graph, don't touch this block.
        if not should_replace:
            continue

        # Otherwise, update the destination with the final target.

        if was_goto:
            # If the block had a goto, overwrite its block destination.
            mgoto.l.b = goto_target
        else:
            # Otherwise, add a goto onto the block. You might think you could skip
            # this step and just change the successor information, but you'll get
            # an INTERR if you do.
            append_goto_onto_non_empty_block(blk, goto_target)

        # Change the successor/predecessor information for this block and its
        # old and new target.
        change_single_target(blk, original_goto_target, goto_target)

        # Counter of the number of blocks changed.
        rc += 1
    return rc


def extract_jcc_parts(
    pred1: ida_hexrays.mblock_t,
) -> tuple[bool, ida_hexrays.mblock_t | None, int, int]:
    """
    For a block that ends in a conditional jump, extract the integer block
    numbers for the "taken" and "not taken" cases.
    """
    # Check if the block ends with a conditional jump
    if ida_hexrays.is_mcode_jcond(pred1.tail.opcode):
        if pred1.tail.d.t != ida_hexrays.mop_b:
            logger.info(
                "extract_jcc_parts: block was jcc, but destination was %s, not mop_b"
                % (MicrocodeHelper.get_mopt_name(pred1.tail.d.t))
            )
            return False, None, -1, -1
        ends_with_jcc = pred1
        _tail: ida_hexrays.minsn_t = pred1.tail
        _dest_operand: ida_hexrays.mop_t = _tail.d
        jcc_dest: int = _dest_operand.b  # byte value

        # The fallthrough location is the block that's not directly targeted
        # by the jcc instruction. Determine that by looking at the successors.
        # I guess technically Hex-Rays enforces that it must be the
        # sequentially-next-numbered block, but oh well.
        jcc_fall_through = pred1.succ(1) if pred1.succ(0) == jcc_dest else pred1.succ(0)

        return True, ends_with_jcc, jcc_dest, jcc_fall_through
    return False, None, -1, -1


def split_mblocks_by_jcc_ending(
    pred1: ida_hexrays.mblock_t, pred2: ida_hexrays.mblock_t
) -> tuple[
    bool,
    ida_hexrays.mblock_t | None,
    ida_hexrays.mblock_t | None,
    int,
    int,
]:
    """
    For a block with two predecessors, figure out if one of them ends in a jcc
    instruction. Return pointers to the block that ends in a jcc and the one
    that doesn't. Also return the integer numbers of those blocks.
    """
    ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through = None, None, -1, -1
    if not pred1.tail or not pred2.tail:
        return False, None, None, -1, -1

    # Check if the first block ends with jcc. Make sure the second one
    # doesn't also.
    ok, ends_with_jcc, jcc_dest, jcc_fall_through = extract_jcc_parts(pred1)
    if ok:
        # If the second block also ends with jcc, then we can't split them.
        if ida_hexrays.is_mcode_jcond(pred2.tail.opcode):
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through
        non_jcc = pred2
    else:
        # Otherwise, check if the second block ends with jcc. Make sure the first
        # one doesn't also.
        ok, ends_with_jcc, jcc_dest, jcc_fall_through = extract_jcc_parts(pred2)
        if not ok:
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through
        non_jcc = pred1
    return True, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through


class deferred_graph_modifier_t:
    """
    The "deferred graph modifier" records changes that the client wishes to make
    to a given graph, but does not apply them immediately. Weird things could
    happen if we were to modify a graph while we were iterating over it, so save
    the modifications until we're done iterating over the graph.
    """

    class edgeinfo_t:
        def __init__(self, src=-1, dst1=-1, dst2=-1):
            self.src = src
            self.dst1 = dst1
            self.dst2 = dst2

    def __init__(self):
        self.clear()

    def clear(self):
        self.edges = []

    def add(self, src, dest):
        """
        Plan to add an edge
        """
        self.edges.append(deferred_graph_modifier_t.edgeinfo_t(src=src, dst2=dest))

    def replace(self, src, old_dest, new_dest):
        """
        Plan to replace an edge from src->old_dest to src->new_dest
        """
        # If the edge was already planned to be replaced, replace the
        # old destination with the new one
        for e in self.edges:
            if e.src == src and e.dst1 == old_dest:
                old_dest = e.dst2
        self.edges.append(
            deferred_graph_modifier_t.edgeinfo_t(src=src, dst1=old_dest, dst2=new_dest)
        )

    def apply(self, mba, cfi=None):
        """
        Apply the planned changes to the graph
        """

        # Iterate through the edges slated for removal or addition
        for e in self.edges:
            mb_src = mba.get_mblock(e.src)
            if e.dst1 != -1:
                mb_dst1 = mba.get_mblock(e.dst1)
                mb_src.succset._del(mb_dst1.serial)
                mb_dst1.predset._del(mb_src.serial)
            mb_dst2 = mba.get_mblock(e.dst2)
            mb_src.succset.push_back(mb_dst2.serial)
            mb_dst2.predset.push_back(mb_src.serial)
            if cfi == None:
                logger.info(
                    "Replaced edge (%d->%d) by (%d->%d)\n"
                    % (e.src, e.dst1, e.src, e.dst2)
                )
            else:
                if e.src in cfi.block_to_key.keys():
                    logger.info(
                        f"Replaced edge ({e.src}->{e.dst1}) by ({e.src}->{e.dst2}) BlockKey = {hex(cfi.block_to_key[e.src])}"
                    )
                else:
                    logger.info(
                        f"Replaced edge ({e.src}->{e.dst1}) by ({e.src}->{e.dst2}) BlockKey = {cfi.block_to_key}"
                    )
        return len(self.edges)

    def change_goto(self, blk, old, new):
        """
        Either change the destination of an existing goto, or add a new goto onto
        the end of the block to the destination. Also, plan to modify the graph
        structure later to reflect these changes.
        """

        changed = True
        disp_pred = blk.serial

        # If the last instruction isn't a goto, add a new one
        if blk.tail.opcode != ida_hexrays.m_goto:
            append_goto_onto_non_empty_block(blk, new)
        else:
            # Otherwise, if it is a goto, be sure we're actually
            # *changing* the destination to a different location
            prev = blk.tail.l.b
            if prev == new:
                changed = False
            else:
                # And if so, do it
                blk.tail.l.b = new

        # If we did change the destination, plan to update the graph later
        if changed:
            self.replace(blk.serial, old, new)
        return changed


class jz_info_t:
    """
    Helper class, used to determine whether a function is likely obfuscated or not.
    Also used to collect the number of times a var. was used in a comparison,
    and a list of the values it was compared against
    """

    def __init__(self, op=None, nseen=0):
        self.op = op
        self.nseen = nseen
        self.nums = []

    def should_blacklist(self):
        """
        Determines whether a function is likely obfuscated via
        a) Minimum number o fcomparisons made against comp. variable
        b) constant values in comparisons are suff. entropic
        :return: True if not obfuscated
        """

        # This check is pretty weak. I thought I could set the minimum number to
        # 6, but the pattern deobfuscators might eliminate some of them before
        # this function gets called.
        if self.nseen < MIN_NUM_COMPARISONS:
            return True

        # Count the number of 1-bits in the constant values used for comparison
        num_bits = 0
        num_ones = 0
        for num in self.nums:
            num_bits += num.size * 8
            v = num.nnn.value
            for i in range(num.size * 8):
                if v & (1 << i):
                    num_ones += 1

        # Compute the percentage of 1-bits. Given that these constants seem to be
        # created pseudorandomly, the percentage should be roughly 1/2.
        entropy = 0.0 if num_bits == 0 else num_ones / float(num_bits)
        logger.info(
            f"{self.nseen} comparisons, {len(self.nums)} numbers, {num_bits} bits, {num_ones} ones, {float(entropy)} entropy"
        )
        return entropy < 0.3 or entropy > 0.6


class jtbl_collector_t(ida_hexrays.minsn_visitor_t):
    """
    Looks for switch statements (jump tables) in the Hex-Rays microcode.
    Each m_jtbl represents a decompiled 'switch' with its table of targets.
    """

    def __init__(self):
        ida_hexrays.minsn_visitor_t.__init__(self)
        # list of all m_jtbl instructions we encountered
        self.switch_insns = []

    def visit_minsn(self):
        ins = self.curins

        # If this is a jump-table instruction, stash it
        if ins.opcode == ida_hexrays.m_jtbl:
            # ins.l is the index expression feeding the table
            # ins.r is the table descriptor (pointer + size)
            self.switch_insns.append(
                {
                    "insn": ins,
                    "index_mop": ins.l,
                    "table_mop": ins.r,
                    # you can also inspect ins.jumps or ins.cases for the targets
                    "cases": getattr(ins, "jumps", None),
                }
            )

        return 0


@dataclasses.dataclass
class SwitchInfo:
    jtbl_insn: ida_hexrays.minsn_t
    index_reg: ida_hexrays.mop_t
    table: ida_hexrays.mop_t
    state_var: ida_hexrays.mop_t
    cases: ida_hexrays.mcases_t


class switch_state_collector_t(ida_hexrays.minsn_visitor_t):
    """
    1) Records all m_xdu instructions (var → reg)
    2) On m_jtbl, finds which reg is the index, then looks up any prior xdu to map
       that reg back to the original var.
    """

    def __init__(self):
        super().__init__()
        self.xdu_map: list[MicrocodeInstruction] = []
        self.switches: list[SwitchInfo] = []

    def visit_minsn(self):
        ins = self.curins

        if ins.opcode == ida_hexrays.m_xdu:
            # record dest_reg ← src_var
            self.xdu_map.append(MicrocodeInstruction.from_minsn(ins))

        elif ins.opcode == ida_hexrays.m_jtbl:
            idx_mop = ins.l
            tbl_mop = ins.r
            state_var = None
            logger.debug(f"jump table at: {hex(ins.ea)}")
            for msin in reversed(self.xdu_map):
                dest = msin.minsn.d
                src = msin.minsn.l
                logger.debug(
                    f"{msin}, {hex(msin.minsn.ea)}, {dest.dstr()}, {src.dstr()}"
                )
                if dest.equal_mops(idx_mop, ida_hexrays.EQ_IGNSIZE):
                    state_var = src
                    break
            assert (
                state_var is not None
            ), f"state_var is None for jump table at {hex(ins.ea)}"
            # report_debug(dir(ins))
            info = SwitchInfo(
                jtbl_insn=ins,
                index_reg=idx_mop,
                table=tbl_mop,
                state_var=state_var,
                cases=tbl_mop.c,
            )
            self.switches.append(info)

        return 0


class jz_collector_t(ida_hexrays.minsn_visitor_t):
    """
    Looks for jz, jg comparisons against constant values. Utilised jz_info_t class.
    """

    def __init__(self):
        ida_hexrays.minsn_visitor_t.__init__(self)
        self.seen_comparisons = []
        self.n_max_jz = -1

    def visit_minsn(self):
        ins = self.curins

        # We're looking for jz/jg instructions...
        if ins.opcode not in [ida_hexrays.m_jz, ida_hexrays.m_jg]:
            return 0

        # ... which compare something against a number ...
        if ins.r.t != ida_hexrays.mop_n:
            return 0

        found = 0
        this_mop = ins.l
        idx_found = 0

        # Search for the comparison operand in the saved information
        for sc in self.seen_comparisons:
            if sc.op.equal_mops(this_mop, ida_hexrays.EQ_IGNSIZE):
                sc.nseen += 1
                sc.nums.append(ins.r)
                found = sc.nseen
                break
            idx_found += 1

        # If we didn't find it in the vector, create a new JZInfo structure
        if not found:
            jz = jz_info_t()
            jz.op = this_mop
            jz.nseen = 1
            jz.nums.append(ins.r)
            self.seen_comparisons.append(jz)

        # If the variable we just saw has been used more often than the previous
        # candidate, mark this variable as the new candidate
        if self.n_max_jz < 0 or found > self.seen_comparisons[self.n_max_jz].nseen:
            self.n_max_jz = idx_found

        return 0


def get_first_block(
    mba: ida_hexrays.mba_t,
) -> tuple[bool, ida_hexrays.mblock_t | None, int, int]:
    """
    This function finds the "first" block immediately before the control flow
    flattening dispatcher begins. The logic is simple; start at the beginning
    of the function, keep moving forward until the next block has more than one
    predecessor. As it happens, this is where the assignment to the switch
    dispatch variable takes place, and that's mostly why we want it.
    The information is recorded in the arguments iFirst and iDispatch.

    Finds the first block before control flow dispatcher begins.
    :param mba: mba_t
    :return: True if found, mblock_t first block, serial first block, dispatcher serial
    """
    logger.info("Determining first block before cfg disp begins")
    # Initialise first and dispatch to erroneous values
    first, dispatch = -1, -1
    curr = 0

    while True:

        logger.info(f"Investigating if dispatcher. Current block = {curr}")
        # If we find a block with more than one successor, we failed.
        mb = mba.get_mblock(curr)
        if mb.nsucc() != 1:
            logger.error(f"Block {curr} had {mb.nsucc()} (!= 1) successors\n")
            return False, None, -1, -1

        # Get the successor block
        succ = mb.succ(0)
        mb_next_block = mba.get_mblock(succ)

        # If the successor has more than one predecessor, we're done
        if mb_next_block.npred() != 1:
            break

        # Otherwise, move onto the next block
        curr = succ

    # We found it; pass the information back to the caller
    first = curr
    dispatch = mb.succ(0)
    return True, mb, first, dispatch


class block_insn_assign_number_extractor_t(ida_hexrays.minsn_visitor_t):
    """
    This class is used to find all variables that have 32-bit numeric values
    assigned to them in the first block (as well as the values that are
    assigned to them).
    """

    def __init__(self):
        ida_hexrays.minsn_visitor_t.__init__(self)
        self.seen_assignments = []

    def visit_minsn(self):
        ins = self.curins
        if (
            ins.opcode != ida_hexrays.m_mov
            or ins.l.t != ida_hexrays.mop_n
            or ins.l.size != 4
        ):
            return 0

        # Record all such information in the vector
        self.seen_assignments.append((ins.d, ins.l.nnn.value))
        return 0


class handoff_var_finder_t(ida_hexrays.minsn_visitor_t):
    """
    Protected functions might use either one, or two, variables for the switch
    dispatch number. If it uses two, one of them is the "update" variable, whose
    contents will be copied into the "comparison" variable in the first dispatch
    block. This class is used to locate the "update" variable, by simply looking
    for a variable whose contents are copied into the "comparison" variable,
    which must have had a number assigned to it in the first block.
    """

    class seen_copy_t:
        def __init__(self, op, count=1):
            self.op = op
            self.count = count

    def __init__(self, op_max, num_extractor):
        ida_hexrays.minsn_visitor_t.__init__(self)
        # We're looking for assignments to this variable
        self.comparison_var = op_max
        self.num_extractor = num_extractor
        # This information is generated by this class. Namely, it's a list of
        # variables that are seen copied into the comparison variable, as well
        # as a count of the number of times it is copied.
        self.seen_copies = []

    def visit_minsn(self):
        ins = self.curins

        # We want copies into our comparison variable
        if ins.opcode not in [
            ida_hexrays.m_mov,
            ida_hexrays.m_and,
        ] or not ins.d.equal_mops(self.comparison_var, ida_hexrays.EQ_IGNSIZE):
            return 0

        # Iterate through the numeric assignments from the first block. These
        # are our candidates.
        for sas in self.num_extractor.seen_assignments:
            if ins.l.equal_mops(sas[0], ida_hexrays.EQ_IGNSIZE):

                # If we found a copy into our comparison variable from a
                # variable that was assigned to a constant in the first block,
                # add it to the vector (or increment its counter if it was
                # already there).
                found = False

                for sc in self.seen_copies:
                    if sas[0].equal_mops(sc.op, ida_hexrays.EQ_IGNSIZE):
                        sc.count += 1
                        found = True
                if not found:
                    self.seen_copies.append(handoff_var_finder_t.seen_copy_t(sas[0]))

        return 0


class jz_mapper_t(ida_hexrays.minsn_visitor_t):
    """
    Once we know which variable is the one used for comparisons, look for all
    jz instructions that compare a number against this variable. This then tells
    us which number corresponds to which basic block.
    """

    def __init__(self, cfi, assign_var):
        ida_hexrays.minsn_visitor_t.__init__(self)
        self.cfi = cfi
        self.assign_var = assign_var
        self.debug = True

    def visit_minsn(self):
        ins = self.curins
        mba = self.mba
        blk = self.blk
        is_jnz = False

        # We're looking for jz instructions that compare a number ...
        # if its a jnz and the last instruction of the block, the dest_no will be next block in the list
        if ins.opcode != ida_hexrays.m_jz:
            if blk.tail != ins and ins.opcode != ida_hexrays.m_jnz:
                return 0
            is_jnz = True

        if ins.r.t != ida_hexrays.mop_n:
            return 0

        # ... against our comparison variable ...
        if not self.cfi.op_compared.equal_mops(ins.l, ida_hexrays.EQ_IGNSIZE):

            # ... or, if it's the dispatch block, possibly the assignment variable ...
            if blk.serial != self.cfi.dispatch or not self.assign_var.equal_mops(
                ins.l, ida_hexrays.EQ_IGNSIZE
            ):
                return 0

        # ... and the destination of the jz must be a block
        if ins.d.t != ida_hexrays.mop_b:
            return 0

        # Record the information in two maps
        key_val = ins.r.nnn.value

        # told you above, if flag set, the next block is the destination
        if is_jnz:
            block_no = blk.nextb.serial
        else:
            block_no = ins.d.b
        self.cfi.report(
            f"Mapping found, key_val = {hex(key_val)} -> block = {block_no}"
        )
        self.cfi.key_to_block[key_val] = block_no
        self.cfi.block_to_key[block_no] = key_val
        return 0


def compute_dominators(mba: ida_hexrays.mba_t) -> list[ida_hexrays.bitset_t]:
    """
    Compute dominator information for the function.
    :param mba: mba_t
    :return: list of bitset_t, each representing a block and its dominators
    """
    num_blocks = mba.qty
    assert num_blocks > 0

    # Use Hex-Rays' handy bitsets_t to represent dominators
    dom_info: list[ida_hexrays.bitset_t] = []
    for i in range(num_blocks):
        dom_info.append(ida_hexrays.bitset_t())

    # Per the algorithm, initialize each block to be dominated by every block
    for bs in dom_info:
        bs.fill_with_ones(num_blocks - 1)

    # ... except the first block, which only dominates itself
    dom_info[0].clear()
    dom_info[0].add(0)

    # Now we've got a standard, not-especially-optimized dataflow analysis
    # fixedpoint computation...
    while True:
        changed = False

        # For every block...
        for i in range(1, num_blocks):

            # Grab its current dataflow value and copy it
            bs_curr = dom_info[i]
            bs_before = ida_hexrays.bitset_t(bs_curr)

            # Get that block from the graph
            block_i: ida_hexrays.mblock_t = mba.get_mblock(i)

            # Iterate over its predecessors, intersecting their dataflow
            # values against this one's values
            for pr in block_i.predset:
                bs_curr.intersect(dom_info[pr])

            # Then, re-indicate that the block dominates itself
            bs_curr.add(i)

            # If this process changed the dataflow information, we're going to
            # need another iteration
            if bs_before.compare(bs_curr) != 0:
                changed = True

        # Keep going until the dataflow information stops changing
        if not changed:
            break

    # The dominator information has been computed. Now we're going to derive
    # some information from it. Namely, the current representation tells us,
    # for each block, which blocks dominate it. We want to know, instead, for
    # each block, which blocks are dominated by it. This is a simple
    # transformation; for each block b and dominator d, update the information
    # for d to indicate that it dominates b.

    # Create a new array_of_bitsets
    dom_info_output: list[ida_hexrays.bitset_t] = []
    for i in range(num_blocks):
        dom_info_output.append(ida_hexrays.bitset_t())

    # Iterate over each block
    for i in range(num_blocks):
        # Get the dominator information for this block (b)
        bs_curr = dom_info[i]

        # For each block d that dominates this one, mark that d dominates b
        for bit in bs_curr:
            odi = dom_info_output[bit]
            odi.add(i)

    # Just return the inverted dominator information
    return dom_info_output


class cf_flatten_info_t:
    def __init__(self, plugin):
        self.plugin = plugin
        self.maturity = None
        self.mb_first = None
        self.detected_dispatchers = []
        self.op_assigned: ida_hexrays.mop_t | None = None
        self.op_compared = None
        self.op_sub_compared = None
        self.first = -1
        self.dispatch = -1
        self.ufirst = 0
        self.which_func = ida_idaapi.BADADDR
        self.dom_info: list[ida_hexrays.bitset_t] = []
        self.dominated_clusters: list[int] = []
        self.tracking_first_blocks = False
        self.op_and_assign = False
        self.op_and_imm = 0
        self.key_to_block = {}
        self.block_to_key = {}
        self.clear()

    def report(self, msg):
        logger.info(msg)

    def report_error(self, msg):
        logger.error(msg)

    def report_debug(self, msg):
        logger.debug(msg)

    def clear(self):
        self.op_assigned = None
        self.op_compared = None
        self.op_sub_compared = None
        self.first = -1
        self.dispatch = -1
        self.ufirst = 0
        self.which_func = ida_idaapi.BADADDR
        self.dom_info.clear()
        self.dominated_clusters.clear()
        self.tracking_first_blocks = False
        self.op_and_assign = False
        self.op_and_imm = 0
        self.key_to_block = {}
        self.block_to_key = {}

    def clear_mmat_calls(self):
        self.op_assigned = None
        self.op_compared = None
        self.op_sub_compared = None
        self.which_func = ida_idaapi.BADADDR
        self.dom_info.clear()
        self.dominated_clusters.clear()
        self.tracking_first_blocks = False
        self.op_and_assign = False
        self.op_and_imm = 0
        self.key_to_block = {}
        self.block_to_key = {}

    # Convenience function to look up a block number by its key. This way, we can
    # write the iterator-end check once, so clients don't have to do it.
    def find_block_by_key(self, key):
        return self.key_to_block.get(key, -1)

    def detect_additional_dispatchers(self, blk):
        """
        Detect additional dispatchers.
        """
        mba = blk.mba
        logger.info(f"Detecting additional dispatchers ..")
        block: ida_hexrays.mblock_t = mba.get_mblock(0)
        i = 0
        while block.nextb != None:
            block: ida_hexrays.mblock_t = mba.get_mblock(i)
            if (
                block.npred() >= 3
                and block.get_reginsn_qty() >= 1
                and i not in self.detected_dispatchers
            ):
                logger.info(
                    f"Block serial = {block.serial} with greater equal 3 predecessors found, verifying whether potential dispatcher .."
                )
                self.detected_dispatchers.append(i)
            i += 1

    def get_assigned_and_comparison_variables(self, blk: ida_hexrays.mblock_t):
        """
        This function computes all of the preliminary information needed for
        unflattening.
        """
        mba = blk.mba
        self.clear()
        ea = mba.entry_ea

        # Ensure that this function hasn't been blacklisted (e.g. because entropy
        # calculation indicates that it isn't obfuscated).
        if ea in self.plugin.black_list:
            logger.error(f"[+] Function Ea = {hex(ea)} blacklisted!")
            return False

        # There's also a separate whitelist for functions that were previously
        # seen to be obfuscated.
        was_white_listed = ea in self.plugin.white_list

        logger.info(f"Running switch collector")
        # Look for the variable that was used for the switch statement
        # statements. This is our "comparison" variable.
        switch_tbl_collector = switch_state_collector_t()
        mba.for_all_topinsns(switch_tbl_collector)
        if len(switch_tbl_collector.switches) == 0:
            logger.info(
                f"No switch statements seen for function @ {hex(ea)} - adding function to blacklist"
            )
            # If there were no comparisons and we haven't seen this function
            # before, blacklist it.
            if not was_white_listed:
                self.plugin.black_list.append(ea)
            return False

        logger.info(
            f"Max switch statements seen = {len(switch_tbl_collector.switches)}"
        )

        # Otherwise, we were able to find jz comparison information. Use that to
        # determine if the constants look entropic enough. If not, blacklist this
        # function. If so, whitelist it.
        if not was_white_listed:
            # this kicks out cfgNetwork handling .. lowering entropy..
            # if jtblc.switch_insns[0].should_blacklist():
            #     report(f"Classified function as not obfuscated")
            #     self.plugin.black_list.append(ea)
            #     return False
            self.plugin.white_list.append(ea)

        op_max = switch_tbl_collector.switches[0].state_var
        logger.info(f"Comparison variable = {op_max.dstr()}")
        # op_max is our "comparison" variable used in the control flow switch.
        # if op_max.size < 4:
        #     self.report_error(f"Comparison variable {op_max.dstr()} is too narrow\n")
        #     return False

        ok = False
        # Find the "first" block in the function, the one immediately before the
        # control flow switch.
        ok, self.mb_first, self.first, self.dispatch = get_first_block(mba)
        if not ok:
            logger.error(f"Failed determining the first block")
            return False

        assert self.mb_first
        first = self.mb_first
        assert self.dispatch
        self.detected_dispatchers.append(self.dispatch)
        self.detect_additional_dispatchers(blk)

        logger.info(
            f"Determined dispatcher block = {self.dispatch}, first_block = {first.serial}, first.start = {hex(first.start)}"
        )

        # Get all variables assigned to numbers in the first block. If we find the
        # comparison variable in there, then the assignment and comparison
        # variables are the same. If we don't, then there are two separate
        # variables.
        fbe = block_insn_assign_number_extractor_t()
        first.for_all_insns(fbe)

        # Was the comparison variable assigned a number in the first block?
        found = False
        for sas in fbe.seen_assignments:
            logger.info(f"sas[0] = {sas[0].dstr()}")
            if sas[0].equal_mops(op_max, ida_hexrays.EQ_IGNSIZE):
                found = True
                break

        # This is the "assignment" variable, whose value is updated by the switch
        # case code2
        local_op_assigned = None
        if found:
            # If the "comparison" variable was assigned a number in the first block,
            # then the function is only using one variable, not two, for dispatch.
            local_op_assigned = op_max
        else:
            # Otherwise, look for assignments of one of the variables assigned a
            # number in the first block to the comparison variable

            # For all variables assigned a number in the first block, find all
            # assignments throughout the function to the comparison variable
            hvf = handoff_var_finder_t(op_max, fbe)
            mba.for_all_topinsns(hvf)

            # There should have only been one of them; is that true?
            if len(hvf.seen_copies) != 1:
                logger.error(f"Multiple copies found by handoff finder!")
                return False

            # If only one variable (X) assigned a number in the first block was
            # ever copied into the comparison variable, then X is our "assignment"
            # variable.
            local_op_assigned = hvf.seen_copies[0].op

            # Find the number that was assigned to the assignment variable in the
            # first block.
            found = False
            for sas in fbe.seen_assignments:
                if sas[0].equal_mops(local_op_assigned, ida_hexrays.EQ_IGNSIZE):
                    ufirst = sas[1]
                    found = True
                    break
            if not found:
                return False

        # Make copies of the comparison and assignment variables so we don't run
        # into liveness issues
        self.op_compared = ida_hexrays.mop_t(op_max)
        self.op_assigned = ida_hexrays.mop_t(local_op_assigned)

        # Extract the key-to-block mapping for each JZ against the comparison
        # variable
        # jzm = jz_mapper_t(self, local_op_assigned)
        # mba.for_all_topinsns(jzm)

        # Once we've found the "comparison" variable (op_max), also pull in
        # the jump-table's own mapping of keys → blocks.
        # for swi in switch_tbl_collector.switches:
        #     # only use the jump-table whose state_var matches our op_max
        #     if swi.state_var and swi.state_var.equal_mops(
        #         op_max, ida_hexrays.EQ_IGNSIZE
        #     ):
        #         assert swi.cases is not None
        #         # swi.cases is typically a dict of {key_value: target_block}
        #         for case_idx in range(swi.cases.size()):
        #             case_item: ida_hexrays.ccase_t = swi.cases.at(case_idx)
        #             for val_idx in range(case_item.values.size()):
        #                 case_val = case_item.values.at(val_idx)
        #                 self.key_to_block[case_val] = case_item.ea
        #                 self.block_to_key[case_item.ea] = case_val
        #         report(f"[+] Imported {len(swi.cases)} jump-table entries")
        #         report_debug(f"Jump-table cases: {swi.cases.values}")
        #         break
        for swi in switch_tbl_collector.switches:
            if not swi.state_var or not swi.state_var.equal_mops(
                op_max, ida_hexrays.EQ_IGNSIZE
            ):
                continue
            assert swi.cases is not None
            logger.info(f"[+] Found jump-table for {op_max.dstr()}, importing cases")
            num_imported = 0

            vals: ida_xref.casevec_t = swi.cases.values  # casevec_t of the keys
            targs: ida_pro.intvec_t = swi.cases.targets  # intvec_t of the block numbers
            # they should be the same length
            for vals, blk_ in zip(vals, targs):
                py_blk = int(blk_)  # ensure a Python int
                # vals is an intvec_t, so iterating yields int-like
                for val in vals:
                    py_key = int(val)  # coerce to Python int
                    if py_key not in self.key_to_block:
                        self.key_to_block[py_key] = py_blk
                        num_imported += 1

                # map each block back to *one* representative key
                if py_blk not in self.block_to_key and len(vals) > 0:
                    self.block_to_key[py_blk] = int(vals[0])

            logger.info(f"[+] Imported {num_imported} jump-table entries")
            break

        # Save off the current function's starting EA
        self.which_func = ea

        # Compute the dominator information for this function and stash it
        self.dom_info = compute_dominators(mba)

        # Compute some more information from the dominators. Basically, once the
        # control flow dispatch switch has transferred control to the function's
        # code, there might be multiple basic blocks that can execute before
        # control goes back to the switch statement. For all of those blocks, we
        # want to know the "first" block as part of that region of the graph,
        # i.e., the one targeted by a jump out of the control flow dispatch
        # switch.

        # to explain this process in my own words:
        # After the control flow switch block, we enter a control flow block
        # This control flow block can have multiple basic blocks that run after
        # the control flow block (f.e. if else branches etc.)
        # For these non control flow blocks, we collect information, so the first control flow block
        # before them

        # This is done by generating a new bitset again

        # Allocate an array mapping each basic block to the block that dominates
        # it and was targeted by the control flow switch.
        dominated_clusters = [-1] * mba.qty

        # For each block/key pair (the targets of the control flow switch)
        for i, _ in sorted(self.block_to_key.items()):

            # weird case where we have an out of bounds here
            if i > len(self.dom_info):
                continue
            bitset = self.dom_info[i]

            # For each block dominated by this control flow switch target, mark
            # that this block its the beginning of its cluster.
            for bit in bitset:
                self.report_debug("-> setting bit %d to %d" % (bit, i))
                dominated_clusters[bit] = i

        # Save that information off.
        self.dominated_clusters = dominated_clusters
        self.report(
            f"m_DominatedClusters: {', '.join(map(str, self.dominated_clusters))}"
        )

        # Ready to go!
        return True


class assign_searcher_t(ida_hexrays.minsn_visitor_t):
    """
    Looks for assign
    """

    def __init__(self, op, dispatcher_reg):
        ida_hexrays.minsn_visitor_t.__init__(self)
        self.op = op
        self.dispatcher_reg = dispatcher_reg
        logger.info(
            f"Initiated assign_searcher_t, op = {self.op.dstr()}, dispatcher_reg = {self.dispatcher_reg.dstr()}"
        )
        self.jz_target_block = -1
        self.hits = []
        self.assign_infos = []

    def visit_minsn(self):

        ins = self.curins

        # filter out non mov instr.
        if ins.opcode not in [ida_hexrays.m_mov, ida_hexrays.m_jz]:
            return 0

        if ins.opcode == ida_hexrays.m_mov:
            # filter out non mop_number as src operand
            if ins.l.t != ida_hexrays.mop_n and ins.d.t != ida_hexrays.mop_r:
                return 0

            if ins.d.dstr() == self.op.dstr():
                self.hits.append(ins)
            return 0
        else:

            if (
                ins.l.dstr() == self.dispatcher_reg.dstr()
                and ins.r.dstr() == self.op.dstr()
            ) or (
                ins.l.dstr() == self.op.dstr()
                and ins.r.dstr() == self.dispatcher_reg.dstr()
            ):
                block_no = ins.d.b
                logger.info(f"Current instruction = {ins.dstr()}, block = {block_no}")
                self.jz_target_block = block_no
            return 0


def compute_cfg_fingerprint(mba: ida_hexrays.mba_t) -> str:
    """
    Stable fingerprint of the CFG at this maturity level.
    We sort blocks by start_ea to avoid serial re-ordering issues.
    """
    lines = []
    for blk in sorted(
        [mba.get_mblock(i) for i in range(mba.qty)], key=lambda b: b.start
    ):
        succ_eas = sorted(mba.get_mblock(s).start for s in blk.succset)
        lines.append(f"{hex(blk.start)}:{','.join(hex(e) for e in succ_eas)}")
    return hashlib.sha1("\n".join(lines).encode()).hexdigest()


class cf_unflattener_t:
    """
    Main unflattener class.
    """

    def __init__(self, plugin):
        self.cfi: cf_flatten_info_t = cf_flatten_info_t(plugin)
        self.plugin = plugin
        self.last_maturity = ida_hexrays.MMAT_ZERO
        self.clear()
        self.verbose = True
        self.debug = True

    def report(self, msg):
        logger.info(msg)

    def report_error(self, msg):
        logger.error(msg)

    def report_debug(self, msg):
        logger.debug(msg)

    def clear(self):
        self.cfi.clear()
        self.deferred_erasures_local = []
        self.performed_erasures_global = []

    def get_dominated_cluster_head(
        self, mba: ida_hexrays.mba_t, disp_pred: int
    ) -> tuple[bool, ida_hexrays.mblock_t | None, int | None]:
        """
        Find block dominating the dispatcher predecessor and is one of the targets
        of the CFG switch.
        :param mba: mba_t object
        :param disp_pred: dispatcher predecessor serial
        :return: Flag if succeeded, mblock_t, mblock_t serial
        """
        # Find the block that is targeted by the dispatcher, and that
        # dominates the block we're currently looking at. This logic won't
        # work for the first block (since it wasn't targeted by the control
        # flow dispatch switch, so it doesn't have an entry in the dominated
        # cluster information), so we special-case it.
        if disp_pred == self.cfi.first:
            cluster_head = self.cfi.first
            mb_cluster_head: ida_hexrays.mblock_t = mba.get_mblock(self.cfi.first)
        else:
            # If it wasn't the first block, look up its cluster head block
            cluster_head = self.cfi.dominated_clusters[disp_pred]
            if cluster_head < 0:
                self.report(f"Cluster_head returned zero!")
                return False, None, None
            mb_cluster_head: ida_hexrays.mblock_t = mba.get_mblock(cluster_head)
            self.report(
                f"Block {disp_pred} was part of dominated cluster {cluster_head}"
            )

        return True, mb_cluster_head, cluster_head

    def get_dominated_cluster_head_by_pattern_dirty(
        self, mba: ida_hexrays.mba_t, mb: ida_hexrays.mblock_t
    ) -> tuple[bool, ida_hexrays.mblock_t | None, int | None]:
        """
        Return the dominated cluster head by pattern.
        This looks at dom_info, searching for the start of the cluster.
        :param mba: mba_t object
        :param disp_pred: dispatcher predecessor
        :return: Flag if succeeded, mblock_t, mblock_t serial
        """

        ok = False
        mb_cluster_head: ida_hexrays.mblock_t | None = None
        cluster_head: int | None = None

        # get the predset into a separate list
        visited_preds = [mb_serial for mb_serial in mb.predset]
        visited_preds.append(mb.serial)
        self.report(
            f"Searching for cluster_head the dirty way, serial = {mb.serial}, predset = {visited_preds}"
        )

        # go through the predsets
        for pred in visited_preds:
            pred_mb = mba.get_mblock(pred)
            for mb_pred_serial in pred_mb.predset:
                target_mb = mba.get_mblock(mb_pred_serial)
                self.report_debug(
                    f"Visited pred = {pred}, mb_pred_serial = {mb_pred_serial}"
                )
                # if one of the predecessors of the predsets is not in the visited_preds array
                # then take that one separately
                if mb_pred_serial not in visited_preds:
                    dom_info = self.cfi.dom_info[mb_pred_serial]
                    self.report(
                        f"Potential cluster_head found, potential_target = {mb_pred_serial}, dom_info = {','.join(str(x) for x in dom_info)}"
                    )
                else:
                    continue
                visited_preds.append(mb_pred_serial)

                # check if the dom_info includes visited_preds and the current serial
                # if not, that's not a potential cluster head
                for node in dom_info:
                    self.report_debug(f"Node = {node}")
                    if node not in visited_preds:
                        return ok, mb_cluster_head, cluster_head

                target_pred_mb = mba.get_mblock(target_mb.predset[0])
                # if yes, take the successor, see if the successor branches into
                # this block in the final instruction via a jz/jc or w.e.
                # if all of this succeeds, we found our dirty cluster head
                last_instr = target_pred_mb.tail
                # not a jz ? don't continue
                if last_instr.opcode != ida_hexrays.m_jz:
                    self.report_debug(
                        f"Last instruction is not a jump, last_instr = {last_instr.dstr()}"
                    )
                    return ok, mb_cluster_head, cluster_head

                # is the target block our dispatcher block? great we found it!
                dest_no = last_instr.d.b
                self.report(
                    f"cluster_head_dirty, last_instruction = {last_instr.dstr()}, target_block = {dest_no}"
                )
                if dest_no == target_mb.serial:
                    self.report(f"Cluster head found! Cluster serial = {dest_no}")
                    return True, mba.get_mblock(dest_no), dest_no
                else:
                    self.report(
                        f"Failed finding cluster head via dirty_method for block = {mb.serial}"
                    )
                    return ok, mb_cluster_head, cluster_head

        return ok, mb_cluster_head, cluster_head

    def find_block_target_or_last_copy(
        self,
        mb: ida_hexrays.mblock_t,
        mb_cluster_head: ida_hexrays.mblock_t,
        what: ida_hexrays.mop_t,
        allow_multi_succs: bool,
    ) -> int:
        """
        This function attempts to locate the numeric assignment to a given variable
        "what" starting from the end of the block "mb". It follows definitions
        backwards, even across blocks, until it either reaches the block
        "mbClusterHead", or, if the boolean "bAllowMultiSuccs" is false, it will
        stop the first time it reaches a block with more than one successor.
        If it finds an assignment whose source is a stack variable, then it will not
        be able to continue in the backwards direction, because intervening memory
        writes will make the definition information useless. In that case, it
        switches to a strategy of searching in the forward direction from
        mbClusterHead, looking for assignments to that stack variable.
        Information about the chain of assignment instructions along the way are
        stored in the vector called m_DeferredErasuresLocal, a member variable of
        the CFUnflattener class.
        """

        logger.info(f"Current what = {what.dstr()}")

        mba = mb.mba
        cluster_head = mb_cluster_head.serial
        local = []

        # Search backwards looking for a numeric assignment to "what". We may or
        # may not find a numeric assignment, but we might find intervening
        # assignments where "what" is copied from other variables.
        found, op_num = find_numeric_def_backwards(
            mb, what, local, True, allow_multi_succs, cluster_head
        )

        # If we found no intervening assignments to "what", that's bad.
        if len(local) == 0:
            logger.info(
                f"Local array is zero, failed backward search! Dirty search now for block = {mb.serial}"
            )
            if mb.get_reginsn_qty() == 2:
                logger.info(f"2 instructions check suceeded!")
                head_insn = mb.head
                logger.info(f"Head instruction = {head_insn.dstr()}")
            return -1

        logger.info(f"Local array not zero!")

        # opCopy now contains the last non-numeric assignment that we saw before
        # FindNumericDefBackwards terminated (either due to not being able to
        # follow definitions, or, if bAllowMultiSuccs is true, because it recursed
        # into a block with more than one successor.
        op_copy = local[-1].op_copy

        # Copy the assignment chain into the erasures vector, so we can later
        # remove them if our analysis succeeds.
        self.deferred_erasures_local.extend(local)

        # If we didn't find a numeric definition, but we did find an assignment
        # from a stack variable, switch to a forward analysis from the beginning
        # of the cluster. If we don't find it, this is not necessarily an
        # indication that the analysis failed; for blocks with two successors,
        # we do further analysis.
        logger.info(f"OpCopy = {op_copy.dstr()}")
        if not found and op_copy and op_copy.t == ida_hexrays.mop_S:
            logger.info("Running forward analysis")
            num: ida_hexrays.mop_t | None = find_forward_stack_var_def(
                mb_cluster_head, op_copy, local
            )
            if num:
                op_num = num
                found = True
            else:
                self.report_error("Forward method also failed")

        dest_no = -1

        # If we found a numeric assignment...
        if found and op_num:

            # Look up the integer number of the block corresponding to that value.
            dest_no = self.cfi.find_block_by_key(op_num.nnn.value)
            if dest_no < 0:
                self.report_error(
                    f"Block {mb.serial} assigned unknown key {hex(op_num.nnn.value)} to assigned var"
                )
        else:

            # search all instructions, if the register is assigned only ONCE and that is with a
            # high entropy variable, we can extract the high entropy value, and grab the block by key via that
            logger.info(
                f"Attempting to search for block by key via iterating all instructions, op_copy = {op_copy}"
            )
            searcher = assign_searcher_t(op_copy, self.cfi.op_compared)
            mba.for_all_topinsns(searcher)
            if len(searcher.hits) == 1:
                logger.info(f"Only one assignment, {searcher.hits[0].dstr()}")
                key = searcher.hits[0].l.nnn.value
                dest_no = self.cfi.find_block_by_key(key)
                if dest_no == -1:
                    dest_no = searcher.jz_target_block
                    logger.info(f"Target block via assign_searcher = {dest_no}")
                return dest_no

        return dest_no

    def handle_two_preds(
        self,
        mb: ida_hexrays.mblock_t,
        mb_cluster_head: ida_hexrays.mblock_t,
        op_copy: ida_hexrays.mop_t,
    ) -> tuple[
        bool, ida_hexrays.mblock_t | None, ida_hexrays.mblock_t | None, int, int
    ]:
        """
        Handle constructs with two successors, f.e. if statements
        If block assigns to assignment variable with 2 predecessors, analyse each
        predecessor looking for numeric assignments by calling the previous function
        :param mb: mblock_t
        :param mb_cluster_head: cluster head mblock_t
        :param op_copy:
        :return:
        """
        ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target = (
            None,
            None,
            -1,
            -1,
        )
        mba = mb.mba
        disp_pred = mb.serial
        cluster_head: int = mb_cluster_head.serial

        if mb.npred() == 2:
            pred1 = mba.get_mblock(mb.pred(0))
            pred2 = mba.get_mblock(mb.pred(1))
        else:
            # No really, don't call this function on a block that doesn't have two
            # predecessors.
            return False, None, None, -1, -1

        # Given the two predecessors, find the block with the conditional jump at
        # the end of it (store the block in "ends_with_jcc") and the one without
        # (store it in non_jcc). Also find the block number of the jcc target, and
        # the block number of the jcc fallthrough (i.e., the block number of
        # non_jcc).
        ok, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through = (
            split_mblocks_by_jcc_ending(pred1, pred2)
        )
        if not ok:
            self.report(
                "Block %s w/preds %s, %s did not have one predecessor ending in jcc, one without"
                % (disp_pred, pred1.serial, pred2.serial)
            )
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through
        assert ends_with_jcc is not None
        assert mb_cluster_head is not None
        assert op_copy is not None
        assert non_jcc is not None
        # Sanity checking the structure of the graph. The nonJcc block should only
        # have one incoming edge...
        if non_jcc.npred() != 1:
            self.report(
                "Block %d w/preds %d, %d did not have one predecessor ending in jcc, one without"
                % (disp_pred, pred1.serial, pred2.serial)
            )
            return False, None, None, -1, -1

        # ... namely, from the block ending with the jcc.
        if non_jcc.pred(0) != ends_with_jcc.serial:
            self.report(
                "Block %d w/preds %d, %d, non-jcc pred %d did not have the other as its predecessor"
                % (disp_pred, pred1.serial, pred2.serial, non_jcc.serial)
            )
            return False, None, None, -1, -1

        # Call the previous function to locate the numeric definition of the
        # variable that is used to update the assignment variable if the jcc is
        # not taken.

        actual_goto_target: int = self.find_block_target_or_last_copy(
            ends_with_jcc, mb_cluster_head, op_copy, allow_multi_succs=False
        )

        # If that succeeded...
        if actual_goto_target >= 0:

            # ... then do the same thing when the jcc is not taken.
            actual_jcc_target: int = self.find_block_target_or_last_copy(
                non_jcc, mb_cluster_head, op_copy, allow_multi_succs=True
            )

            # If that succeeded, great! We can unflatten this two-way block.
            if actual_jcc_target >= 0:
                return (
                    True,
                    ends_with_jcc,
                    non_jcc,
                    actual_goto_target,
                    actual_jcc_target,
                )

        return False, None, None, -1, -1

    def process_erasures(self, mba: ida_hexrays.mba_t):
        """
        Erase superfluos chain of instructions, used to copy numeric value
        into assignment variable.
        :param mba: mba_t
        """
        self.performed_erasures_global.extend(self.deferred_erasures_local)
        for erase in self.deferred_erasures_local:

            self.report(
                "Erasing %08X: %s"
                % (erase.ins_mov.ea, ida_lines.tag_remove(erase.ins_mov._print()))
            )
            # Be gone, sucker
            mba.get_mblock(erase.block).make_nop(erase.ins_mov)
        self.deferred_erasures_local = []

    @staticmethod
    def check_maturity(maturity: int) -> bool:
        """
        Check if the maturity level is correct for the current function.
        """
        return maturity == ida_hexrays.MMAT_LOCOPT

    def func(self, blk: ida_hexrays.mblock_t) -> int:
        """
        Top level unflattening function for entire graph.

        :param blk: mblock_t
        :return: number of changes applied. See also mark_lists_dirty.
        """

        if self.plugin.activated == False:
            return 0

        mba = blk.mba

        # if added to white list, we continue
        if (
            mba.entry_ea in self.plugin.black_list
            and mba.entry_ea not in self.plugin.white_list
        ):
            return 0

        # Only operate once per maturity level, update maturity, operate only on MMAT_LOCOPT
        if self.last_maturity == mba.maturity:
            return 0
        self.last_maturity = mba.maturity
        if not self.check_maturity(mba.maturity):
            return 0

        # remove single gotos
        changed = remove_single_gotos(mba)
        logger.info(f"Number of single GOTOS changed = {changed}")
        if changed != 0:
            mba.verify(True)

        # Otherwise, we need to do the full unflattening.
        # (This is the slow path.)
        # collect assignment and comp. variables
        # main routine to collect cfg information
        if not self.cfi.get_assigned_and_comparison_variables(blk):
            self.report_error("Failed collecting control-flow flattening information")
            return changed

        # Create an object that allows us to modify the graph at a future point.
        dgm = deferred_graph_modifier_t()
        dirty_chains = False

        # if flag to run for multiple dispatchers is deactivated,
        # then adjust the array to contain the dispatch block detected by
        # get_first_block only
        if self.plugin.RUN_MLTPL_DISPATCHERS is False:
            self.report(f"RUN_MLTPL_DISPATCHERS = {self.plugin.RUN_MLTPL_DISPATCHERS}")
            self.cfi.detected_dispatchers = [self.cfi.dispatch]

        self.report(
            f"Number of dispatchers to unflatten = {len(self.cfi.detected_dispatchers)}"
        )
        for detected_dispatcher in self.cfi.detected_dispatchers:

            # update the object variable, get predecessors
            self.cfi.dispatch = detected_dispatcher
            dispatch_predset_block = mba.get_mblock(self.cfi.dispatch)
            if dispatch_predset_block is None:
                self.report_error(
                    f"Could not retrieve block for serial = {self.cfi.dispatch}"
                )
                continue

            dispatch_predset = dispatch_predset_block.predset
            self.report(
                f"DispatcherBlock = {self.cfi.dispatch}, predset = {dispatch_predset}"
            )

            # Iterate through the predecessors of the top-level control flow switch
            for disp_pred in dispatch_predset:

                only_erase = False
                mb = mba.get_mblock(disp_pred)
                self.report(
                    f"dispatcher = {self.cfi.dispatch}, deobfuscating predecessor = {disp_pred}, pred_successors = {mb.nsucc()}"
                )

                # if we have multiple successors, we check whether the last instruction of the block is a jnz,
                # if yes, then get the next block, because this will be the successor
                # if the successor ends with a goto, we update the block we want to check to the successor
                # we set a flag 'only_erase' that we only want to erase the state update in that block, but not the
                # goto itself. Cases like this always ended up as 'failure states' in Emotet. Meaning that the
                # follow-up block end the complete function
                # This might need additional hardening at later stages
                if mb.nsucc() != 1:
                    tail = mb.tail
                    if tail.opcode == ida_hexrays.m_jnz:
                        self.report(
                            f"Tail instruction is jnz, checking if follow block tail is goto to dispatcher .."
                        )
                        flw_block = mba.get_mblock(disp_pred + 1)
                        if flw_block.tail.opcode == ida_hexrays.m_goto:
                            self.report(
                                f"Tail is goto! patching this block = {disp_pred + 1}, only erasing the assignment"
                            )
                            disp_pred = disp_pred + 1
                            mb = mba.get_mblock(disp_pred)
                            only_erase = True
                    else:
                        continue

                # Find the block that dominates this cluster, or skip this block if
                # we can't. This ensures that we only try to unflatten parts of the
                # control flow graph that were actually flattened. Also, we need the
                # cluster head so we know where to bound our searches for numeric
                # definitions.
                ok, mb_cluster_head, cluster_head = self.get_dominated_cluster_head(
                    mba, disp_pred
                )
                if not mb_cluster_head:
                    # added additional method to search for the cluster head
                    self.report(
                        f"Could not find dominated cluster head for pred = {disp_pred} via get_dominated_cluster_head."
                    )
                    ok, mb_cluster_head, cluster_head = (
                        self.get_dominated_cluster_head_by_pattern_dirty(mba, mb)
                    )
                    if not ok:
                        self.report(
                            f"Could not find dominated cluster head for pred = {disp_pred} via dirty way"
                        )
                        continue

                self.report(f"disp_pred = {disp_pred}, cluster_head = {cluster_head}")
                self.deferred_erasures_local = []
                assert mb_cluster_head is not None
                assert self.cfi.op_assigned is not None
                # Try to find a numeric assignment to the assignment variable, but
                # pass false for the last parameter so that the search stops if it
                # reaches a block with more than one successor. This ought to succeed
                # if the flattened control flow region only has one destination,
                # rather than two destinations for flattening of if-statements.
                dest_no = self.find_block_target_or_last_copy(
                    mb, mb_cluster_head, self.cfi.op_assigned, allow_multi_succs=False
                )

                #!TODO what do we do here...?
                if dest_no == disp_pred:
                    self.report(
                        f"Found branch where destination == block, setting dest_no as value in "
                    )
                    continue
                    # dest_no2 = self.cfi.block_to_key[disp_pred]
                    # self.report(f"Key = {hex(dest_no2)}")
                # if we couldn't find a proper destination, for the block so far
                # we will try to search for the proper destination by applying pattern matching
                elif dest_no == -1:

                    self.report(
                        f"Could not find destination for block = {disp_pred}, attempting pattern search now"
                    )
                    disp_block = mba.get_mblock(self.cfi.dispatch)
                    tail_reg = disp_block.tail
                    # if the block has no instruction, return that fetching the dest. block failed
                    if tail_reg == None:
                        dest_no = -1
                    else:
                        # otherwise check if it is a jg instruction
                        # if yes, and there is only 1 successor for the jg block
                        # continue as this means if the jg jump fails, we can only
                        # enter a single successor branch
                        # if the successor branch final instruction is a jcnd,
                        # this is a potential dest block
                        if tail_reg.opcode == ida_hexrays.m_jg:
                            self.report(f"Dispatcher block tail is jg instruction")

                            succ_block = mba.get_mblock(self.cfi.dispatch + 1)
                            if succ_block.tail.opcode == ida_hexrays.m_jcnd:
                                dest_no = succ_block.tail.d.b
                                self.report(f"Destination via jcnd pattern = {dest_no}")

                # Couldn't find any assignments at all to the assignment variable?
                # That's bad, don't continue.
                if not self.deferred_erasures_local:
                    self.report(f"No assignments found for block = {disp_pred}!")
                    continue

                # Did we find a block target? Great; just update the CFG to point the
                # destination directly to its target, rather than back to the
                # dispatcher.
                if dest_no >= 0:
                    # Make a note to ourselves to modify the graph structure later
                    msg = ""
                    if only_erase == False:
                        dgm.change_goto(mb, self.cfi.dispatch, dest_no)
                        msg = f"Changed goto on {disp_pred} to {dest_no}"
                    else:
                        msg = f"Erasing only the instruction, only_erase = {only_erase}"

                    # Erase the intermediary assignments to the assignment variable
                    self.process_erasures(mba)
                    self.report(msg)

                    changed += 1
                    continue

                # Stash off a copy of the last variable in the chain of assignments
                # to the assignment variable, as well as the assignment instruction
                # (the latter only for debug-printing purposes).
                op_copy = self.deferred_erasures_local[-1].op_copy
                m = self.deferred_erasures_local[-1].ins_mov
                self.report(
                    f"Block {disp_pred} did not define assign a number to assigned var; assigned {MicrocodeHelper.get_mopt_name(m.l.t)} instead"
                )

                # Call the function that handles the case of a conditional assignment
                # to the assignment variable (i.e., the flattened version of an
                # if-statement).
                ok, ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target = (
                    self.handle_two_preds(mb, mb_cluster_head, op_copy)
                )
                if ok:

                    # Get rid of the superfluous assignments
                    self.process_erasures(mba)

                    # Make a note to ourselves to modify the graph structure later,
                    # for the non-taken side of the conditional. Change the goto
                    # target.
                    dgm.replace(mb.serial, self.cfi.dispatch, actual_goto_target)
                    mb.tail.l.b = actual_goto_target

                    # Mark that the def-use information will need re-analyzing
                    dirty_chains = True

                    # Copy the instructions from the block that targets the dispatcher
                    # onto the end of the jcc taken block.
                    mb_head = mb.head
                    mb_curr = mb_head
                    if non_jcc:
                        while True:
                            copy = ida_hexrays.minsn_t(mb_curr)
                            non_jcc.insert_into_block(copy, non_jcc.tail)
                            mb_curr = mb_curr.next
                            if not mb_curr:
                                break

                        # Make a note to ourselves to modify the graph structure later,
                        # for the taken side of the conditional. Change the goto target.
                        dgm.replace(non_jcc.serial, mb.serial, actual_jcc_target)
                        non_jcc.tail.l.b = actual_jcc_target

                        # We added instructions to the nonJcc block, so its def-use lists
                        # are now spoiled. Mark it dirty.
                        non_jcc.mark_lists_dirty()

        changed += dgm.apply(mba, self.cfi)
        # After we've processed every block, apply the deferred modifications to
        # the graph structure.

        # If there were any two-way conditionals, that means we copied
        # instructions onto the jcc taken blocks, which means the def-use info is
        # stale. Mark them dirty, and perform local optimization for the lulz too.
        if dirty_chains:
            mba.mark_chains_dirty()
            mba.optimize_local(0)

        # If we changed the graph, verify that we did so legally.
        if changed:
            logger.info(f"UNFLATTENER: blk.start={hex(blk.start)} (changed={changed})")
            mba.verify(True)

        # if safe mode, deactivate the plugin after usage to prevent the annoying crashes
        if self.plugin.SAFE_MODE:
            self.plugin.activated = False

        return changed


class UnflattenControlFlowRule(FlowOptimizationRule):
    """
    Removes opaque dispatcher-based control-flow flattening.
    Ported from pyhrdeobv2 (Eidolon).
    """

    DESCRIPTION = "CFG unflattening / dispatcher removal"

    def __init__(self):
        super().__init__()
        # restrict to LOCOPT if you like:
        self.maturities = [ida_hexrays.MMAT_LOCOPT]
        self.cfu: cf_unflattener_t | None = None  # lazy init
        self.SAFE_MODE = False
        self.RUN_MLTPL_DISPATCHERS = True
        self.activated = True

    def configure(self, cfg: dict[str, typing.Any]):
        super().configure(cfg)
        self.reset = cfg.get("FORCE_UNFLATTEN", False)
        self.SAFE_MODE = cfg.get("SAFE_MODE", False)
        self.RUN_MLTPL_DISPATCHERS = cfg.get("RUN_MLTPL_DISPATCHERS", True)
        if self.reset:
            self.reset_maturity()
            self.reset = False

    # D-810 will invoke this once per function (& maturity)
    # @typing.override  # todo: add upstream method
    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        mba = blk.mba
        if mba is None:
            return 0
        ea = mba.entry_ea

        # whitelist / blacklist handled by BlockOptimizerManager prior to call,
        # but keep a safeguard here for manual usage.
        if self.use_whitelist and ea not in self.whitelisted_function_ea_list:
            return 0
        if self.use_blacklist and ea in self.blacklisted_function_ea_list:
            return 0

        changed = 0
        try:
            if self.cfu is None:
                # reuse original class almost unchanged
                self.cfu = cf_unflattener_t(weakref.proxy(self))
            # cf_unflattener_t originally expected a block; give it the head
            blk0 = mba.get_mblock(0)
            changed = self.cfu.func(blk0)

        except Exception as exc:
            logger.error("Unflattening failed for %s: %s", hex(ea), exc, exc_info=True)
        finally:
            # Reset maturity so the pass can run again on the next function
            self.reset_maturity()
        return changed

    def enforce_unflatten(self, vaddr):
        """
        Enforce the unflattening of a function at addr.
        :param vaddr: Virtual address of function
        """
        if vaddr in self.blacklisted_function_ea_list:
            self.blacklisted_function_ea_list.remove(vaddr)
        if vaddr not in self.whitelisted_function_ea_list:
            self.whitelisted_function_ea_list.append(vaddr)

    def reset_maturity(self):
        if self.cfu:
            self.cfu.last_maturity = ida_hexrays.MMAT_ZERO

    @property
    def black_list(self) -> list[int]:
        return self.blacklisted_function_ea_list

    @property
    def white_list(self) -> list[int]:
        return self.whitelisted_function_ea_list
