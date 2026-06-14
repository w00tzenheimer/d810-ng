"""Live Hex-Rays evidence collection for cleanup-family candidates."""
from __future__ import annotations

from collections.abc import Sequence

import ida_hexrays

from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.passes.fake_jump import (
    FakeJumpPredFix,
    resolve_fake_jump_target,
    should_skip_fake_jump_predecessor,
)
from d810.passes.single_iteration import (
    DEFAULT_MAX_MAGIC,
    DEFAULT_MIN_MAGIC,
    SingleIterationConvertFix,
    SingleIterationPredFix,
)
from d810.analyses.control_flow.conditional_jump_eval import conditional_operand_size
from d810.analyses.control_flow.loop_prover import prove_single_iteration

FAKE_JUMP_CONDITIONAL_OPCODES = frozenset(
    {
        ida_hexrays.m_jz,
        ida_hexrays.m_jnz,
        ida_hexrays.m_jae,
        ida_hexrays.m_jb,
        ida_hexrays.m_ja,
        ida_hexrays.m_jbe,
        ida_hexrays.m_jg,
        ida_hexrays.m_jge,
        ida_hexrays.m_jl,
        ida_hexrays.m_jle,
    }
)


def collect_live_fake_jump_block_fixes(
    blk: object,
    *,
    logger: object | None = None,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> tuple[FakeJumpPredFix, ...]:
    """Analyze one live mblock and derive deterministic per-predecessor fixes."""
    if blk is None or blk.tail is None:
        return ()
    if blk.tail.opcode not in FAKE_JUMP_CONDITIONAL_OPCODES:
        return ()
    if blk.get_reginsn_qty() != 1:
        return ()
    if blk.tail.r.t != ida_hexrays.mop_n:
        return ()
    if blk.nextb is None:
        return ()
    if _live_block_has_terminal_successor(blk):
        return ()

    if logger is not None:
        logger.info(
            "Checking if block %s is fake loop: %s",
            blk.serial,
            format_minsn_t(blk.tail),
        )

    op_compared = ida_hexrays.mop_t(blk.tail.l)
    fixes: list[FakeJumpPredFix] = []

    for pred_serial in list(blk.predset):
        pred_blk = blk.mba.get_mblock(pred_serial)
        if pred_blk is None or pred_blk.tail is None:
            continue
        if _last_assignment_to_mop_is_nonconstant(pred_blk, op_compared):
            if logger is not None:
                logger.info(
                    "Pred %s updates compared operand for candidate fake jump %s "
                    "with a non-constant value; preserving carrier guard",
                    pred_blk.serial,
                    blk.serial,
                )
            continue

        branch_arm_target = _resolve_fake_jump_branch_arm_target(
            blk,
            pred_blk,
            op_compared,
        )
        if branch_arm_target is not None:
            if logger is not None:
                logger.info(
                    "Pred %s resolves fake jump via direct branch-arm assignment: "
                    "%s -> %s",
                    pred_blk.serial,
                    blk.serial,
                    branch_arm_target,
                )
            fixes.append(
                FakeJumpPredFix(
                    fake_block=int(blk.serial),
                    pred_block=int(pred_blk.serial),
                    new_target=int(branch_arm_target),
                )
            )
            continue

        cmp_variable_tracker = MopTracker(
            [op_compared],
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        cmp_variable_tracker.reset()
        pred_histories = cmp_variable_tracker.search_backward(
            pred_blk,
            pred_blk.tail,
        )

        resolved_histories = [h for h in pred_histories if h.is_resolved()]
        unresolved_count = len(pred_histories) - len(resolved_histories)

        if len(resolved_histories) == 0:
            if logger is not None:
                logger.debug(
                    "No resolved histories for pred %s, skipping",
                    pred_serial,
                )
            continue

        if should_skip_fake_jump_predecessor(
            len(resolved_histories),
            unresolved_count,
        ):
            if logger is not None:
                logger.warning(
                    "Pred %s has extreme unresolved:resolved ratio (%d vs %d) with few resolved - "
                    "unsafe to ignore unresolved, skipping",
                    pred_serial,
                    unresolved_count,
                    len(resolved_histories),
                )
            continue

        if unresolved_count > 0 and logger is not None:
            logger.debug(
                "Pred %s has %d unresolved and %d resolved paths - using resolved only",
                pred_serial,
                unresolved_count,
                len(resolved_histories),
            )

        pred_values = get_all_possibles_values(resolved_histories, [op_compared])
        pred_values = [value[0] for value in pred_values]
        if None in pred_values:
            if logger is not None:
                logger.info("Some path are not resolved, can't fix jump")
            return ()

        if logger is not None:
            logger.info(
                "Pred %s has %s possible path (%s different cst): %s",
                pred_blk.serial,
                len(pred_values),
                len(set(pred_values)),
                pred_values,
            )

        resolution = resolve_fake_jump_target(
            opcode=blk.tail.opcode,
            compared_value=blk.tail.r.nnn.value,
            pred_comparison_values=pred_values,
            taken_target=blk.tail.d.b,
            fallthrough_target=blk.nextb.serial,
            jz_opcode=ida_hexrays.m_jz,
            jnz_opcode=ida_hexrays.m_jnz,
            jae_opcode=ida_hexrays.m_jae,
            jb_opcode=ida_hexrays.m_jb,
            ja_opcode=ida_hexrays.m_ja,
            jbe_opcode=ida_hexrays.m_jbe,
            jg_opcode=ida_hexrays.m_jg,
            jge_opcode=ida_hexrays.m_jge,
            jl_opcode=ida_hexrays.m_jl,
            jle_opcode=ida_hexrays.m_jle,
            operand_size=conditional_operand_size(blk.tail.l, blk.tail.r),
        )
        if resolution.new_target is None:
            if logger is not None:
                logger.debug(
                    "Jump seems legit '%s' from %s: %s",
                    format_minsn_t(blk.tail),
                    pred_blk.serial,
                    pred_values,
                )
            continue

        fixes.append(
            FakeJumpPredFix(
                fake_block=int(blk.serial),
                pred_block=int(pred_blk.serial),
                new_target=int(resolution.new_target),
            )
        )

    return tuple(fixes)


def _live_block_successors(blk: object) -> tuple[int, ...]:
    if blk is None:
        return ()
    try:
        nsucc = int(blk.nsucc())
    except (AttributeError, TypeError, ValueError):
        return ()

    successors: list[int] = []
    for index in range(nsucc):
        try:
            successors.append(int(blk.succ(index)))
        except (AttributeError, TypeError, ValueError):
            return ()
    return tuple(successors)


def _live_successor_count(blk: object) -> int:
    if blk is None:
        return 0
    nsucc = getattr(blk, "nsucc", None)
    if callable(nsucc):
        try:
            return int(nsucc())
        except (AttributeError, TypeError, ValueError):
            return 0
    if nsucc is not None:
        try:
            return int(nsucc)
        except (TypeError, ValueError):
            return 0
    return len(_live_block_successors(blk))


def _live_block_has_terminal_successor(blk: object) -> bool:
    mba = getattr(blk, "mba", None)
    if mba is None:
        return False
    getter = getattr(mba, "get_mblock", None)
    if not callable(getter):
        return False
    for succ in _live_block_successors(blk):
        succ_blk = getter(int(succ))
        if succ_blk is not None and _live_successor_count(succ_blk) == 0:
            return True
    return False


def _resolve_fake_jump_branch_arm_target(
    blk: object,
    pred_blk: object,
    op_compared: object,
) -> int | None:
    """Resolve a direct 2-way predecessor arm without merging sibling histories."""
    if blk is None or pred_blk is None or op_compared is None:
        return None
    if getattr(blk, "tail", None) is None or getattr(pred_blk, "tail", None) is None:
        return None
    if getattr(blk, "nextb", None) is None:
        return None

    pred_successors = _live_block_successors(pred_blk)
    if len(pred_successors) != 2 or int(blk.serial) not in pred_successors:
        return None

    direct_const = _find_live_state_assignment(pred_blk, op_compared)
    if direct_const is None:
        return None

    resolution = resolve_fake_jump_target(
        opcode=int(blk.tail.opcode),
        compared_value=int(blk.tail.r.nnn.value),
        pred_comparison_values=(int(direct_const),),
        taken_target=int(blk.tail.d.b),
        fallthrough_target=int(blk.nextb.serial),
        jz_opcode=ida_hexrays.m_jz,
        jnz_opcode=ida_hexrays.m_jnz,
    )
    if resolution.new_target is None:
        return None
    return int(resolution.new_target)


def collect_live_fake_jump_fixes(
    mba: object,
    *,
    logger: object | None = None,
    max_nb_block: int = 100,
    max_path: int = 1000,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[FakeJumpPredFix, ...]:
    """Derive validated FakeJump fixes from a live mba without mutating it."""
    if mba is None:
        return ()

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return ()

    fixes: list[FakeJumpPredFix] = []
    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        fixes.extend(
            collect_live_fake_jump_block_fixes(
                blk,
                logger=logger,
                max_nb_block=max_nb_block,
                max_path=max_path,
            )
        )
    return tuple(fixes)


def _is_magic_constant(
    value: int | None,
    *,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
) -> bool:
    if value is None:
        return False
    unsigned_value = value & 0xFFFFFFFF
    return min_magic <= unsigned_value <= max_magic


def _get_jnz_comparison_info(blk: object) -> tuple[object | None, int | None]:
    if blk is None or blk.tail is None:
        return None, None
    if blk.tail.opcode != ida_hexrays.m_jnz:
        return None, None

    if blk.tail.r and blk.tail.r.t == ida_hexrays.mop_n:
        return blk.tail.l, blk.tail.r.signed_value()
    if blk.tail.l and blk.tail.l.t == ida_hexrays.mop_n:
        return blk.tail.r, blk.tail.l.signed_value()
    return None, None


def _get_equality_jump_comparison_info(
    blk: object,
) -> tuple[int | None, object | None, int | None]:
    if blk is None or blk.tail is None:
        return None, None, None
    if blk.tail.opcode not in (ida_hexrays.m_jz, ida_hexrays.m_jnz):
        return None, None, None

    if blk.tail.r and blk.tail.r.t == ida_hexrays.mop_n:
        return blk.tail.opcode, blk.tail.l, blk.tail.r.signed_value()
    if blk.tail.l and blk.tail.l.t == ida_hexrays.mop_n:
        return blk.tail.opcode, blk.tail.r, blk.tail.l.signed_value()
    return None, None, None


def _find_live_state_assignment(blk: object, state_mop: object) -> int | None:
    if blk is None or state_mop is None:
        return None

    insn = blk.tail
    while insn:
        if insn.opcode == ida_hexrays.m_mov:
            if insn.d and insn.d.equal_mops(state_mop, ida_hexrays.EQ_IGNSIZE):
                if insn.l and insn.l.t == ida_hexrays.mop_n:
                    return insn.l.signed_value()
        insn = insn.prev
    return None


def _mop_subtree_reads(node: object, mop: object, depth: int = 0) -> bool:
    """Return True when source operand ``node`` reads ``mop`` (descending nested insns).

    Walks the ``l``/``r``/``d`` operand tree of a source expression, descending into
    nested ``mop_d`` sub-instructions, so an induction update like
    ``i = (i + 1)`` (where ``i`` hides inside a sub-add) is still detected.
    """
    if node is None or mop is None or depth > 8:
        return False
    equal_mops = getattr(node, "equal_mops", None)
    if callable(equal_mops):
        try:
            if equal_mops(mop, ida_hexrays.EQ_IGNSIZE):
                return True
        except (TypeError, ValueError):
            pass
    sub = getattr(node, "d", None)
    if sub is not None and sub is not node:
        for slot in ("l", "r", "d"):
            if _mop_subtree_reads(getattr(sub, slot, None), mop, depth + 1):
                return True
    return False


def _last_assignment_to_mop_is_nonconstant(blk: object, mop: object) -> bool:
    """Return True when ``blk``'s last write to ``mop`` is a dynamic *carrier* update.

    Fake-jump cleanup may bypass a conditional when each predecessor gives the
    compared operand a known constant.  That is not valid for loop latches whose
    predecessor computes the compared operand dynamically *from itself*, e.g.
    ``i = i + 1`` followed by ``jb i, bound``.  In that shape the branch is the
    loop-carrier guard and must remain in the CFG.

    The guard fires only for a **self-referential** non-constant write — one whose
    source reads the compared operand back (a genuine induction/accumulation).  A
    plain copy/widen of the operand from another register/temporary
    (``mov``/``xdu`` of a different mop), as emitted by OLLVM dispatcher state
    shuffling, is *not* a carrier update: it falls through to the deterministic
    MopTracker resolution, which independently proves whether the jump is fake.
    """
    if blk is None or mop is None:
        return False
    insn = getattr(blk, "tail", None)
    while insn is not None:
        dest = getattr(insn, "d", None)
        equal_mops = getattr(dest, "equal_mops", None)
        if (
            dest is not None
            and callable(equal_mops)
            and equal_mops(mop, ida_hexrays.EQ_IGNSIZE)
        ):
            is_const_mov = (
                getattr(insn, "opcode", None) == ida_hexrays.m_mov
                and getattr(getattr(insn, "l", None), "t", None) == ida_hexrays.mop_n
            )
            if is_const_mov:
                return False
            # Non-constant write: only a self-referential update (the operand
            # reappears in the source) is a real loop carrier worth preserving.
            return _mop_subtree_reads(
                getattr(insn, "l", None), mop
            ) or _mop_subtree_reads(getattr(insn, "r", None), mop)
        insn = getattr(insn, "prev", None)
    return False


def _iter_pre_tail_instructions(blk: object) -> tuple[object, ...]:
    if blk is None or blk.tail is None:
        return ()
    instructions: list[object] = []
    insn = blk.tail.prev
    while insn is not None:
        instructions.append(insn)
        insn = insn.prev
    return tuple(reversed(instructions))


def _copy_source_for_destination(insn: object, dest_mop: object) -> object | None:
    if insn is None or dest_mop is None:
        return None
    if getattr(insn, "opcode", None) not in (ida_hexrays.m_mov, ida_hexrays.m_xdu):
        return None
    dest = getattr(insn, "d", None)
    if dest is None or not dest.equal_mops(dest_mop, ida_hexrays.EQ_IGNSIZE):
        return None
    return getattr(insn, "l", None)


def _copied_state_update_operands(
    blk: object,
    compared_mop: object,
) -> tuple[object, object] | None:
    """Return ``(state_mop, update_mop)`` for a tiny copied-carrier header.

    This recognizes headers shaped like::

        cmp_carrier = state_carrier
        state_carrier = update_carrier
        jz cmp_carrier, MAGIC, @header

    The helper deliberately rejects any unrelated pre-tail instruction because
    the resulting redirect skips the header body.
    """
    instructions = _iter_pre_tail_instructions(blk)
    if len(instructions) != 2:
        return None

    state_mop = _copy_source_for_destination(instructions[0], compared_mop)
    if state_mop is None:
        return None

    update_mop = _copy_source_for_destination(instructions[1], state_mop)
    if update_mop is None:
        return None
    return state_mop, update_mop


def _copied_comparison_source_mop(
    blk: object,
    compared_mop: object,
) -> object | None:
    """Return the source copied into ``compared_mop`` by a side-effect-free header."""
    source_mop = None
    instructions = _iter_pre_tail_instructions(blk)
    if not instructions:
        return None
    for insn in instructions:
        if getattr(insn, "opcode", None) not in (ida_hexrays.m_mov, ida_hexrays.m_xdu):
            return None
        copied_source = _copy_source_for_destination(insn, compared_mop)
        if copied_source is not None:
            source_mop = copied_source
    return source_mop


def _resolve_live_mop_constants(
    pred_blk: object,
    mop: object,
    *,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> frozenset[int] | None:
    if pred_blk is None or mop is None:
        return None
    if getattr(mop, "t", None) == ida_hexrays.mop_n:
        return frozenset((int(mop.signed_value()),))

    direct_const = _find_live_state_assignment(pred_blk, mop)
    if direct_const is not None:
        return frozenset((int(direct_const),))

    if getattr(pred_blk, "tail", None) is None:
        return None

    tracker = MopTracker([mop], max_nb_block=max_nb_block, max_path=max_path)
    tracker.reset()
    histories = tracker.search_backward(pred_blk, pred_blk.tail)
    resolved_histories = [history for history in histories if history.is_resolved()]
    if not resolved_histories or len(resolved_histories) != len(histories):
        return None

    values = get_all_possibles_values(resolved_histories, [mop])
    constants = {value[0] for value in values if value and value[0] is not None}
    if len(constants) != len(values) or not constants:
        return None
    return frozenset(int(value) for value in constants)


def _resolve_live_mop_constant(
    pred_blk: object,
    mop: object,
    *,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> int | None:
    constants = _resolve_live_mop_constants(
        pred_blk,
        mop,
        max_nb_block=max_nb_block,
        max_path=max_path,
    )
    if constants is None or len(constants) != 1:
        return None
    return int(next(iter(constants)))


def _equality_jump_target(
    *,
    opcode: int,
    value: int,
    check_const: int,
    taken_target: int,
    fallthrough_target: int,
) -> int | None:
    if opcode == ida_hexrays.m_jz:
        return int(taken_target if value == check_const else fallthrough_target)
    if opcode == ida_hexrays.m_jnz:
        return int(taken_target if value != check_const else fallthrough_target)
    return None


def _collect_copied_carrier_single_iteration_fixes(
    blk: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> tuple[SingleIterationPredFix, ...]:
    opcode, compared_mop, check_const = _get_equality_jump_comparison_info(blk)
    if opcode is None or compared_mop is None or not _is_magic_constant(
        check_const,
        min_magic=min_magic,
        max_magic=max_magic,
    ):
        return ()

    taken_target, fallthrough_target = _get_conditional_targets(blk)
    if taken_target is None or fallthrough_target is None:
        return ()
    if int(taken_target) != int(blk.serial) and int(fallthrough_target) != int(
        blk.serial
    ):
        return ()

    copied_operands = _copied_state_update_operands(blk, compared_mop)
    if copied_operands is None:
        if logger is not None:
            logger.debug(
                "Copied-carrier single-iteration rejected at block %d: "
                "pre-tail shape not carrier-copy/update",
                int(blk.serial),
            )
        return ()
    state_mop, update_mop = copied_operands

    fixes: list[SingleIterationPredFix] = []
    preds = tuple(int(serial) for serial in getattr(blk, "predset", ()))
    for pred in preds:
        if pred == int(blk.serial):
            continue
        pred_blk = blk.mba.get_mblock(pred)
        if pred_blk is None or pred_blk.nsucc() != 1:
            continue
        if int(pred_blk.succ(0)) != int(blk.serial):
            continue

        init_const = _resolve_live_mop_constant(
            pred_blk,
            state_mop,
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        update_constants = _resolve_live_mop_constants(
            pred_blk,
            update_mop,
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        if not _is_magic_constant(
            init_const,
            min_magic=min_magic,
            max_magic=max_magic,
        ) or not update_constants or not all(
            _is_magic_constant(
                update_const,
                min_magic=min_magic,
                max_magic=max_magic,
            )
            for update_const in update_constants
        ):
            if logger is not None:
                logger.debug(
                    "Copied-carrier single-iteration rejected at block %d pred %d: "
                    "unresolved init/update constants init=%r update=%r",
                    int(blk.serial),
                    int(pred),
                    init_const,
                    sorted(update_constants) if update_constants else None,
                )
            continue

        first_target = _equality_jump_target(
            opcode=int(opcode),
            value=int(init_const),
            check_const=int(check_const),
            taken_target=int(taken_target),
            fallthrough_target=int(fallthrough_target),
        )
        second_targets = frozenset(
            _equality_jump_target(
                opcode=int(opcode),
                value=int(update_const),
                check_const=int(check_const),
                taken_target=int(taken_target),
                fallthrough_target=int(fallthrough_target),
            )
            for update_const in update_constants
        )
        if None in second_targets:
            continue
        if first_target != int(blk.serial):
            if logger is not None:
                logger.debug(
                    "Copied-carrier single-iteration rejected at block %d pred %d: "
                    "first target %r is not loop header %d",
                    int(blk.serial),
                    int(pred),
                    first_target,
                    int(blk.serial),
                )
            continue
        if len(second_targets) != 1:
            if logger is not None:
                logger.debug(
                    "Copied-carrier single-iteration rejected at block %d pred %d: "
                    "update constants select multiple targets %r",
                    int(blk.serial),
                    int(pred),
                    sorted(second_targets),
                )
            continue
        second_target = int(next(iter(second_targets)))
        if second_target == int(blk.serial):
            if logger is not None:
                logger.debug(
                    "Copied-carrier single-iteration rejected at block %d pred %d: "
                    "update still loops to %d",
                    int(blk.serial),
                    int(pred),
                    int(second_target),
                )
            continue

        if logger is not None:
            logger.info(
                "Detected copied-carrier single-iteration loop at block %d: "
                "pred=%d init=0x%X check=0x%X updates=%s target=%d",
                int(blk.serial),
                int(pred),
                int(init_const) & 0xFFFFFFFF,
                int(check_const) & 0xFFFFFFFF,
                ",".join(
                    f"0x{int(update_const) & 0xFFFFFFFF:X}"
                    for update_const in sorted(update_constants)
                ),
                int(second_target),
            )

        fixes.append(
            SingleIterationPredFix(
                loop_header=int(blk.serial),
                pred_block=int(pred),
                new_target=int(second_target),
            )
        )

    return tuple(fixes)


def _collect_copied_comparison_convert_fixes(
    blk: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> tuple[SingleIterationConvertFix, ...]:
    """Convert a copied-comparison self-loop once all real entries exit.

    The block's non-tail body must be only register copies, preserving those
    side effects when the tail is changed to a goto.  The self predecessor is
    ignored only when every non-self predecessor proves the copied value takes
    the non-self exit arm.
    """
    opcode, compared_mop, check_const = _get_equality_jump_comparison_info(blk)
    if opcode is None or compared_mop is None or not _is_magic_constant(
        check_const,
        min_magic=min_magic,
        max_magic=max_magic,
    ):
        return ()

    taken_target, fallthrough_target = _get_conditional_targets(blk)
    if taken_target is None or fallthrough_target is None:
        return ()
    if int(taken_target) != int(blk.serial) and int(fallthrough_target) != int(
        blk.serial
    ):
        return ()

    source_mop = _copied_comparison_source_mop(blk, compared_mop)
    if source_mop is None:
        return ()

    exit_targets: set[int] = set()
    real_pred_count = 0
    for pred in tuple(int(serial) for serial in getattr(blk, "predset", ())):
        if pred == int(blk.serial):
            continue
        pred_blk = blk.mba.get_mblock(pred)
        if pred_blk is None or pred_blk.nsucc() != 1:
            return ()
        if int(pred_blk.succ(0)) != int(blk.serial):
            return ()
        real_pred_count += 1

        pred_values = _resolve_live_mop_constants(
            pred_blk,
            source_mop,
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        if not pred_values or not all(
            _is_magic_constant(
                value,
                min_magic=min_magic,
                max_magic=max_magic,
            )
            for value in pred_values
        ):
            return ()

        for value in pred_values:
            selected_target = _equality_jump_target(
                opcode=int(opcode),
                value=int(value),
                check_const=int(check_const),
                taken_target=int(taken_target),
                fallthrough_target=int(fallthrough_target),
            )
            if selected_target is None or int(selected_target) == int(blk.serial):
                return ()
            exit_targets.add(int(selected_target))

    if real_pred_count == 0 or len(exit_targets) != 1:
        return ()
    exit_target = next(iter(exit_targets))
    if exit_target == int(blk.serial):
        return ()

    if logger is not None:
        logger.info(
            "Detected copied-comparison single-iteration convert at block %d: "
            "target=%d check=0x%X",
            int(blk.serial),
            int(exit_target),
            int(check_const) & 0xFFFFFFFF,
        )

    return (
        SingleIterationConvertFix(
            loop_header=int(blk.serial),
            new_target=int(exit_target),
        ),
    )


def _collect_body_preserving_single_iteration_fixes(
    blk: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
) -> tuple[SingleIterationPredFix, ...]:
    """Redirect loop body backedges when the body update proves the next exit.

    This covers header-only loops shaped like::

        header:
            jz state, MAGIC, body
        body:
            side_effects
            state = EXIT_MAGIC
            goto header

    Rewriting ``body -> header`` to ``body -> exit`` preserves the body
    side effects and skips only the second, now-proven header check.  The
    initial header edge is intentionally left untouched, so no proof of the
    incoming state value is required.
    """
    opcode, state_mop, check_const = _get_equality_jump_comparison_info(blk)
    if opcode is None or state_mop is None or not _is_magic_constant(
        check_const,
        min_magic=min_magic,
        max_magic=max_magic,
    ):
        return ()
    if _iter_pre_tail_instructions(blk):
        return ()

    taken_target, fallthrough_target = _get_conditional_targets(blk)
    if taken_target is None or fallthrough_target is None:
        return ()

    fixes: list[SingleIterationPredFix] = []
    header_successors = {int(taken_target), int(fallthrough_target)}
    preds = tuple(int(serial) for serial in getattr(blk, "predset", ()))
    for pred in preds:
        if pred not in header_successors:
            continue
        pred_blk = blk.mba.get_mblock(pred)
        if pred_blk is None or pred_blk.nsucc() != 1:
            continue
        if int(pred_blk.succ(0)) != int(blk.serial):
            continue

        update_const = _find_live_state_assignment(pred_blk, state_mop)
        if not _is_magic_constant(
            update_const,
            min_magic=min_magic,
            max_magic=max_magic,
        ):
            continue

        exit_target = _equality_jump_target(
            opcode=int(opcode),
            value=int(update_const),
            check_const=int(check_const),
            taken_target=int(taken_target),
            fallthrough_target=int(fallthrough_target),
        )
        if exit_target is None:
            continue
        if int(exit_target) in (int(blk.serial), int(pred)):
            continue
        if int(exit_target) not in header_successors:
            continue

        if logger is not None:
            logger.info(
                "Detected body-preserving single-iteration loop at block %d: "
                "body=%d update=0x%X check=0x%X target=%d",
                int(blk.serial),
                int(pred),
                int(update_const) & 0xFFFFFFFF,
                int(check_const) & 0xFFFFFFFF,
                int(exit_target),
            )

        fixes.append(
            SingleIterationPredFix(
                loop_header=int(blk.serial),
                pred_block=int(pred),
                new_target=int(exit_target),
            )
        )

    return tuple(fixes)


def _get_conditional_targets(blk: object) -> tuple[int | None, int | None]:
    if blk is None or blk.tail is None or not hasattr(blk, "succset"):
        return None, None

    taken_target = getattr(getattr(blk.tail, "d", None), "b", None)
    if taken_target is None:
        return None, None

    successors = tuple(int(serial) for serial in getattr(blk, "succset", ()))
    fallthrough_candidates = tuple(
        serial for serial in successors if serial != int(taken_target)
    )
    if len(fallthrough_candidates) != 1:
        return None, None
    return int(taken_target), int(fallthrough_candidates[0])


def collect_live_single_iteration_block_fixes(
    blk: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> tuple[SingleIterationPredFix, ...]:
    """Analyze one live loop header and derive proven single-iteration redirects."""
    copied_carrier_fixes = _collect_copied_carrier_single_iteration_fixes(
        blk,
        logger=logger,
        min_magic=min_magic,
        max_magic=max_magic,
        max_nb_block=max_nb_block,
        max_path=max_path,
    )
    if copied_carrier_fixes:
        return copied_carrier_fixes

    body_preserving_fixes = _collect_body_preserving_single_iteration_fixes(
        blk,
        logger=logger,
        min_magic=min_magic,
        max_magic=max_magic,
    )
    if body_preserving_fixes:
        return body_preserving_fixes

    state_mop, check_const = _get_jnz_comparison_info(blk)
    if state_mop is None or not _is_magic_constant(
        check_const,
        min_magic=min_magic,
        max_magic=max_magic,
    ):
        return ()

    taken_target, fallthrough_target = _get_conditional_targets(blk)
    if taken_target is None or fallthrough_target is None:
        return ()

    preds = tuple(int(serial) for serial in getattr(blk, "predset", ()))
    succs = set(int(serial) for serial in getattr(blk, "succset", ()))
    backedge_preds = tuple(pred for pred in preds if pred in succs)
    if not backedge_preds:
        return ()

    entry_preds = tuple(pred for pred in preds if pred not in succs)
    if not entry_preds:
        return ()

    fixes_by_key: dict[tuple[int, int], SingleIterationPredFix] = {}
    conflicts: set[tuple[int, int]] = set()

    for backedge_pred in backedge_preds:
        backedge_blk = blk.mba.get_mblock(backedge_pred)
        if backedge_blk is None or backedge_blk.nsucc() != 1:
            continue
        if int(backedge_blk.succ(0)) != int(blk.serial):
            continue

        update_const = _find_live_state_assignment(backedge_blk, state_mop)
        if not _is_magic_constant(
            update_const,
            min_magic=min_magic,
            max_magic=max_magic,
        ):
            continue

        for entry_pred in entry_preds:
            entry_blk = blk.mba.get_mblock(entry_pred)
            if entry_blk is None or entry_blk.nsucc() != 1:
                continue
            if int(entry_blk.succ(0)) != int(blk.serial):
                continue

            init_const = _find_live_state_assignment(entry_blk, state_mop)
            if not _is_magic_constant(
                init_const,
                min_magic=min_magic,
                max_magic=max_magic,
            ):
                continue

            if not prove_single_iteration(init_const, check_const, update_const):
                continue

            if logger is not None:
                logger.info(
                    "Detected single-iteration loop at block %d: init=0x%X, check=0x%X, update=0x%X",
                    int(blk.serial),
                    int(init_const),
                    int(check_const),
                    int(update_const),
                )

            for pred_block, new_target in (
                (int(entry_pred), int(fallthrough_target)),
                (int(backedge_pred), int(taken_target)),
            ):
                key = (int(blk.serial), pred_block)
                fix = SingleIterationPredFix(
                    loop_header=int(blk.serial),
                    pred_block=pred_block,
                    new_target=new_target,
                )
                existing = fixes_by_key.get(key)
                if existing is None:
                    fixes_by_key[key] = fix
                    continue
                if existing.new_target != new_target:
                    conflicts.add(key)

    for key in conflicts:
        fixes_by_key.pop(key, None)

    return tuple(fixes_by_key[key] for key in sorted(fixes_by_key))

def collect_live_single_iteration_fixes(
    mba: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    max_nb_block: int = 100,
    max_path: int = 1000,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[SingleIterationPredFix, ...]:
    """Derive validated single-iteration redirects from a live mba."""
    if mba is None:
        return ()

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return ()

    fixes_by_key: dict[tuple[int, int], SingleIterationPredFix] = {}
    conflicts: set[tuple[int, int]] = set()

    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        for fix in collect_live_single_iteration_block_fixes(
            blk,
            logger=logger,
            min_magic=min_magic,
            max_magic=max_magic,
            max_nb_block=max_nb_block,
            max_path=max_path,
        ):
            key = (fix.loop_header, fix.pred_block)
            existing = fixes_by_key.get(key)
            if existing is None:
                fixes_by_key[key] = fix
                continue
            if existing.new_target != fix.new_target:
                conflicts.add(key)

    for key in conflicts:
        fixes_by_key.pop(key, None)

    return tuple(fixes_by_key[key] for key in sorted(fixes_by_key))


def collect_live_single_iteration_convert_fixes(
    mba: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    max_nb_block: int = 100,
    max_path: int = 1000,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[SingleIterationConvertFix, ...]:
    """Derive validated single-iteration header conversions from a live mba."""
    if mba is None:
        return ()

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return ()

    fixes_by_block: dict[int, SingleIterationConvertFix] = {}
    conflicts: set[int] = set()

    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        for fix in _collect_copied_comparison_convert_fixes(
            blk,
            logger=logger,
            min_magic=min_magic,
            max_magic=max_magic,
            max_nb_block=max_nb_block,
            max_path=max_path,
        ):
            existing = fixes_by_block.get(fix.loop_header)
            if existing is None:
                fixes_by_block[fix.loop_header] = fix
                continue
            if existing.new_target != fix.new_target:
                conflicts.add(fix.loop_header)

    for block_serial in conflicts:
        fixes_by_block.pop(block_serial, None)

    return tuple(fixes_by_block[key] for key in sorted(fixes_by_block))
