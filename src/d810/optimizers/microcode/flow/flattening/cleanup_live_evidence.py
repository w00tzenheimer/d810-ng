"""Live Hex-Rays evidence collection for cleanup-family candidates."""
from __future__ import annotations

from collections.abc import Sequence

import ida_hexrays

from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FakeJumpPredFix,
    resolve_fake_jump_target,
    should_skip_fake_jump_predecessor,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    DEFAULT_MAX_MAGIC,
    DEFAULT_MIN_MAGIC,
    SingleIterationPredFix,
)
from d810.recon.flow.conditional_jump_eval import conditional_operand_size
from d810.recon.flow.loop_prover import prove_single_iteration

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
) -> tuple[SingleIterationPredFix, ...]:
    """Analyze one live loop header and derive proven single-iteration redirects."""
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
