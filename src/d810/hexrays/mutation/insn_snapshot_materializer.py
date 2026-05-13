"""Helpers for validating and rebuilding instruction snapshots."""
from __future__ import annotations

from collections.abc import Sequence

import ida_hexrays

from d810.cfg.flowgraph import InsnSnapshot
from d810.core.logging import getLogger
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.utils.hexrays_formatters import sanitize_ea

logger = getLogger(__name__)


def _iter_insn_snapshot_operands(insn_snapshot: InsnSnapshot) -> tuple[tuple[str, object], ...]:
    if insn_snapshot.operand_slots:
        return insn_snapshot.operand_slots
    slot_names = ("l", "r", "d")
    return tuple(
        (slot_names[idx], operand)
        for idx, operand in enumerate(insn_snapshot.operands[: len(slot_names)])
    )


def instruction_snapshot_safe_ea(
    instructions: Sequence[InsnSnapshot],
    *,
    fallback: int,
) -> int:
    return next(
        (sanitize_ea(instruction.ea) for instruction in instructions if instruction.ea > 0),
        sanitize_ea(fallback) or 1,
    )


def _sanitize_mop_tree_eas(mop: "ida_hexrays.mop_t", safe_ea: int) -> None:
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        mop.d.ea = safe_ea
        _sanitize_mop_tree_eas(mop.d.l, safe_ea)
        _sanitize_mop_tree_eas(mop.d.r, safe_ea)
        _sanitize_mop_tree_eas(mop.d.d, safe_ea)


def _rebuild_mop_from_snapshot_operand(operand: object, safe_ea: int) -> "ida_hexrays.mop_t":
    if isinstance(operand, MopSnapshot):
        mop = operand.to_mop()
    elif hasattr(operand, "to_mop"):
        mop = operand.to_mop()  # type: ignore[assignment]
    elif isinstance(operand, ida_hexrays.mop_t):
        mop = ida_hexrays.mop_t()
        mop.assign(operand)
    else:
        raise TypeError(f"Unsupported InsertBlock operand type: {type(operand).__name__}")

    if not isinstance(mop, ida_hexrays.mop_t):
        raise TypeError(f"Operand did not rebuild to mop_t: {type(mop).__name__}")
    expected_t = getattr(operand, "t", None)
    if isinstance(expected_t, int) and mop.t != expected_t:
        raise TypeError(
            f"Operand rebuilt to wrong mop type: expected {expected_t}, got {mop.t}"
        )
    _sanitize_mop_tree_eas(mop, safe_ea)
    return mop


def validate_insn_snapshots(instructions: Sequence[InsnSnapshot]) -> str | None:
    """Return None when snapshots are structurally rebuildable."""
    safe_ea = instruction_snapshot_safe_ea(instructions, fallback=1)
    try:
        for instruction in instructions:
            for _slot_name, operand in _iter_insn_snapshot_operands(instruction):
                _rebuild_mop_from_snapshot_operand(operand, safe_ea)
    except Exception as exc:
        return str(exc)
    return None


def _build_minsn_from_snapshot(
    insn_snapshot: InsnSnapshot,
    safe_ea: int,
) -> "ida_hexrays.minsn_t":
    new_ins = ida_hexrays.minsn_t(sanitize_ea(safe_ea))
    new_ins.opcode = insn_snapshot.opcode

    new_ins.l = ida_hexrays.mop_t()
    new_ins.l.erase()
    new_ins.r = ida_hexrays.mop_t()
    new_ins.r.erase()
    new_ins.d = ida_hexrays.mop_t()
    new_ins.d.erase()

    for slot_name, operand in _iter_insn_snapshot_operands(insn_snapshot):
        setattr(new_ins, slot_name, _rebuild_mop_from_snapshot_operand(operand, safe_ea))

    return new_ins


def _stkvar_id(mop: "ida_hexrays.mop_t") -> tuple[int, int] | None:
    """Return ``(stkoff, size)`` for a ``mop_S``; ``None`` otherwise."""
    if mop is None:
        return None
    try:
        if int(mop.t) != ida_hexrays.mop_S:
            return None
        return (int(mop.s.off), int(mop.size))
    except Exception:
        return None


def _mop_structural_key(mop: "ida_hexrays.mop_t") -> tuple | None:
    """Return a hashable structural identity for simple ``mop_t`` operands.

    Identity covers exactly the operand kinds we need to compare for
    ``m_add(X, K) -> stkvar`` canonicalisation: stack variables, function
    args (which IDA represents as ``mop_S`` with a stkvar id in shadow
    space at MMAT_GLBOPT1), registers, and integer constants.  All other
    operand kinds return ``None`` so the matcher skips them rather than
    risk a false positive.
    """
    if mop is None:
        return None
    try:
        kind = int(mop.t)
        size = int(getattr(mop, "size", 0) or 0)
        if kind == int(ida_hexrays.mop_S):
            return ("S", int(mop.s.off), size)
        if kind == int(ida_hexrays.mop_n):
            return ("n", int(mop.nnn.value))
        if kind == int(ida_hexrays.mop_r):
            return ("r", int(mop.r), size)
    except Exception:
        return None
    return None


def canonicalize_inline_add_to_stkvar(
    insns: Sequence["ida_hexrays.minsn_t"],
) -> int:
    """Rewrite ``mop_d(add(X, K))`` operands to their stkvar alias.

    When an ``m_add X, K -> stkvar_S`` definition appears earlier in
    ``insns`` (and ``stkvar_S`` is not subsequently overwritten),
    operands of the form ``mop_d(m_add(X, K))`` elsewhere in the body
    are rewritten to reference ``stkvar_S`` directly.

    Motivation: HCC's ``_capture_transitive_def_chain`` prepends stkvar
    definitions to InsertBlock bodies so the new block is self-contained,
    but the body's later instructions still address memory via the inline
    ``(arg_20+#0xD0)`` form.  IDA's intraprocedural aliasing analysis
    cannot prove ``*(a5+0xD0)`` and ``*%var_178`` refer to the same
    memory when one side writes inline and downstream readers use the
    stkvar; ``optimize_global`` then DCEs the writes.  Canonicalising
    both sides on the stkvar keeps the byte-emit corridor alive.

    Returns the number of operand rewrites performed; pure in-place
    mutation on the live ``minsn_t`` objects.
    """
    if not insns:
        return 0

    m_add = int(ida_hexrays.m_add)
    mop_n_t = int(ida_hexrays.mop_n)
    mop_d_t = int(ida_hexrays.mop_d)
    mop_S_t = int(ida_hexrays.mop_S)
    rewrites = 0

    # Each active def: ``(frozenset of unordered operand keys, dest_mop, dest_id)``.
    defs_active: list[tuple] = []

    def _rewrite_operand(operand: "ida_hexrays.mop_t") -> None:
        nonlocal rewrites
        if operand is None:
            return
        try:
            if int(operand.t) != mop_d_t:
                return
            sub = operand.d
            if sub is None:
                return
            if int(sub.opcode) == m_add:
                l_key = _mop_structural_key(sub.l)
                r_key = _mop_structural_key(sub.r)
                if l_key is not None and r_key is not None:
                    use_pair = frozenset((l_key, r_key))
                    for def_pair, def_dest, _dest_id in defs_active:
                        if def_pair == use_pair:
                            operand.assign(def_dest)
                            rewrites += 1
                            return
            _rewrite_operand(sub.l)
            _rewrite_operand(sub.r)
            _rewrite_operand(sub.d)
        except Exception:
            return

    for ins in insns:
        # Diagnostic: dump the destination kind for m_stx instructions so we
        # can see whether the byte-emit writes have d.t == mop_d (and what
        # the sub-instruction looks like).
        try:
            if int(ins.opcode) == int(ida_hexrays.m_stx) and ins.d is not None:
                d_kind = int(ins.d.t)
                if d_kind == mop_d_t and ins.d.d is not None:
                    sub_op = int(ins.d.d.opcode)
                    l_kind = (
                        int(ins.d.d.l.t)
                        if ins.d.d.l is not None
                        else -1
                    )
                    r_kind = (
                        int(ins.d.d.r.t)
                        if ins.d.d.r is not None
                        else -1
                    )
                    logger.info(
                        "MATERIALIZE_CANON_STX_DEST d.t=mop_d sub_opcode=%d "
                        "sub.l.t=%d sub.r.t=%d defs_active=%d dstr=%r",
                        sub_op,
                        l_kind,
                        r_kind,
                        len(defs_active),
                        ins.dstr(),
                    )
                else:
                    logger.info(
                        "MATERIALIZE_CANON_STX_DEST d.t=%d (NOT mop_d) "
                        "defs_active=%d dstr=%r",
                        d_kind,
                        len(defs_active),
                        ins.dstr(),
                    )
        except Exception:
            pass
        _rewrite_operand(ins.l)
        _rewrite_operand(ins.r)
        _rewrite_operand(ins.d)
        dest_id = _stkvar_id(ins.d)
        if dest_id is not None:
            defs_active = [d for d in defs_active if d[2] != dest_id]
        try:
            if int(ins.opcode) != m_add:
                continue
            if ins.d is None or int(ins.d.t) != mop_S_t:
                continue
            l_is_const = (
                ins.l is not None and int(ins.l.t) == mop_n_t
            )
            r_is_const = (
                ins.r is not None and int(ins.r.t) == mop_n_t
            )
            if l_is_const == r_is_const:
                continue
            l_key = _mop_structural_key(ins.l)
            r_key = _mop_structural_key(ins.r)
            if l_key is None or r_key is None:
                continue
            new_id = _stkvar_id(ins.d)
            if new_id is None:
                continue
            defs_active.append((frozenset((l_key, r_key)), ins.d, new_id))
        except Exception:
            continue

    return rewrites


def materialize_insn_snapshots(
    instructions: Sequence[InsnSnapshot],
    *,
    safe_ea: int,
) -> list["ida_hexrays.minsn_t"]:
    safe_ea = sanitize_ea(safe_ea) or 1
    insns = [_build_minsn_from_snapshot(instruction, safe_ea) for instruction in instructions]
    n_rewrites = canonicalize_inline_add_to_stkvar(insns)
    if logger.info_on:
        candidate_defs = 0
        first_def_dump = ""
        for i in insns:
            if (
                int(i.opcode) == int(ida_hexrays.m_add)
                and i.d is not None
                and int(i.d.t) == int(ida_hexrays.mop_S)
            ):
                candidate_defs += 1
                if not first_def_dump:
                    try:
                        first_def_dump = (
                            f" first_def: l.t={int(i.l.t)} r.t={int(i.r.t)} "
                            f"d.t={int(i.d.t)} dstr={i.dstr()!r}"
                        )
                    except Exception:
                        first_def_dump = " first_def: <dump failed>"
        logger.info(
            "MATERIALIZE_CANON ninsns=%d candidate_add_defs=%d rewrites=%d%s",
            len(insns),
            candidate_defs,
            n_rewrites,
            first_def_dump,
        )
    return insns


def mark_all_insns_persistent(mba: "ida_hexrays.mba_t") -> int:
    """Set ``IPROP_PERSIST`` on every ``minsn_t`` in the live mba.

    Brute-force "do not DCE anything" hammer: IDA's documented per-
    instruction kept-alive flag.  Useful as a diagnostic to confirm
    whether ``optimize_global``'s block/instruction removal is driven
    by DCE (which ``IPROP_PERSIST`` suppresses) or by CFG-reachability
    collapse (which it does not).  Returns the number of instructions
    flagged.
    """
    qty = int(getattr(mba, "qty", 0) or 0)
    flagged = 0
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insn = blk.head
        while insn is not None:
            try:
                insn.set_persistent()
                flagged += 1
            except Exception:
                pass
            insn = insn.next
    logger.info(
        "MARK_PERSISTENT_ALL blocks=%d flagged=%d",
        qty,
        flagged,
    )
    return flagged


def canonicalize_inline_add_in_mba(mba: "ida_hexrays.mba_t") -> int:
    """Apply :func:`canonicalize_inline_add_to_stkvar` to every block.

    Designed as a final post-pass on the live mba (e.g. at the end of
    D810's MMAT_GLBOPT1 work, just before IDA enters
    ``optimize_global``) so that inline ``mop_d(add(X, K))`` operands
    introduced by *any* emission path -- snapshot materialisation,
    ``copy_block`` cloning, or compose-into-existing-block flows -- are
    unified onto the stkvar alias whenever the matching
    ``m_add X, K -> stkvar`` def lives in the same block.

    Returns the total number of operand rewrites performed across all
    blocks; logs a per-block summary at INFO when any block rewrites
    at least one operand.
    """
    qty = int(getattr(mba, "qty", 0) or 0)
    total = 0
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insns: list = []
        insn = blk.head
        while insn is not None:
            insns.append(insn)
            insn = insn.next
        if not insns:
            continue
        rewrites = canonicalize_inline_add_to_stkvar(insns)
        if rewrites > 0:
            total += rewrites
            logger.info(
                "CANONICALIZE_LIVE_MBA blk[%d] rewrites=%d ninsns=%d",
                serial,
                rewrites,
                len(insns),
            )
    if total > 0:
        logger.info("CANONICALIZE_LIVE_MBA total rewrites=%d", total)
    return total


__all__ = [
    "canonicalize_inline_add_in_mba",
    "canonicalize_inline_add_to_stkvar",
    "instruction_snapshot_safe_ea",
    "mark_all_insns_persistent",
    "materialize_insn_snapshots",
    "validate_insn_snapshots",
]
