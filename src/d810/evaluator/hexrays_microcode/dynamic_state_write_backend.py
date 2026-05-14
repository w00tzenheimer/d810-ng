"""Live microcode recognizers for dynamic dispatcher state writes."""

from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import Iterable

import ida_hexrays


@dataclass(frozen=True)
class DynamicStateWriteEvidence:
    """Evidence for a guarded transition recovered from a global state carrier."""

    handler_serial: int
    global_ea: int
    target_state: int
    or_insn_ea: int | None
    state_write_ea: int | None
    state_write_block: int
    provenance: str = "global_or_state_write"


def _mop_const_value(mop) -> int | None:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_n:
        return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None)
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _mop_global_ea(mop) -> int | None:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_v:
        return None
    value = getattr(mop, "g", None)
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _mop_matches_state_var(
    mop,
    *,
    mba,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None = None,
) -> bool:
    if mop is None:
        return False
    mop_type = getattr(mop, "t", None)

    if mop_type == ida_hexrays.mop_S:
        s = getattr(mop, "s", None)
        off = getattr(s, "off", None) if s is not None else None
        return off is not None and int(off) == int(state_var_stkoff)

    if mop_type == ida_hexrays.mop_l:
        lref = getattr(mop, "l", None)
        idx = getattr(lref, "idx", None) if lref is not None else None
        if idx is None:
            return False
        if state_var_lvar_idx is not None:
            return int(idx) == int(state_var_lvar_idx)
        try:
            lvar = mba.vars[idx]
            return int(lvar.location.stkoff()) == int(state_var_stkoff)
        except Exception:
            return False

    return False


def recognize_global_or_state_write_transition(
    *,
    mba,
    handler_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None = None,
    known_states: Iterable[int] = (),
) -> DynamicStateWriteEvidence | None:
    """Recognize ``global |= CONST; state = global`` in one handler block.

    This is intentionally narrow.  It only accepts an OR into a global
    ``mop_v`` where the OR constant is already a known dispatcher state, then
    a later assignment from that same global into the dispatcher state
    variable.  The recognizer does not prove the global's pre-OR value, so the
    caller must treat the recovered transition as guarded/advisory evidence.
    """

    known_state_set = {int(value) & 0xFFFFFFFF for value in known_states}
    if not known_state_set:
        return None

    try:
        blk = mba.get_mblock(int(handler_serial))
    except Exception:
        return None
    if blk is None:
        return None

    pending_global_ea: int | None = None
    pending_target_state: int | None = None
    pending_or_ea: int | None = None

    insn = getattr(blk, "head", None)
    while insn is not None:
        opcode = getattr(insn, "opcode", None)
        if opcode == ida_hexrays.m_or:
            left_global = _mop_global_ea(getattr(insn, "l", None))
            dest_global = _mop_global_ea(getattr(insn, "d", None))
            const_value = _mop_const_value(getattr(insn, "r", None))
            if (
                left_global is not None
                and dest_global is not None
                and left_global == dest_global
                and const_value is not None
                and (const_value & 0xFFFFFFFF) in known_state_set
            ):
                pending_global_ea = left_global
                pending_target_state = const_value & 0xFFFFFFFF
                pending_or_ea = int(getattr(insn, "ea", 0) or 0) or None

        elif (
            opcode == ida_hexrays.m_mov
            and pending_global_ea is not None
            and pending_target_state is not None
        ):
            src_global = _mop_global_ea(getattr(insn, "l", None))
            if (
                src_global == pending_global_ea
                and _mop_matches_state_var(
                    getattr(insn, "d", None),
                    mba=mba,
                    state_var_stkoff=state_var_stkoff,
                    state_var_lvar_idx=state_var_lvar_idx,
                )
            ):
                state_write_ea = int(getattr(insn, "ea", 0) or 0) or None
                return DynamicStateWriteEvidence(
                    handler_serial=int(handler_serial),
                    global_ea=int(pending_global_ea),
                    target_state=int(pending_target_state),
                    or_insn_ea=pending_or_ea,
                    state_write_ea=state_write_ea,
                    state_write_block=int(handler_serial),
                )

        insn = getattr(insn, "next", None)

    return None


__all__ = [
    "DynamicStateWriteEvidence",
    "recognize_global_or_state_write_transition",
]
