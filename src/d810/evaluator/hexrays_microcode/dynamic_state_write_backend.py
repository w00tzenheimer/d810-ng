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


@dataclass(frozen=True)
class DerivedXorDispatcherModel:
    """Dispatcher key computed from a low byte of a XOR-mutated carrier."""

    dispatcher_entry_serial: int
    key_stkoff: int | None
    key_lvar_idx: int | None
    carrier_stkoff: int | None
    carrier_lvar_idx: int | None
    xor_key: int
    mask: int = 0xFF


@dataclass(frozen=True)
class DerivedXorTransitionEvidence:
    """Evidence for ``key = low8(carrier) ^ K`` with ``carrier ^= C``."""

    handler_serial: int
    state_write_block: int
    target_state: int
    xor_constant: int
    state_write_ea: int | None
    provenance: str = "derived_xor_dispatch_key"


def _mop_lvar_idx(mop) -> int | None:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_l:
        return None
    lref = getattr(mop, "l", None)
    idx = getattr(lref, "idx", None) if lref is not None else None
    if idx is None:
        return None
    try:
        return int(idx)
    except Exception:
        return None


def _mop_stkoff(mop) -> int | None:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_S:
        return None
    sref = getattr(mop, "s", None)
    off = getattr(sref, "off", None) if sref is not None else None
    if off is None:
        return None
    try:
        return int(off)
    except Exception:
        return None


def _mop_local_identity(mop) -> tuple[int | None, int | None] | None:
    """Return ``(stkoff, lvar_idx)`` for stack/lvar mops."""

    stkoff = _mop_stkoff(mop)
    if stkoff is not None:
        return stkoff, None
    lvar_idx = _mop_lvar_idx(mop)
    if lvar_idx is not None:
        return None, lvar_idx
    return None


def _mop_matches_identity(
    mop,
    *,
    stkoff: int | None,
    lvar_idx: int | None,
) -> bool:
    identity = _mop_local_identity(mop)
    if identity is None:
        return False
    mop_stkoff, mop_lvar_idx = identity
    if stkoff is not None:
        return mop_stkoff is not None and int(mop_stkoff) == int(stkoff)
    if lvar_idx is not None:
        return mop_lvar_idx is not None and int(mop_lvar_idx) == int(lvar_idx)
    return False


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


def _xdu_source_mop(mop):
    """Return the source of an ``xdu`` expression mop, if present."""

    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
        return None
    sub = getattr(mop, "d", None)
    if sub is None or getattr(sub, "opcode", None) != ida_hexrays.m_xdu:
        return None
    return getattr(sub, "l", None)


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


def recognize_derived_xor_dispatcher_model(
    *,
    mba,
    dispatcher_entry_serial: int,
) -> DerivedXorDispatcherModel | None:
    """Recognize ``dispatch_key = xdu(low8(carrier)) ^ CONST``.

    This intentionally models the narrow ABC XOR dispatcher shape where the
    dispatcher compares a derived key, while handlers mutate a separate state
    carrier.  The handler state labels are the derived key values, not the raw
    carrier values.
    """

    try:
        blk = mba.get_mblock(int(dispatcher_entry_serial))
    except Exception:
        return None
    if blk is None:
        return None

    insn = getattr(blk, "head", None)
    while insn is not None:
        if getattr(insn, "opcode", None) != ida_hexrays.m_xor:
            insn = getattr(insn, "next", None)
            continue

        xor_key = _mop_const_value(getattr(insn, "r", None))
        key_identity = _mop_local_identity(getattr(insn, "d", None))
        carrier_mop = _xdu_source_mop(getattr(insn, "l", None))
        carrier_identity = _mop_local_identity(carrier_mop)
        if (
            xor_key is not None
            and 0 <= int(xor_key) <= 0xFF
            and key_identity is not None
            and carrier_identity is not None
        ):
            key_stkoff, key_lvar_idx = key_identity
            carrier_stkoff, carrier_lvar_idx = carrier_identity
            return DerivedXorDispatcherModel(
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                key_stkoff=key_stkoff,
                key_lvar_idx=key_lvar_idx,
                carrier_stkoff=carrier_stkoff,
                carrier_lvar_idx=carrier_lvar_idx,
                xor_key=int(xor_key) & 0xFF,
            )

        insn = getattr(insn, "next", None)

    return None


def recognize_derived_xor_dispatcher_models(*, mba) -> tuple[DerivedXorDispatcherModel, ...]:
    """Return all derived-XOR dispatcher key models visible in an MBA."""

    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except Exception:
        return ()

    models: list[DerivedXorDispatcherModel] = []
    seen: set[tuple[int | None, int | None, int | None, int | None, int]] = set()
    for serial in range(qty):
        model = recognize_derived_xor_dispatcher_model(
            mba=mba,
            dispatcher_entry_serial=serial,
        )
        if model is None:
            continue
        key = (
            model.key_stkoff,
            model.key_lvar_idx,
            model.carrier_stkoff,
            model.carrier_lvar_idx,
            int(model.xor_key),
        )
        if key in seen:
            continue
        seen.add(key)
        models.append(model)
    return tuple(models)


def mop_matches_derived_xor_key(mop, model: DerivedXorDispatcherModel) -> bool:
    """Return whether ``mop`` references the derived dispatcher key variable."""

    return _mop_matches_identity(
        mop,
        stkoff=model.key_stkoff,
        lvar_idx=model.key_lvar_idx,
    )


def recognize_carrier_xor_transition(
    *,
    mba,
    block_serial: int,
    from_state: int,
    model: DerivedXorDispatcherModel,
    known_states: Iterable[int] = (),
) -> DerivedXorTransitionEvidence | None:
    """Recognize ``carrier ^= CONST`` and map it to a derived key transition."""

    known_state_set = {int(value) & model.mask for value in known_states}
    if not known_state_set:
        return None

    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        return None
    if blk is None:
        return None

    insn = getattr(blk, "head", None)
    while insn is not None:
        if getattr(insn, "opcode", None) == ida_hexrays.m_xor:
            const_value = _mop_const_value(getattr(insn, "r", None))
            if (
                const_value is not None
                and _mop_matches_identity(
                    getattr(insn, "l", None),
                    stkoff=model.carrier_stkoff,
                    lvar_idx=model.carrier_lvar_idx,
                )
                and _mop_matches_identity(
                    getattr(insn, "d", None),
                    stkoff=model.carrier_stkoff,
                    lvar_idx=model.carrier_lvar_idx,
                )
            ):
                target_state = (int(from_state) ^ (int(const_value) & model.mask)) & model.mask
                if target_state not in known_state_set:
                    return None
                return DerivedXorTransitionEvidence(
                    handler_serial=int(block_serial),
                    state_write_block=int(block_serial),
                    target_state=int(target_state),
                    xor_constant=int(const_value) & 0xFFFFFFFF,
                    state_write_ea=int(getattr(insn, "ea", 0) or 0) or None,
                )
        insn = getattr(insn, "next", None)

    return None


def derive_initial_xor_dispatch_state(
    *,
    mba,
    pre_header_serial: int | None,
    model: DerivedXorDispatcherModel,
) -> int | None:
    """Return the initial derived key from a carrier constant write."""

    if pre_header_serial is None:
        return None
    try:
        blk = mba.get_mblock(int(pre_header_serial))
    except Exception:
        return None
    if blk is None:
        return None

    insn = getattr(blk, "head", None)
    while insn is not None:
        if (
            getattr(insn, "opcode", None) == ida_hexrays.m_mov
            and _mop_matches_identity(
                getattr(insn, "d", None),
                stkoff=model.carrier_stkoff,
                lvar_idx=model.carrier_lvar_idx,
            )
        ):
            value = _mop_const_value(getattr(insn, "l", None))
            if value is not None:
                return ((int(value) & model.mask) ^ model.xor_key) & model.mask
        insn = getattr(insn, "next", None)

    return None


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
    "DerivedXorDispatcherModel",
    "DerivedXorTransitionEvidence",
    "DynamicStateWriteEvidence",
    "derive_initial_xor_dispatch_state",
    "mop_matches_derived_xor_key",
    "recognize_carrier_xor_transition",
    "recognize_derived_xor_dispatcher_model",
    "recognize_derived_xor_dispatcher_models",
    "recognize_global_or_state_write_transition",
]
