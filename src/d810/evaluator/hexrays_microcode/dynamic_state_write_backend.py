"""Live microcode recognizers for dynamic dispatcher state writes."""

from __future__ import annotations

import operator
from dataclasses import dataclass
from d810.core import logging
from d810.core.typing import Iterable

import ida_hexrays

logger = logging.getLogger(
    "D810.evaluator.hexrays_microcode.dynamic_state_write_backend", logging.INFO
)


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
    "resolve_state_write_value_set",
]


# ---------------------------------------------------------------------------
# General MBA-folded state-write recognizer
#
# OLLVM computes many next-states as opaque-but-constant MBA over *locally
# assigned* constants, e.g.::
#
#     var_780 = 0xDC240D83
#     var_778 = 0x71D1654B
#     var_770 = 0x77535232
#     var_64  = (var_770 ^ var_778) - var_780     ; == 0x2A5E29F6, a real state
#
# The BST walker only proves bare ``mov #const`` writes, so these handlers look
# self-looping / edgeless. A *local forward constant propagation* over the block,
# folding the state-write RHS through the portable KnownBits value domain,
# recovers the concrete next-state without symbolic execution.
# ---------------------------------------------------------------------------

from d810.analyses.abstract_domains.operations import BinaryOp, UnaryOp  # noqa: E402
from d810.analyses.abstract_domains.value_domain import (  # noqa: E402
    KnownBitsValueDomain,
)
from d810.analyses.data_flow.abstract_value import (  # noqa: E402
    TOP,
    AbstractValue,
    Const,
    Top,
    fold_correlated_binop,
    value_set_from_reaching_def_consts,
)

_FOLD_WIDTH = 64  # evaluate in 64-bit, mask the state to 32-bit at the end


def _binary_op_map() -> dict:
    return {
        ida_hexrays.m_add: BinaryOp.ADD,
        ida_hexrays.m_sub: BinaryOp.SUB,
        ida_hexrays.m_mul: BinaryOp.MUL,
        ida_hexrays.m_and: BinaryOp.AND,
        ida_hexrays.m_or: BinaryOp.OR,
        ida_hexrays.m_xor: BinaryOp.XOR,
        ida_hexrays.m_shl: BinaryOp.SHL,
        ida_hexrays.m_shr: BinaryOp.SHR_U,
        ida_hexrays.m_sar: BinaryOp.SHR_S,
    }


def _unary_op_map() -> dict:
    return {
        ida_hexrays.m_bnot: UnaryOp.NOT,
        ida_hexrays.m_neg: UnaryOp.NEG,
    }


def _passthrough_opcodes() -> frozenset:
    # value-preserving for constant folding (extend/move/truncate-low)
    return frozenset(
        {
            ida_hexrays.m_mov,
            ida_hexrays.m_xdu,
            ida_hexrays.m_xds,
            ida_hexrays.m_low,
        }
    )


def _dest_key(mop):
    if mop is None:
        return None
    t = getattr(mop, "t", None)
    if t == ida_hexrays.mop_S:
        return ("S", _mop_stkoff(mop))
    if t == ida_hexrays.mop_l:
        return ("l", _mop_lvar_idx(mop))
    if t == ida_hexrays.mop_r:
        return ("r", getattr(mop, "r", None))
    return None


def _eval_mop(mop, env: dict, vd: KnownBitsValueDomain, xresolve=None, use_block=None):
    c = _mop_const_value(mop)
    if c is not None:
        return vd.const(int(c) & ((1 << _FOLD_WIDTH) - 1), _FOLD_WIDTH)
    t = getattr(mop, "t", None)
    if t == ida_hexrays.mop_d:
        sub = getattr(mop, "d", None)
        if sub is not None:
            return _eval_insn(sub, env, vd, xresolve, use_block)
        return vd.top(_FOLD_WIDTH)
    key = _dest_key(mop)
    if key is not None and key in env:
        return env[key]
    # Cross-block fallback: the operand is defined outside this block. Resolve a
    # whole-function / reaching-def constant (read-only) when one is provable.
    # ``xresolve`` returns ``None`` on any ambiguity, so a miss degrades to ⊤
    # rather than inventing a value.
    if xresolve is not None:
        cv = xresolve(mop, use_block)
        if cv is not None:
            return vd.const(int(cv) & ((1 << _FOLD_WIDTH) - 1), _FOLD_WIDTH)
    return vd.top(_FOLD_WIDTH)


def _eval_insn(insn, env: dict, vd: KnownBitsValueDomain, xresolve=None, use_block=None):
    opcode = getattr(insn, "opcode", None)
    binmap = _binary_op_map()
    unmap = _unary_op_map()
    left = _eval_mop(getattr(insn, "l", None), env, vd, xresolve, use_block)
    if opcode in unmap:
        return vd.eval_unary(unmap[opcode], left, _FOLD_WIDTH)
    if opcode in _passthrough_opcodes():
        return left
    if opcode in binmap:
        right = _eval_mop(getattr(insn, "r", None), env, vd, xresolve, use_block)
        return vd.eval_binary(binmap[opcode], left, right, _FOLD_WIDTH)
    return vd.top(_FOLD_WIDTH)


# ---------------------------------------------------------------------------
# Cross-block operand resolution
# ---------------------------------------------------------------------------
# A handler may compute its next-state from operands assigned in a *predecessor*
# block (OLLVM spills the MBA constants into a shared preheader, then each
# handler reads them).  Local forward propagation leaves those operands at ⊤.
# Two read-only sources recover the missing constants:
#
#   1. SCCP (Sparse Conditional Constant Propagation) -- a whole-function const
#      map keyed by ``get_mop_key`` with CFG reachability (mop_r / mop_S).
#   2. A one-level stack DU reaching-def re-fold for ``mop_S`` operands SCCP
#      leaves overdefined (catches def blocks whose RHS folds locally but whose
#      leaves SCCP could not key, e.g. lvar / nested-mop_d leaves).
#
# Both sources only ever return a *unique provable* constant; ambiguity yields
# ``None`` so the fold degrades to ⊤ rather than inventing a state.


def _sccp_const_map(mba) -> dict:
    """Whole-function SCCP constant map keyed by ``get_mop_key`` (read-only)."""
    try:
        from d810.evaluator.hexrays_microcode.sccp import run_sccp

        raw = run_sccp(mba) or {}
    except Exception:
        return {}
    return {key: int(value) for key, value in raw.items() if value is not None}


def _resolve_stkvar_via_du(mop, mba, use_block) -> int | None:
    """One-level stack DU fallback: unique constant reaching def of *mop*.

    For a ``mop_S`` operand read in *use_block*, walk the stack DU chain to its
    reaching def block(s) and re-fold each block *locally* (no further
    cross-block) for that stack offset.  Returns the value only if every
    out-of-block reaching def folds to the same constant; ``None`` otherwise.
    Read-only.
    """
    if use_block is None:
        return None
    stkoff = _mop_stkoff(mop)
    size = getattr(mop, "size", None)
    if stkoff is None or not size:
        return None
    try:
        from d810.evaluator.hexrays_microcode.chains import (
            find_reaching_defs_for_stkvar,
        )

        defs = find_reaching_defs_for_stkvar(
            mba, int(use_block), int(stkoff), int(size)
        )
    except Exception:
        return None
    if not defs:
        return None
    seen: set[int] = set()
    for site in defs:
        def_blk = int(site.block_serial)
        if def_blk == int(use_block):
            # Same-block def is covered by the in-progress local env already.
            continue
        folded = fold_block_state_write(
            mba=mba,
            block_serial=def_blk,
            state_var_stkoff=int(stkoff),
            state_var_lvar_idx=None,
            cross_block_resolver=None,  # one level only -- no recursion
        )
        if not isinstance(folded, Const):
            return None  # an unfoldable reaching def -> not provably constant
        seen.add(int(folded.value) & 0xFFFFFFFF)
    return next(iter(seen)) if len(seen) == 1 else None


def make_cross_block_resolver(mba):
    """Build a read-only ``(mop, use_block) -> int | None`` constant resolver.

    SCCP is the primary source; a one-level ``mop_S`` DU re-fold is the
    fallback.  Returns ``None`` when no unique cross-block constant is provable.
    """
    sccp_map = _sccp_const_map(mba)
    try:
        from d810.hexrays.expr.p_ast import get_mop_key
    except Exception:
        get_mop_key = None
    mask = (1 << _FOLD_WIDTH) - 1

    debug = logger.debug_on

    def resolve(mop, use_block=None) -> int | None:
        if mop is None:
            return None
        if get_mop_key is not None and sccp_map:
            try:
                key = get_mop_key(mop)
            except Exception:
                key = None
            if key is not None and key in sccp_map:
                if debug:
                    logger.debug(
                        "cross_block: SCCP resolved %s -> 0x%X (use_block=%s)",
                        getattr(mop, "dstr", lambda: "?")(),
                        sccp_map[key] & mask,
                        use_block,
                    )
                return sccp_map[key] & mask
        if getattr(mop, "t", None) == ida_hexrays.mop_S:
            du_val = _resolve_stkvar_via_du(mop, mba, use_block)
            if du_val is not None:
                if debug:
                    logger.debug(
                        "cross_block: DU resolved %s -> 0x%X (use_block=%s)",
                        getattr(mop, "dstr", lambda: "?")(),
                        du_val & mask,
                        use_block,
                    )
                return du_val & mask
        return None

    return resolve


def fold_block_state_write(
    *,
    mba,
    block_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None = None,
    cross_block_resolver=None,
) -> AbstractValue:
    """Fold the next-state value the block writes to the state var (tier T1).

    Local forward constant-propagation: evaluate each instruction's value into a
    per-block environment (recursing into ``mop_d`` sub-instructions), then read
    the value of the *last* write to the state variable.

    Returns an :class:`AbstractValue` (the dispatcher-model-consolidation seam,
    S3): :class:`Const` (value masked to 32 bits, size 4) when the write folds
    to a single constant, else :data:`TOP` to escalate to the next resolve tier
    (no block / no state write / non-constant write all yield ``⊤``).

    When *cross_block_resolver* is supplied, operands defined outside this block
    are resolved through it (SCCP / DU reaching defs) before degrading to ⊤.
    """
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        blk = None
    if blk is None:
        return TOP
    vd = KnownBitsValueDomain()
    env: dict = {}
    result = None
    ins = getattr(blk, "head", None)
    while ins is not None:
        value = _eval_insn(ins, env, vd, cross_block_resolver, int(block_serial))
        dest = getattr(ins, "d", None)
        key = _dest_key(dest)
        if key is not None and value is not None:
            env[key] = value
        if _mop_matches_state_var(
            dest,
            mba=mba,
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
        ):
            if value is not None:
                result = value
        ins = getattr(ins, "next", None)
    if result is None:
        return TOP
    folded = vd.to_const(result)
    return TOP if folded is None else Const(folded & 0xFFFFFFFF, 4)


# ---------------------------------------------------------------------------
# T2 value-set state-write resolver
#
# Some handlers do NOT write the state var from a locally-folded MBA equation;
# they write it from a *bare source variable* that is itself written elsewhere by
# several distinct const ``mov`` sites::
#
#     blk194:  mov #0x41FB8FBB, %var_70      ; one const writer of var_70
#     blk51:   mov #0x71E22BF3, %var_70      ; another const writer
#     blk195:  mov %var_70, %var_7BC          ; state write reads the shared temp
#
# T1 (:func:`fold_block_state_write`) returns ``Top`` for such a multi-valued
# source.  T2 collects ALL reaching defs of the source variable, reads each def's
# const, and -- when every reaching def is a provable constant -- returns the
# value set as ``OneOf`` (or ``Const`` for a singleton).  ``explore()`` then fans
# the powerset out, routing each member to its own handler.  A non-const reaching
# def (or a source that is not a bare stack/lvar variable) falls back to T1.
# ---------------------------------------------------------------------------


def _state_write_source_identity(
    *,
    mba,
    block_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None,
) -> tuple[int | None, int | None] | None:
    """Return the ``(stkoff, lvar_idx)`` of the bare source of the state write.

    Scans *block_serial* for the LAST ``mov V, statevar`` whose source ``V`` is a
    bare stack/lvar variable, and returns ``V``'s identity.  Returns ``None`` when
    the block has no such write or its source is an MBA equation / constant (T1's
    job), so the caller falls back to :func:`fold_block_state_write`.
    """
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        blk = None
    if blk is None:
        return None
    source_identity: tuple[int | None, int | None] | None = None
    insn = getattr(blk, "head", None)
    while insn is not None:
        if getattr(insn, "opcode", None) == ida_hexrays.m_mov and _mop_matches_state_var(
            getattr(insn, "d", None),
            mba=mba,
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
        ):
            identity = _mop_local_identity(getattr(insn, "l", None))
            # Only a *bare* stack/lvar source qualifies; a const or mop_d
            # (MBA) source is left to T1.
            source_identity = identity
        insn = getattr(insn, "next", None)
    return source_identity


def _block_succset(mba, block_serial: int) -> tuple[int, ...]:
    """Return the physical successor serials of *block_serial* (read-only)."""
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        return ()
    if blk is None:
        return ()
    succset = getattr(blk, "succset", None)
    if succset is None:
        return ()
    out: list[int] = []
    try:
        for s in succset:
            out.append(int(s))
    except Exception:
        return ()
    return tuple(out)


def _find_corridor_state_write_block(
    *,
    mba,
    handler_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None,
    corridor_stop_serial: int | None,
    max_depth: int = 6,
) -> tuple[int, tuple[int | None, int | None]] | None:
    """Find the block in the handler's forward corridor that stages the state.

    OLLVM frequently writes a handler's *real* next-state from a shared temp in a
    dispatcher *staging* block reached one or more hops downstream of the handler
    entry (the handler's own block may ``mov #const`` a placeholder first).  This
    walk follows physical successors forward from *handler_serial*, skipping the
    dispatcher entry (*corridor_stop_serial*) and respecting *max_depth* /
    visited-set bounds, and returns the first block whose state-var write reads a
    *bare* stack/lvar source (the shared temp), together with that source's
    identity.  Returns ``None`` when no such staging write exists in range
    (the caller then resolves the handler block itself).
    """
    visited: set[int] = set()
    frontier: list[tuple[int, int]] = [(int(handler_serial), 0)]
    while frontier:
        serial, depth = frontier.pop(0)
        if serial in visited or depth > max_depth:
            continue
        visited.add(serial)
        if corridor_stop_serial is not None and serial == int(corridor_stop_serial):
            continue
        identity = _state_write_source_identity(
            mba=mba,
            block_serial=serial,
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
        )
        # A bare *stack* source in a DOWNSTREAM block (not the handler entry) is a
        # staging write -> resolve its value set there.
        if serial != int(handler_serial) and identity is not None and identity[0] is not None:
            return serial, identity
        for succ in _block_succset(mba, serial):
            if succ not in visited:
                frontier.append((succ, depth + 1))
    return None


def _read_const_writer(
    *,
    mba,
    block_serial: int,
    stkoff: int | None,
    lvar_idx: int | None,
) -> int | None:
    """Return the const of the LAST ``mov #const, V`` in *block_serial*, or ``None``.

    ``V`` is the variable identified by *stkoff* / *lvar_idx*.  ``None`` when the
    block has no constant ``mov`` into ``V`` (a non-const def -> the value set is
    not fully known).
    """
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        blk = None
    if blk is None:
        return None
    value: int | None = None
    insn = getattr(blk, "head", None)
    while insn is not None:
        if getattr(insn, "opcode", None) == ida_hexrays.m_mov and _mop_matches_identity(
            getattr(insn, "d", None),
            stkoff=stkoff,
            lvar_idx=lvar_idx,
        ):
            c = _mop_const_value(getattr(insn, "l", None))
            value = c  # last writer wins; None when this def is non-const
        insn = getattr(insn, "next", None)
    return value


def _default_reaching_def_blocks(mba, *, block_serial: int, stkoff: int, size: int):
    """Default reaching-def provider: block serials defining ``stkoff`` (DU chains)."""
    from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar

    defs = find_reaching_defs_for_stkvar(mba, int(block_serial), int(stkoff), int(size))
    seen: list[int] = []
    for site in defs:
        b = int(site.block_serial)
        if b not in seen:
            seen.append(b)
    return seen


def _py_binop_map() -> dict:
    """opcode -> pure 2-arg constant evaluator (for the correlated-binop fold)."""
    return {
        ida_hexrays.m_xor: operator.xor,
        ida_hexrays.m_add: operator.add,
        ida_hexrays.m_sub: operator.sub,
        ida_hexrays.m_mul: operator.mul,
        ida_hexrays.m_and: operator.and_,
        ida_hexrays.m_or: operator.or_,
    }


def _bare_stk_operand(mop) -> tuple[int, int] | None:
    """``(stkoff, size)`` of *mop* iff it is a bare ``mop_S`` stack var, else ``None``."""
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_S:
        return None
    stkoff = _mop_stkoff(mop)
    size = getattr(mop, "size", None)
    if stkoff is None or not size:
        return None
    return int(stkoff), int(size)


def _state_write_binop_operands(
    *, mba, block_serial: int, state_var_stkoff: int, state_var_lvar_idx: int | None
):
    """Find the LAST ``op(A, B) -> statevar`` write where ``A``/``B`` are bare
    stack vars and ``op`` is a foldable binary op.

    Returns ``(opcode, (a_stkoff, a_size), (b_stkoff, b_size))`` or ``None`` (no
    such write -- the source is a const / bare var / unsupported op).
    """
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        blk = None
    if blk is None:
        return None
    binmap = _py_binop_map()
    found = None
    insn = getattr(blk, "head", None)
    while insn is not None:
        opcode = getattr(insn, "opcode", None)
        if opcode in binmap and _mop_matches_state_var(
            getattr(insn, "d", None),
            mba=mba,
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
        ):
            left = _bare_stk_operand(getattr(insn, "l", None))
            right = _bare_stk_operand(getattr(insn, "r", None))
            if left is not None and right is not None:
                found = (opcode, left, right)  # last writer wins
        insn = getattr(insn, "next", None)
    return found


def _resolve_correlated_binop_state_write(
    *,
    mba,
    block_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None,
    size: int = 4,
    reaching_def_blocks_provider=None,
) -> AbstractValue:
    """Resolve a state write ``op(varA, varB)`` as a correlated value set (T2b).

    OLLVM opaque-constant *split*: the state var is written as a binary op of two
    bare stack vars that are each ``mov #const`` in the SAME shared predecessor
    blocks (e.g. ``var_7BC = var_D0 ^ var_C8``).  T1's cross-block resolver
    collapses to ``⊤`` because each operand has several reaching consts; this
    pairs the operands *per def-block* and folds the op, recovering the real
    states (no spurious cross product).  Returns :data:`TOP` unless both operands
    are defined in the exact same provable-const block set.
    """
    binop = _state_write_binop_operands(
        mba=mba,
        block_serial=int(block_serial),
        state_var_stkoff=int(state_var_stkoff),
        state_var_lvar_idx=state_var_lvar_idx,
    )
    if binop is None:
        return TOP
    opcode, (a_stk, a_sz), (b_stk, b_sz) = binop
    op = _py_binop_map().get(opcode)
    if op is None:
        return TOP
    provider = reaching_def_blocks_provider or _default_reaching_def_blocks

    def consts_by_def_block(stk: int, sz: int) -> dict:
        blocks = provider(
            mba, block_serial=int(block_serial), stkoff=int(stk), size=int(sz)
        )
        return {
            int(b): _read_const_writer(
                mba=mba, block_serial=int(b), stkoff=int(stk), lvar_idx=None
            )
            for b in blocks
        }

    return fold_correlated_binop(
        consts_by_def_block(a_stk, a_sz), consts_by_def_block(b_stk, b_sz), op
    )


def resolve_state_write_value_set(
    *,
    mba,
    block_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None = None,
    size: int = 4,
    cross_block_resolver=None,
    corridor_stop_serial: int | None = None,
    reaching_def_blocks_provider=None,
    const_writer_reader=None,
) -> AbstractValue:
    """Resolve a handler's next-state write as a value set (tier T2).

    When the state write reads a *bare source variable* with several distinct
    const reaching defs (e.g. a shared OLLVM temp written ``#A`` in one block and
    ``#B`` in another), T1's local const-fold returns ``⊤`` because the source is
    multi-valued.  T2 recovers the powerset:

    1. Locate the state-var write that reads a bare source ``V``: first the
       handler block, else (when the handler only ``mov #const`` a placeholder)
       the dispatcher *staging* block one or more hops downstream in the handler's
       forward corridor (bounded; stops at *corridor_stop_serial*, the dispatcher
       entry).
    2. DU-collect ALL reaching-def blocks of ``V`` (injectable provider) and read
       each block's const ``mov #const, V`` writer (injectable reader).
    3. Project via :func:`value_set_from_reaching_def_consts`:
       every def const -> :class:`OneOf` (or :class:`Const` for a singleton);
       any non-const def / no defs / non-bare source -> fall back to T1
       :func:`fold_block_state_write` (``Const | Top``).

    The two provider hooks default to the live DU-chain / block-scan readers but
    are injectable so the resolver is unit-testable without IDA.  Each serialized
    block carries its EA at the call sites (standing rule); this resolver returns
    only values, not edges.
    """
    write_block = int(block_serial)
    source_identity = _state_write_source_identity(
        mba=mba,
        block_serial=write_block,
        state_var_stkoff=int(state_var_stkoff),
        state_var_lvar_idx=state_var_lvar_idx,
    )
    src_stkoff = source_identity[0] if source_identity is not None else None
    src_lvar_idx = source_identity[1] if source_identity is not None else None

    # The handler block itself does not read a bare stack source -> the real
    # next-state may be staged downstream from a shared temp. Follow the corridor.
    if src_stkoff is None:
        staged = _find_corridor_state_write_block(
            mba=mba,
            handler_serial=int(block_serial),
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
            corridor_stop_serial=corridor_stop_serial,
        )
        if staged is not None:
            write_block, (src_stkoff, src_lvar_idx) = staged

    # Only a bare *stack* source is value-set resolvable via the DU reaching-def
    # provider. A non-bare source may still be an opaque-constant SPLIT
    # ``op(varA, varB)`` (T2b: var ^ var folded per correlated def-block) -- try
    # that before degrading to the T1 local fold (const / lvar / true-MBA source).
    if src_stkoff is None:
        binop_value_set = _resolve_correlated_binop_state_write(
            mba=mba,
            block_serial=int(block_serial),
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
            size=int(size),
            reaching_def_blocks_provider=reaching_def_blocks_provider,
        )
        if not isinstance(binop_value_set, Top):
            return binop_value_set
        return fold_block_state_write(
            mba=mba,
            block_serial=int(block_serial),
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
            cross_block_resolver=cross_block_resolver,
        )

    provider = reaching_def_blocks_provider or _default_reaching_def_blocks
    reader = const_writer_reader or (
        lambda def_block: _read_const_writer(
            mba=mba,
            block_serial=int(def_block),
            stkoff=src_stkoff,
            lvar_idx=src_lvar_idx,
        )
    )

    def_blocks = provider(
        mba, block_serial=int(write_block), stkoff=int(src_stkoff), size=int(size)
    )
    consts = [reader(int(def_block)) for def_block in def_blocks]
    value_set = value_set_from_reaching_def_consts(consts)
    # A value set was proven (Const or OneOf) -> use it. Otherwise (Top: a
    # non-const reaching def, no defs, etc.) fall back to the T1 local fold.
    if isinstance(value_set, Top):
        return fold_block_state_write(
            mba=mba,
            block_serial=int(block_serial),
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
            cross_block_resolver=cross_block_resolver,
        )
    return value_set


def recognize_constant_folded_state_write(
    *,
    mba,
    handler_serial: int,
    state_var_stkoff: int,
    state_var_lvar_idx: int | None = None,
    known_states: Iterable[int] = (),
    cross_block_resolver=None,
) -> DynamicStateWriteEvidence | None:
    """Recover a next-state from an MBA-over-constants state write by folding it.

    Returns evidence iff the fold yields a *known* dispatcher state (so we never
    invent a target that is not in the routing map).  *cross_block_resolver*, if
    supplied, lets the fold resolve operands defined in predecessor blocks
    (SCCP / DU reaching defs).
    """
    known = {int(v) & 0xFFFFFFFF for v in known_states}
    if not known:
        return None
    folded_value = fold_block_state_write(
        mba=mba,
        block_serial=int(handler_serial),
        state_var_stkoff=int(state_var_stkoff),
        state_var_lvar_idx=state_var_lvar_idx,
        cross_block_resolver=cross_block_resolver,
    )
    # S3: fold_block_state_write now returns an AbstractValue. Unwrap Const ->
    # int so this recognizer's external behaviour is byte-identical to the old
    # ``int | None`` contract (Top / non-Const escalates -> no evidence here).
    if not isinstance(folded_value, Const):
        return None
    folded = int(folded_value.value) & 0xFFFFFFFF
    if folded not in known:
        return None
    return DynamicStateWriteEvidence(
        handler_serial=int(handler_serial),
        global_ea=0,
        target_state=int(folded),
        or_insn_ea=None,
        state_write_ea=None,
        state_write_block=int(handler_serial),
        provenance="constant_folded_state_write",
    )
