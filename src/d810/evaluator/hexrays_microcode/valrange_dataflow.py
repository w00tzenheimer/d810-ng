"""Forward dataflow domain for value-range analysis.

Reconstructs the per-block ``valranges_t::known`` map that the Hex-Rays
decompiler computes internally.  Each map entry associates a microcode
operand location (register or stack variable) with the set of values it
can hold at that program point.

Domain values are IDA's native ``valrng_t`` objects, which support
intervals, strided ranges, known-bit masks, and set unions/intersections.

**Meet semantics**: union (``valrng_t.unite_with``) -- at a merge point
the variable can hold any value that *any* predecessor allows.

**Transfer**: walk the block's instruction list applying GEN/KILL.
Assignments of constants GEN a singleton range.  Assignments from unknown
sources KILL (set to all-values).

**Edge refinement**: for BLT_2WAY predecessors whose tail is a conditional
jump comparing an operand against an immediate, the outgoing state toward
each successor is refined:

* taken edge  -- intersect with the constraint implied by the condition
* fall-through edge -- intersect with the *inverse* of that constraint

This matches the internal ``sub_180130CC0`` logic discovered by reverse-
engineering ``hexx64.dll``.

Usage::

    result = run_valrange_fixpoint(mba)
    # result.in_states[serial] is the ValrangeEnv at block entry
    # Compare with IDA's native get_valranges() for validation.
"""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays
import idaapi

from d810.cfg.lattice import BOTTOM, TOP, LatticeMeet
from d810.core.logging import getLogger
from d810.core.typing import Any, Optional
from d810.evaluator.hexrays_microcode.forward_dataflow import FixpointResult

logger = getLogger(__name__)

# ---------------------------------------------------------------------------
# Key type -- identifies a microcode operand location
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValrangeKey:
    """Identity of a value-range location (mirrors ``valrange_key_t``).

    Attributes:
        mop_type: ``mop_r`` (register) or ``mop_S`` (stack variable).
        identifier: mreg number for registers, stack offset for stack vars.
        size: Operand width in bytes.
    """

    mop_type: int  # ida_hexrays.mop_r or mop_S
    identifier: int
    size: int


# ---------------------------------------------------------------------------
# Environment type
# ---------------------------------------------------------------------------

# Maps operand locations to their value ranges.
# Missing key = no constraint (all values possible).
# Empty valrng_t = unreachable / bottom.
ValrangeEnv = dict[ValrangeKey, ida_hexrays.valrng_t]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clone_valrng(vr: ida_hexrays.valrng_t) -> ida_hexrays.valrng_t:
    """Deep-copy a valrng_t via the IDA copy constructor."""
    return ida_hexrays.valrng_t(vr)


def _clone_env(env: ValrangeEnv) -> ValrangeEnv:
    """Deep-copy an entire environment."""
    return {k: _clone_valrng(v) for k, v in env.items()}


def _vr_to_str(vr) -> str:
    """Canonical string representation for equality comparison.

    SWIG-wrapped ``valrng_t`` objects don't support value-based ``__eq__``,
    so we compare via their printed form.
    """
    try:
        return vr.dstr()
    except Exception:
        return repr(vr)


def _envs_equal(a: ValrangeEnv, b: ValrangeEnv) -> bool:
    """Value-based equality for two ValrangeEnv dicts.

    Uses ``valrng_t.dstr()`` because SWIG objects default to identity
    comparison, which would prevent the fixpoint from ever converging.
    """
    if a.keys() != b.keys():
        return False
    return all(_vr_to_str(a[k]) == _vr_to_str(b[k]) for k in a)


def _make_all_values(size: int) -> object:
    """Create a valrng_t representing all values for *size* bytes."""
    vr = ida_hexrays.valrng_t(size)
    vr.set_all()
    return vr


def _resolve_singleton(mop, env: ValrangeEnv) -> Optional[int]:
    """Return the singleton constant value for *mop*, or None.

    Handles three cases:
    - ``mop_n`` (immediate): return the literal value.
    - ``mop_r`` or ``mop_S`` with a singleton in *env*: extract via
      ``valrng_t.cvt_to_single_value()``.
    - Otherwise: return None.
    """
    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value
    key = _extract_key_from_mop(mop)
    if key is not None and key in env:
        vr = env[key]
        if vr is TOP or vr is BOTTOM:
            return None
        ok, val = vr.cvt_to_single_value()
        if ok:
            return int(val)
    return None


def _extract_key_from_mop(mop) -> Optional[ValrangeKey]:
    """Extract a ValrangeKey from a microcode operand, or None."""
    if mop is None:
        return None
    t = mop.t
    if t == ida_hexrays.mop_r:
        return ValrangeKey(mop_type=t, identifier=int(mop.r), size=int(mop.size))
    if t == ida_hexrays.mop_S:
        try:
            stkoff = mop.s.off
        except Exception:
            stkoff = getattr(mop, "stkoff", None)
            if stkoff is None:
                return None
        return ValrangeKey(mop_type=t, identifier=int(stkoff), size=int(mop.size))
    return None


def _key_to_mlist(key: ValrangeKey) -> ida_hexrays.mlist_t:
    """Convert a ValrangeKey to an mlist_t for def-list intersection checks."""
    ml = ida_hexrays.mlist_t()
    if key.mop_type == ida_hexrays.mop_r:
        ml.reg.add(key.identifier, key.size)
    elif key.mop_type == ida_hexrays.mop_S:
        ml.addmem(key.identifier, key.size)
    return ml


def _lookup_range(mop, env: ValrangeEnv) -> Optional[ida_hexrays.valrng_t]:
    """Look up the valrng_t for an operand in the environment, or None."""
    key = _extract_key_from_mop(mop)
    if key is not None and key in env:
        vr = env[key]
        if vr is not TOP and vr is not BOTTOM:
            return vr
    return None


# ---------------------------------------------------------------------------
# Jcc opcode → cmpop_t mapping
# ---------------------------------------------------------------------------

# m_jnz = 0x2B is the first conditional jump; cmpop_t starts at CMP_NZ = 0.
# The enum order is identical: jnz, jz, jae, jb, ja, jbe, jg, jge, jl, jle.
_JCC_FIRST = idaapi.m_jnz  # m_jnz
_JCC_LAST = idaapi.m_jle  # m_jle


def _jcc_to_cmpop(opcode: int) -> Optional[int]:
    """Convert a conditional-jump opcode to a cmpop_t value, or None."""
    if _JCC_FIRST <= opcode <= _JCC_LAST:
        return opcode - _JCC_FIRST
    return None


def _negate_cmpop(cmp: int) -> int:
    """Return the negated comparison operator.

    CMP_NZ ↔ CMP_Z, CMP_AE ↔ CMP_B, CMP_A ↔ CMP_BE,
    CMP_GT ↔ CMP_LE, CMP_GE ↔ CMP_LT.
    """
    _NEGATE = {0: 1, 1: 0, 2: 3, 3: 2, 4: 5, 5: 4, 6: 9, 7: 8, 8: 7, 9: 6}
    return _NEGATE.get(cmp, cmp)


# ---------------------------------------------------------------------------
# Per-value meet (union semantics) and meet strategy
# ---------------------------------------------------------------------------

# Sentinel representing "no constraint" (all values possible).
# Used as default_missing in the meet: if a predecessor doesn't mention a
# key, the variable is unconstrained along that path.
_ALL_VALUES = TOP


def _valrange_value_meet(a: Any, b: Any) -> Any:
    """Meet two value-range lattice elements via union.

    Lattice orientation (union-meet):
        BOTTOM (empty/unreachable) is identity for union.
        TOP (all-values/unconstrained) is absorbing for union.
        Concrete valrng_t values are united.
    """
    if a is BOTTOM:
        return _clone_valrng(b) if b is not BOTTOM and b is not TOP else b
    if b is BOTTOM:
        return _clone_valrng(a) if a is not TOP else a
    if a is TOP or b is TOP:
        return TOP

    merged = _clone_valrng(a)
    merged.unite_with(b)
    if merged.all_values():
        return TOP
    return merged


#: Reusable meet strategy for the value-range domain.
#: ``default_missing=TOP`` means a key absent from any predecessor is treated
#: as unconstrained (all values), which is absorbing under union — the key
#: gets widened to TOP and effectively dropped.
_valrange_meet_strategy = LatticeMeet(
    value_meet=_valrange_value_meet,
    default_missing=_ALL_VALUES,
)


def valrange_meet(pred_outs: list[ValrangeEnv]) -> ValrangeEnv:
    """Merge predecessor output states via union of ranges.

    Delegates to :class:`~d810.cfg.lattice.LatticeMeet` with union semantics.
    Entries that widen to TOP (all values) are pruned from the result since
    they carry no useful constraint.
    """
    raw = _valrange_meet_strategy.meet(pred_outs)
    # Prune TOP entries — missing key already means "all values".
    return {k: v for k, v in raw.items() if v is not TOP and v is not BOTTOM}


# ---------------------------------------------------------------------------
# Edge-sensitive transfer: branch condition refinement
# ---------------------------------------------------------------------------


def _refine_for_branch_edge(
    pred_blk,
    successor_serial: int,
    env: ValrangeEnv,
) -> ValrangeEnv:
    """Refine *env* based on a BLT_2WAY predecessor's branch condition.

    For ``jcc operand, #imm, target_block``:
    - If *successor_serial* is the jump target: intersect with the condition.
    - If *successor_serial* is the fall-through: intersect with the inverse.

    Returns a new (possibly refined) environment.
    """

    if pred_blk.type != ida_hexrays.BLT_2WAY:
        return env

    tail = pred_blk.tail
    if tail is None:
        return env

    cmpop = _jcc_to_cmpop(tail.opcode)
    if cmpop is None:
        return env

    # We need: jcc  <left_operand>, <right_immediate>, <target_block>
    # The left operand identifies the variable; the right must be an immediate.
    left = tail.l
    right = tail.r

    if right is None or right.t != ida_hexrays.mop_n:
        return env

    key = _extract_key_from_mop(left)
    if key is None:
        return env

    imm_value = right.nnn.value
    op_size = left.size

    # Build the constraint range from the comparison.
    constraint = ida_hexrays.valrng_t(op_size)
    constraint.set_cmp(cmpop, imm_value)

    # Determine if this successor is the taken or fall-through edge.
    # Normal BLT_2WAY: succset[0] = fall-through (condition FALSE),
    #                   succset[1] = jump target (condition TRUE).
    # For the constraint: taken edge gets the condition as-is, fall-through
    # gets the inverted condition.
    # Note: inverted_jx does NOT affect the succset order.  The opcode
    # semantics are what matters, and we already have the correct cmpop
    # from the opcode.  So we simply use the succset order as documented.
    succ_list = list(pred_blk.succset)
    is_fallthrough = len(succ_list) >= 1 and succ_list[0] == successor_serial
    is_taken = len(succ_list) >= 2 and succ_list[1] == successor_serial

    if not is_taken and not is_fallthrough:
        # Cannot determine edge direction; skip refinement.
        return env

    if is_fallthrough and not is_taken:
        # Fall-through: the condition is FALSE → invert the constraint.
        constraint.inverse()

    # Apply the branch constraint for this key.
    # The branch condition is the authoritative statement about possible
    # values on this edge — intersect it with whatever the predecessor's
    # OUT state already says about this key.
    env = _clone_env(env)
    if key in env:
        # Intersect the predecessor's outgoing range with the branch constraint.
        # Clone the constraint first so we don't mutate the original.
        refined = _clone_valrng(env[key])
        refined.intersect_with(constraint)
        if refined.empty():
            # The OUT state range and the branch constraint are disjoint.
            # This means the branch constraint is the only information for
            # this edge (the OUT range may be stale from a wider meet).
            env[key] = constraint
        else:
            env[key] = refined
    else:
        # No prior constraint; the branch constraint is all we have.
        if not constraint.all_values() and not constraint.empty():
            env[key] = constraint

    return env


# ---------------------------------------------------------------------------
# Transfer function
# ---------------------------------------------------------------------------


_SET_FLAG_OPCODES = frozenset({
    ida_hexrays.m_setz, ida_hexrays.m_setnz,
    ida_hexrays.m_setae, ida_hexrays.m_setb,
    ida_hexrays.m_seta, ida_hexrays.m_setbe,
    ida_hexrays.m_setg, ida_hexrays.m_setge,
    ida_hexrays.m_setl, ida_hexrays.m_setle,
    ida_hexrays.m_sets, ida_hexrays.m_seto, ida_hexrays.m_setp,
})

_ARITH_OPCODES = frozenset({
    ida_hexrays.m_add, ida_hexrays.m_sub,
    ida_hexrays.m_mul,
    ida_hexrays.m_xor, ida_hexrays.m_and, ida_hexrays.m_or,
    ida_hexrays.m_shl, ida_hexrays.m_shr, ida_hexrays.m_sar,
})


def _try_gen(ins, key: ValrangeKey, env: ValrangeEnv) -> Optional[ida_hexrays.valrng_t]:
    """Try to produce a GEN range for the instruction's destination.

    Mirrors hexx64's ``valranges_transfer_single_insn`` switch.
    Returns a valrng_t if the instruction produces a known range,
    or None to fall through to KILL.
    """
    opcode = ins.opcode
    mask = (1 << (key.size * 8)) - 1

    # --- m_mov (4): constant or variable-to-variable range copy ---
    if opcode == ida_hexrays.m_mov:
        if ins.l is not None:
            # Immediate → singleton
            if ins.l.t == ida_hexrays.mop_n:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_eq(ins.l.nnn.value)
                return vr
            # Variable → copy range from env (hexx64: valranges_lookup_key_range)
            src_vr = _lookup_range(ins.l, env)
            if src_vr is not None:
                return _clone_valrng(src_vr)
        return None

    # --- m_xdu (9): zero-extend ---
    if opcode == ida_hexrays.m_xdu:
        if ins.l is not None:
            src_size = ins.l.size
            # If source is a sub-instruction producing a set-flag result → [0, 1]
            if ins.l.t == ida_hexrays.mop_d and ins.l.d is not None:
                if ins.l.d.opcode in _SET_FLAG_OPCODES:
                    vr = ida_hexrays.valrng_t(key.size)
                    vr.set_cmp(4, 1)  # CMP_A=4 → <=1 after negation... actually use range
                    # Simpler: just set [0, 1]
                    vr0 = ida_hexrays.valrng_t(key.size)
                    vr0.set_eq(0)
                    vr1 = ida_hexrays.valrng_t(key.size)
                    vr1.set_eq(1)
                    vr0.unite_with(vr1)
                    return vr0
            # Source variable with known range → zero-extend preserves it
            src_vr = _lookup_range(ins.l, env)
            if src_vr is not None:
                vr = ida_hexrays.valrng_t(src_vr)
                if vr.get_size() != key.size:
                    vr.reduce_size(key.size)
                return vr
            # Unknown source: result is [0, max_for_source_size]
            src_max = (1 << (src_size * 8)) - 1 if src_size < 8 else mask
            vr = ida_hexrays.valrng_t(key.size)
            vr.set_cmp(5, src_max)  # CMP_BE=5 → <=src_max (unsigned)
            return vr
        return None

    # --- m_xds (8): sign-extend ---
    if opcode == ida_hexrays.m_xds:
        if ins.l is not None:
            src_size = ins.l.size
            # Sub-instruction set-flag → [0, 1]
            if ins.l.t == ida_hexrays.mop_d and ins.l.d is not None:
                if ins.l.d.opcode in _SET_FLAG_OPCODES:
                    vr0 = ida_hexrays.valrng_t(key.size)
                    vr0.set_eq(0)
                    vr1 = ida_hexrays.valrng_t(key.size)
                    vr1.set_eq(1)
                    vr0.unite_with(vr1)
                    return vr0
            # Source with known range
            src_vr = _lookup_range(ins.l, env)
            if src_vr is not None:
                vr = ida_hexrays.valrng_t(src_vr)
                if vr.get_size() != key.size:
                    vr.reduce_size(key.size)
                return vr
            # Unknown source: signed bound [-min, max] for source size
            if src_size < 8:
                sign_bit = 1 << (src_size * 8 - 1)
                # Result can be [0..sign_bit-1] or [sign-extended negative values]
                # Use IDA's set_cmp with signed bounds
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_all()  # conservative: all values
                return vr
        return None

    # --- m_low (0xA): truncation (low part) ---
    if opcode == ida_hexrays.m_low:
        if ins.l is not None:
            src_vr = _lookup_range(ins.l, env)
            if src_vr is not None:
                ok, val = src_vr.cvt_to_single_value()
                if ok:
                    vr = ida_hexrays.valrng_t(key.size)
                    vr.set_eq(int(val) & mask)
                    return vr
            # Truncation: result is bounded by dest size
            vr = ida_hexrays.valrng_t(key.size)
            vr.set_cmp(5, mask)  # CMP_BE → <=mask
            return vr
        return None

    # --- m_high (0xB): high part ---
    if opcode == ida_hexrays.m_high:
        if ins.l is not None:
            src_vr = _lookup_range(ins.l, env)
            if src_vr is not None:
                ok, val = src_vr.cvt_to_single_value()
                if ok:
                    shift = ins.l.size - key.size
                    if shift > 0:
                        vr = ida_hexrays.valrng_t(key.size)
                        vr.set_eq((int(val) >> (shift * 8)) & mask)
                        return vr
        return None

    # --- set-flag opcodes (0xF-0x12, 0x1D-0x29): result is [0, 1] ---
    # Note: hexx64 handles setz/setnz/setae/setb with map intersection.
    # We simplify to just producing [0, 1].
    if opcode in _SET_FLAG_OPCODES:
        vr0 = ida_hexrays.valrng_t(key.size)
        vr0.set_eq(0)
        vr1 = ida_hexrays.valrng_t(key.size)
        vr1.set_eq(1)
        vr0.unite_with(vr1)
        return vr0

    # --- m_neg (5): negation ---
    if opcode == ida_hexrays.m_neg:
        l_val = _resolve_singleton(ins.l, env)
        if l_val is not None:
            vr = ida_hexrays.valrng_t(key.size)
            vr.set_eq((-l_val) & mask)
            return vr
        return None

    # --- m_bnot (7): bitwise NOT ---
    if opcode == ida_hexrays.m_bnot:
        l_val = _resolve_singleton(ins.l, env)
        if l_val is not None:
            vr = ida_hexrays.valrng_t(key.size)
            vr.set_eq((~l_val) & mask)
            return vr
        return None

    # --- m_lnot (6): logical NOT → result is [0, 1] ---
    if opcode == ida_hexrays.m_lnot:
        vr0 = ida_hexrays.valrng_t(key.size)
        vr0.set_eq(0)
        vr1 = ida_hexrays.valrng_t(key.size)
        vr1.set_eq(1)
        vr0.unite_with(vr1)
        return vr0

    # --- Arithmetic with two operands ---
    if opcode in _ARITH_OPCODES:
        l_val = _resolve_singleton(ins.l, env)
        r_val = _resolve_singleton(ins.r, env)

        # Both singletons: compute exact result
        if l_val is not None and r_val is not None:
            result = None
            if opcode == ida_hexrays.m_add:
                result = (l_val + r_val) & mask
            elif opcode == ida_hexrays.m_sub:
                result = (l_val - r_val) & mask
            elif opcode == ida_hexrays.m_mul:
                result = (l_val * r_val) & mask
            elif opcode == ida_hexrays.m_xor:
                result = (l_val ^ r_val) & mask
            elif opcode == ida_hexrays.m_and:
                result = (l_val & r_val) & mask
            elif opcode == ida_hexrays.m_or:
                result = (l_val | r_val) & mask
            elif opcode == ida_hexrays.m_shl:
                if 0 <= r_val < key.size * 8:
                    result = (l_val << r_val) & mask
            elif opcode == ida_hexrays.m_shr:
                if 0 <= r_val < key.size * 8:
                    result = (l_val >> r_val) & mask
            elif opcode == ida_hexrays.m_sar:
                if 0 <= r_val < key.size * 8:
                    sign_bit = 1 << (key.size * 8 - 1)
                    if l_val & sign_bit:
                        # Sign-extend before shift
                        l_signed = l_val - (1 << (key.size * 8))
                        result = (l_signed >> r_val) & mask
                    else:
                        result = (l_val >> r_val) & mask
            if result is not None:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_eq(result)
                return vr

        # m_and with immediate mask (hexx64 pattern): result ∈ [0, mask_val]
        if opcode == ida_hexrays.m_and:
            r_imm = _resolve_singleton(ins.r, env)
            if r_imm is not None:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_cmp(5, r_imm & mask)  # CMP_BE → <= mask_val
                return vr
            l_imm = _resolve_singleton(ins.l, env)
            if l_imm is not None:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_cmp(5, l_imm & mask)  # CMP_BE → <= mask_val
                return vr

        # m_or with immediate mask (hexx64 pattern): result >= mask_val
        if opcode == ida_hexrays.m_or:
            r_imm = _resolve_singleton(ins.r, env)
            if r_imm is not None and r_imm != 0:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_cmp(2, r_imm & mask)  # CMP_AE → >= mask_val
                return vr

        return None

    return None


def _transfer_single_insn(ins, blk, env: ValrangeEnv) -> None:
    """Apply GEN/KILL for a single instruction (mutates *env* in-place).

    Mirrors hexx64's ``valranges_transfer_single_insn`` + def-list KILL.
    Handles: mov (const + var→var), xdu, xds, low, high, neg, bnot, lnot,
    set-flags (→[0,1]), add, sub, mul, xor, and, or, shl, shr, sar.
    KILL uses ``build_def_list`` to remove only actually-clobbered entries.
    """

    # Assertions are synthetic constraints (IPROP_ASSERT).
    if ins.is_assert():
        d = ins.d
        if d is not None:
            key = _extract_key_from_mop(d)
            if key is not None and ins.l is not None and ins.l.t == ida_hexrays.mop_n:
                vr = ida_hexrays.valrng_t(key.size)
                vr.set_eq(ins.l.nnn.value)
                if key in env:
                    env[key].intersect_with(vr)
                else:
                    env[key] = vr
        return

    # Determine destination key.
    # Set-flag opcodes write to .d with size 1, but the destination
    # operand we care about is the same .d field.
    d = ins.d
    if d is None:
        return

    key = _extract_key_from_mop(d)

    # Try GEN: produce a range for the destination.
    gen_vr = None
    if key is not None:
        gen_vr = _try_gen(ins, key, env)

    # KILL phase.
    # For instructions with a trackable dest key, always kill that key.
    # For side-effect instructions (calls, stx), use build_def_list to
    # determine which additional env entries are clobbered.
    if key is not None:
        env.pop(key, None)
    if ins.has_side_effects():
        try:
            def_list = blk.build_def_list(ins, ida_hexrays.MUST_ACCESS)
            if not def_list.empty():
                to_kill = [
                    k for k in env
                    if def_list.has_common(_key_to_mlist(k))
                ]
                for k in to_kill:
                    del env[k]
        except Exception:
            pass  # build_def_list failed; dest key already killed above

    # Apply GEN after KILL (GEN overwrites what KILL removed).
    if gen_vr is not None and key is not None:
        env[key] = gen_vr


def valrange_transfer(mba, serial: int, in_state: ValrangeEnv) -> ValrangeEnv:
    """Block-level transfer function: walk instructions applying GEN/KILL.

    Args:
        mba: The ``ida_hexrays.mba_t`` instance.
        serial: Block serial number.
        in_state: Input value-range environment (not mutated).

    Returns:
        Output environment after processing all instructions in the block.
    """
    blk = mba.get_mblock(serial)
    env = _clone_env(in_state)
    ins = blk.head
    while ins is not None:
        _transfer_single_insn(ins, blk, env)
        ins = ins.next
    return env


# ---------------------------------------------------------------------------
# Edge-aware fixpoint solver
# ---------------------------------------------------------------------------


def run_valrange_fixpoint(
    mba,
    *,
    max_iterations: int = 1000,
):
    """Run forward value-range dataflow analysis on *mba*.

    This is an edge-aware variant of ``run_forward_fixpoint_on_mba``:
    when merging predecessor outputs, each predecessor's OUT state is first
    refined through ``_refine_for_branch_edge`` before the union-meet.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        max_iterations: Safety bound.

    Returns:
        ``FixpointResult`` with ``in_states`` and ``out_states`` for every
        block serial.  ``in_states[serial]`` is the reconstructed
        ``valranges_t::known`` map for that block.
    """

    nodes = list(range(mba.qty))
    entry_node = 0

    in_states: dict[int, ValrangeEnv] = {n: {} for n in nodes}
    out_states: dict[int, ValrangeEnv] = {n: {} for n in nodes}

    # Seed with ALL nodes so the first pass reaches every reachable block.
    # (Starting with only the entry node would stall if the entry block's
    # transfer produces an empty OUT — identical to the initial state.)
    worklist: list[int] = list(range(mba.qty))
    iterations = 0

    while worklist and iterations < max_iterations:
        node = worklist.pop()
        iterations += 1

        blk = mba.get_mblock(node)
        preds = list(blk.predset)

        if preds:
            # Edge-aware meet: refine each predecessor's OUT for this edge,
            # then union-meet the results.
            refined_outs = []
            for p in preds:
                pred_blk = mba.get_mblock(p)
                refined = _refine_for_branch_edge(pred_blk, node, out_states[p])
                refined_outs.append(refined)
            in_new = valrange_meet(refined_outs)
        else:
            in_new = in_states[node]

        # Always store the latest IN state — the IN can change even when
        # the OUT stays the same (e.g. a block that overwrites the constrained
        # variable: IN gains a new constraint from a predecessor's branch,
        # but OUT remains the same constant).
        in_states[node] = in_new

        out_new = valrange_transfer(mba, node, in_new)

        if not _envs_equal(out_new, out_states[node]):
            out_states[node] = out_new
            for succ in blk.succset:
                if succ not in worklist:
                    worklist.append(succ)

    if logger.debug_on:
        logger.debug(
            "valrange fixpoint: %d iterations, %d nodes, %d worklist remaining",
            iterations,
            len(nodes),
            len(worklist),
        )

    return FixpointResult(
        in_states=in_states,
        out_states=out_states,
        iterations=iterations,
    )


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------


def validate_against_ida(mba, result=None) -> dict:
    """Compare reconstructed valranges against IDA's native ``get_valranges()``.

    Args:
        mba: The ``ida_hexrays.mba_t`` instance.
        result: A ``FixpointResult`` from ``run_valrange_fixpoint``.
            If None, runs the analysis first.
        verbose: Print per-block comparison details.

    Returns:
        Dict with keys ``matched``, ``mismatched``, ``ida_only``, ``ours_only``,
        each mapping to a count.
    """

    if result is None:
        result = run_valrange_fixpoint(mba)

    stats = {"matched": 0, "mismatched": 0, "ida_only": 0, "ours_only": 0}

    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        our_env = result.in_states.get(serial, {})

        # Collect all operand locations from instructions in this block.
        locations: set[ValrangeKey] = set(our_env.keys())
        ins = blk.head
        while ins is not None:
            for mop in (ins.l, ins.r, ins.d):
                key = _extract_key_from_mop(mop)
                if key is not None:
                    locations.add(key)
            ins = ins.next

        for key in locations:
            # Query IDA's native valrange.
            vivl = ida_hexrays.vivl_t()
            if key.mop_type == ida_hexrays.mop_r:
                vivl.set_reg(key.identifier, key.size)
            elif key.mop_type == ida_hexrays.mop_S:
                vivl.set_stkoff(key.identifier, key.size)
            else:
                continue

            ida_vr = ida_hexrays.valrng_t(key.size)
            ida_ok = blk.get_valranges(
                ida_vr, vivl, ida_hexrays.VR_AT_START | ida_hexrays.VR_EXACT
            )

            ida_has = ida_ok and not ida_vr.empty() and not ida_vr.all_values()
            our_has = (
                key in our_env
                and not our_env[key].empty()
                and not our_env[key].all_values()
            )

            if ida_has and our_has:
                ida_str = ida_vr.dstr()
                our_str = our_env[key].dstr()
                if ida_str == our_str:
                    stats["matched"] += 1
                else:
                    stats["mismatched"] += 1
                    if logger.debug_on:
                        logger.debug(
                            "  blk[%s] %s: IDA=%s  OURS=%s",
                            serial,
                            key,
                            ida_str,
                            our_str,
                        )
            elif ida_has and not our_has:
                stats["ida_only"] += 1
                if logger.debug_on:
                    logger.debug(
                        "  blk[%s] %s: IDA=%s  OURS=(none)",
                        serial,
                        key,
                        ida_vr.dstr(),
                    )
            elif our_has and not ida_has:
                stats["ours_only"] += 1
                if logger.debug_on:
                    logger.debug(
                        "  blk[%s] %s: IDA=(none)  OURS=%s",
                        serial,
                        key,
                        our_env[key].dstr(),
                    )

    return stats


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_valrange_key(key: ValrangeKey) -> str:
    """Format a key like IDA's ``print_valrange_key``.

    Registers: ``eax.4``  Stack vars: ``%0x3C.4``
    """
    if key.mop_type == ida_hexrays.mop_S:
        return f"%0x{key.identifier:X}.{key.size}"
    if key.mop_type == ida_hexrays.mop_r:
        name = ida_hexrays.get_mreg_name(key.identifier, key.size)
        if name:
            return f"{name}.{key.size}"
        return f"r{key.identifier}.{key.size}"
    return f"?{key.identifier}.{key.size}"


def format_valrange_env(env: ValrangeEnv) -> str:
    """Format an environment like IDA's ``valranges_t::print``.

    Returns ``"none"`` for empty envs, otherwise
    ``"key1:range1, key2:range2, ..."``.
    """
    if not env:
        return "none"
    parts = []
    for key, vr in env.items():
        if vr is TOP or vr is BOTTOM:
            continue
        if vr.empty() or vr.all_values():
            continue
        parts.append(f"{format_valrange_key(key)}:{vr.dstr()}")
    return ", ".join(parts) if parts else "none"


__all__ = [
    "ValrangeKey",
    "ValrangeEnv",
    "valrange_meet",
    "valrange_transfer",
    "run_valrange_fixpoint",
    "validate_against_ida",
    "format_valrange_key",
    "format_valrange_env",
]
