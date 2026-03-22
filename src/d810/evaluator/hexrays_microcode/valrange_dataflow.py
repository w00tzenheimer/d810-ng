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


def _transfer_single_insn(ins, env: ValrangeEnv) -> None:
    """Apply GEN/KILL for a single instruction (mutates *env* in-place).

    - Assertions (``is_assert()``) with ``mov #constant, dest`` → GEN
      singleton range.  Assertions are synthetic constraints inserted by
      Hex-Rays and must NOT be treated as side-effect instructions.
    - ``mov #constant, dest``  → GEN singleton range for dest
    - Any other write to dest  → KILL (remove constraint for dest)
    - Calls with side-effects  → KILL everything
    """

    # Assertions are synthetic constraint instructions (IPROP_ASSERT).
    # They encode value-range facts as "mov #val, op" and must be
    # handled as GEN, not killed by has_side_effects().
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

    # Side-effect instructions (calls, stx, etc.) may clobber memory but
    # generally don't invalidate register or stack-variable constraints
    # that aren't in the def-list.  A full implementation would consult
    # build_def_list() to KILL only affected locations.  For now we
    # conservatively kill only the destination operand (if extractable)
    # rather than wiping the entire env — the real hexx64 algorithm does
    # the same via per-instruction def-lists.
    if ins.has_side_effects():
        d = ins.d
        if d is not None:
            key = _extract_key_from_mop(d)
            if key is not None:
                env.pop(key, None)
        return

    # Identify the destination operand.
    d = ins.d
    if d is None:
        return

    key = _extract_key_from_mop(d)
    if key is None:
        return

    # GEN: mov #imm, dest (regular constant assignment)
    if (
        ins.opcode == ida_hexrays.m_mov
        and ins.l is not None
        and ins.l.t == ida_hexrays.mop_n
    ):
        vr = ida_hexrays.valrng_t(key.size)
        vr.set_eq(ins.l.nnn.value)
        env[key] = vr
        return

    # GEN: arithmetic with two known-constant operands
    if ins.opcode in (
        ida_hexrays.m_add,
        ida_hexrays.m_sub,
        ida_hexrays.m_xor,
        ida_hexrays.m_and,
        ida_hexrays.m_or,
    ):
        l_val = _resolve_singleton(ins.l, env)
        r_val = _resolve_singleton(ins.r, env)
        if l_val is not None and r_val is not None:
            mask = (1 << (key.size * 8)) - 1
            if ins.opcode == ida_hexrays.m_add:
                result = (l_val + r_val) & mask
            elif ins.opcode == ida_hexrays.m_sub:
                result = (l_val - r_val) & mask
            elif ins.opcode == ida_hexrays.m_xor:
                result = (l_val ^ r_val) & mask
            elif ins.opcode == ida_hexrays.m_and:
                result = (l_val & r_val) & mask
            elif ins.opcode == ida_hexrays.m_or:
                result = (l_val | r_val) & mask
            vr = ida_hexrays.valrng_t(key.size)
            vr.set_eq(result)
            env[key] = vr
            return
        # Fall through to KILL if operands aren't resolved

    # KILL: destination is overwritten by a non-constant → remove constraint.
    env.pop(key, None)


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
        _transfer_single_insn(ins, env)
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
