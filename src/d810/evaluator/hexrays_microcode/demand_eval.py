"""Demand-driven worklist variable resolution (Algorithm 2).

Resolves a variable to a constant by lazily building a dependency graph
using IDA UD chains and iteratively resolving it with a bounded worklist.
No recursion, no environment copies -- uses a flat memo dict with explicit
bounds.

The memo dict is shared across calls for caching within a single
emulation pass.
"""
from __future__ import annotations

from collections import deque

from d810.core.logging import getLogger

logger = getLogger(__name__)

# Bounds to prevent runaway analysis.
_MAX_WORKLIST_ITERATIONS = 200
_MAX_WORKLIST_SIZE = 500

# Opcodes we can safely evaluate with known constant operands.
# Mirrors the arithmetic subset of MicroCodeInterpreter._eval_instruction.
_SAFE_OPCODES: frozenset[int] | None = None


def _get_safe_opcodes() -> frozenset[int]:
    """Lazily build the set of safe arithmetic opcodes."""
    global _SAFE_OPCODES
    if _SAFE_OPCODES is not None:
        return _SAFE_OPCODES
    import ida_hexrays
    _SAFE_OPCODES = frozenset([
        ida_hexrays.m_mov,
        ida_hexrays.m_neg,
        ida_hexrays.m_lnot,
        ida_hexrays.m_bnot,
        ida_hexrays.m_xds,
        ida_hexrays.m_xdu,
        ida_hexrays.m_low,
        ida_hexrays.m_high,
        ida_hexrays.m_add,
        ida_hexrays.m_sub,
        ida_hexrays.m_mul,
        ida_hexrays.m_udiv,
        ida_hexrays.m_sdiv,
        ida_hexrays.m_umod,
        ida_hexrays.m_smod,
        ida_hexrays.m_or,
        ida_hexrays.m_and,
        ida_hexrays.m_xor,
        ida_hexrays.m_shl,
        ida_hexrays.m_shr,
        ida_hexrays.m_sar,
        ida_hexrays.m_cfadd,
        ida_hexrays.m_ofadd,
        ida_hexrays.m_sets,
        ida_hexrays.m_seto,
        ida_hexrays.m_setnz,
        ida_hexrays.m_setz,
        ida_hexrays.m_setae,
        ida_hexrays.m_setb,
        ida_hexrays.m_seta,
        ida_hexrays.m_setbe,
        ida_hexrays.m_setg,
        ida_hexrays.m_setge,
        ida_hexrays.m_setl,
        ida_hexrays.m_setle,
        ida_hexrays.m_setp,
    ])
    return _SAFE_OPCODES


# Unary opcodes (only use ins.l, not ins.r).
_UNARY_OPCODES: frozenset[int] | None = None


def _get_unary_opcodes() -> frozenset[int]:
    """Lazily build the set of unary opcodes."""
    global _UNARY_OPCODES
    if _UNARY_OPCODES is not None:
        return _UNARY_OPCODES
    import ida_hexrays
    _UNARY_OPCODES = frozenset([
        ida_hexrays.m_mov,
        ida_hexrays.m_neg,
        ida_hexrays.m_lnot,
        ida_hexrays.m_bnot,
        ida_hexrays.m_xds,
        ida_hexrays.m_xdu,
        ida_hexrays.m_low,
        ida_hexrays.m_high,
        ida_hexrays.m_sets,
    ])
    return _UNARY_OPCODES


def resolve_variable_demand(
    mba: object,
    blk_serial: int,
    mop_type: int,
    identifier: int,
    size: int,
    memo: dict[tuple, int | None] | None = None,
) -> int | None:
    """Resolve a variable to a constant using demand-driven worklist.

    Uses IDA UD chains to find definitions, then iteratively resolves
    dependency chains without recursion. The memo dict is shared across
    calls for caching.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Block serial where the variable is used.
        mop_type: Operand type (``ida_hexrays.mop_r`` or ``mop_S``).
        identifier: Register number (for mop_r) or stack offset (for mop_S).
        size: Operand size in bytes.
        memo: Shared memo dict for caching across calls. Created if None.

    Returns:
        The constant value if resolved, or ``None`` if unresolvable.
    """
    import ida_hexrays

    if memo is None:
        memo = {}

    from d810.hexrays.expr.p_ast import get_mop_key

    # Build a synthetic mop_key for the query variable.
    # get_mop_key returns (mop_type, size, identifier) for mop_r and mop_S.
    key: tuple = (mop_type, size, identifier)

    if key in memo:
        return memo[key]

    # Find single def via UD chains.
    from d810.evaluator.hexrays_microcode.chains import (
        find_reaching_defs_for_reg,
        find_reaching_defs_for_stkvar,
    )

    if mop_type == ida_hexrays.mop_r:
        defs = find_reaching_defs_for_reg(mba, blk_serial, identifier, size)
    elif mop_type == ida_hexrays.mop_S:
        defs = find_reaching_defs_for_stkvar(mba, blk_serial, identifier, size)
    else:
        memo[key] = None
        return None

    if len(defs) != 1:
        memo[key] = None
        return None

    # Worklist entries: (mop_key, def_block_serial, def_insn_ea)
    worklist: deque[tuple[tuple, int, int]] = deque()
    worklist.append((key, defs[0].block_serial, defs[0].ins_ea))

    return _process_worklist(mba, worklist, memo)


def _process_worklist(
    mba: object,
    worklist: deque[tuple[tuple, int, int]],
    memo: dict[tuple, int | None],
) -> int | None:
    """Iteratively resolve the worklist until the initial key is resolved.

    Returns the value for the first key that was added, or None.
    """
    import ida_hexrays
    from d810.evaluator.hexrays_microcode.chains import (
        find_reaching_defs_for_reg,
        find_reaching_defs_for_stkvar,
    )

    if not worklist:
        return None

    # Remember the original key we want to resolve.
    original_key = worklist[0][0]

    iteration = 0
    while worklist and iteration < _MAX_WORKLIST_ITERATIONS:
        iteration += 1

        wl_key, wl_blk, wl_ea = worklist.popleft()

        if wl_key in memo:
            continue  # Already resolved (or marked unresolvable).

        # Find the defining instruction.
        def_insn = _find_def_insn(mba, wl_blk, wl_ea)
        if def_insn is None:
            memo[wl_key] = None
            continue

        # Only handle safe arithmetic opcodes.
        if def_insn.opcode not in _get_safe_opcodes():
            memo[wl_key] = None
            continue

        # Get source operands for this instruction.
        sources = _get_source_operands(def_insn)

        # Check if all source operands are resolved.
        all_resolved = True
        for src in sources:
            src_key = _mop_to_key(src)
            if src_key is None:
                # Unsupported operand type.
                memo[wl_key] = None
                all_resolved = False
                break

            if src.t == ida_hexrays.mop_n:
                # Immediate value -- resolve directly.
                memo[src_key] = src.nnn.value
            elif src_key not in memo:
                # Source not resolved yet -- find its def and add to worklist.
                if len(worklist) >= _MAX_WORKLIST_SIZE:
                    memo[src_key] = None
                    all_resolved = False
                    continue

                src_type = src_key[0]
                src_size = src_key[1]
                src_id = src_key[2] if len(src_key) > 2 else None

                if src_id is None:
                    memo[src_key] = None
                    all_resolved = False
                    continue

                if src_type == ida_hexrays.mop_r:
                    src_defs = find_reaching_defs_for_reg(mba, wl_blk, src_id, src_size)
                elif src_type == ida_hexrays.mop_S:
                    src_defs = find_reaching_defs_for_stkvar(mba, wl_blk, src_id, src_size)
                else:
                    memo[src_key] = None
                    all_resolved = False
                    continue

                if len(src_defs) == 1:
                    worklist.append((src_key, src_defs[0].block_serial, src_defs[0].ins_ea))
                else:
                    memo[src_key] = None
                all_resolved = False

        if all_resolved and wl_key not in memo:
            # All sources available -- evaluate the instruction.
            result = _eval_with_constants(def_insn, memo)
            memo[wl_key] = result
        elif wl_key not in memo:
            # Check if it was marked None above (unsupported operand).
            if memo.get(wl_key) is None and wl_key in memo:
                continue
            # Re-queue for later (sources may resolve in next iteration).
            if len(worklist) < _MAX_WORKLIST_SIZE:
                worklist.append((wl_key, wl_blk, wl_ea))

    return memo.get(original_key)


def _find_def_insn(mba: object, blk_serial: int, ea: int) -> object | None:
    """Scan a block for the instruction at a given EA."""
    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return None
    ins = blk.head  # type: ignore[attr-defined]
    while ins is not None:
        if ins.ea == ea:
            return ins
        ins = ins.next  # type: ignore[attr-defined]
    return None


def _get_source_operands(ins: object) -> list[object]:
    """Extract source mop_t list from an instruction.

    For unary ops (mov, neg, etc.), returns [ins.l].
    For binary ops (add, sub, etc.), returns [ins.l, ins.r].
    """
    sources: list[object] = []
    if ins.l is not None:  # type: ignore[attr-defined]
        sources.append(ins.l)  # type: ignore[attr-defined]
    if ins.opcode not in _get_unary_opcodes() and ins.r is not None:  # type: ignore[attr-defined]
        sources.append(ins.r)  # type: ignore[attr-defined]
    return sources


def _mop_to_key(mop: object) -> tuple | None:
    """Convert a mop_t to a hashable key matching get_mop_key format.

    Returns None for unsupported operand types.
    """
    import ida_hexrays
    t = mop.t  # type: ignore[attr-defined]
    size = mop.size  # type: ignore[attr-defined]

    if t == ida_hexrays.mop_n:
        nnn = mop.nnn  # type: ignore[attr-defined]
        val = nnn.value if nnn is not None else 0
        return (t, size, mop.valnum, val)  # type: ignore[attr-defined]
    elif t == ida_hexrays.mop_r:
        return (t, size, mop.r)  # type: ignore[attr-defined]
    elif t == ida_hexrays.mop_S:
        s = mop.s  # type: ignore[attr-defined]
        if s is not None:
            return (t, size, s.off)
        return None
    else:
        return None


def _eval_with_constants(
    ins: object,
    memo: dict[tuple, int | None],
) -> int | None:
    """Evaluate an instruction using known constant values from memo.

    Returns the computed value masked to destination size, or None on failure.
    """
    import ida_hexrays
    from d810.hexrays.utils.hexrays_helpers import AND_TABLE
    from d810.core.bits import (
        get_add_cf,
        get_add_of,
        get_parity_flag,
        get_sub_of,
        signed_to_unsigned,
        unsigned_to_signed,
    )

    opcode = ins.opcode  # type: ignore[attr-defined]
    d = ins.d  # type: ignore[attr-defined]
    if d is None or d.size <= 0:
        return None

    res_mask = AND_TABLE.get(d.size, AND_TABLE[8])

    def _val(mop: object) -> int | None:
        """Resolve a source operand to its constant value."""
        t = mop.t  # type: ignore[attr-defined]
        if t == ida_hexrays.mop_n:
            nnn = mop.nnn  # type: ignore[attr-defined]
            return nnn.value if nnn is not None else 0
        key = _mop_to_key(mop)
        if key is None:
            return None
        return memo.get(key)

    l_mop = ins.l  # type: ignore[attr-defined]
    r_mop = ins.r  # type: ignore[attr-defined]

    lv = _val(l_mop) if l_mop is not None else None
    if lv is None:
        return None

    # Unary operations.
    if opcode == ida_hexrays.m_mov:
        return lv & res_mask
    elif opcode == ida_hexrays.m_neg:
        return (-lv) & res_mask
    elif opcode == ida_hexrays.m_lnot:
        return int(lv == 0) & res_mask
    elif opcode == ida_hexrays.m_bnot:
        return (lv ^ res_mask) & res_mask
    elif opcode == ida_hexrays.m_xds:
        ls = l_mop.size if l_mop is not None else d.size  # type: ignore[attr-defined]
        left_signed = unsigned_to_signed(lv, ls)
        return signed_to_unsigned(left_signed, d.size) & res_mask
    elif opcode == ida_hexrays.m_xdu:
        return lv & res_mask
    elif opcode == ida_hexrays.m_low:
        return lv & res_mask
    elif opcode == ida_hexrays.m_high:
        shift_bits = d.size * 8 if d.size else 0
        return (lv >> shift_bits) & res_mask
    elif opcode == ida_hexrays.m_sets:
        ls = l_mop.size if l_mop is not None else d.size  # type: ignore[attr-defined]
        left_signed = unsigned_to_signed(lv, ls)
        return (1 if left_signed < 0 else 0) & res_mask

    # Binary operations -- need right value.
    rv = _val(r_mop) if r_mop is not None else None
    if rv is None:
        return None

    ls = l_mop.size if l_mop is not None else d.size  # type: ignore[attr-defined]
    rs = r_mop.size if r_mop is not None else d.size  # type: ignore[attr-defined]

    if opcode == ida_hexrays.m_add:
        return (lv + rv) & res_mask
    elif opcode == ida_hexrays.m_sub:
        return (lv - rv) & res_mask
    elif opcode == ida_hexrays.m_mul:
        return (lv * rv) & res_mask
    elif opcode == ida_hexrays.m_udiv:
        return (lv // rv) & res_mask if rv != 0 else None
    elif opcode == ida_hexrays.m_sdiv:
        if rv == 0:
            return None
        left_s = unsigned_to_signed(lv, ls)
        right_s = unsigned_to_signed(rv, rs)
        if right_s == 0:
            return None
        quotient = (abs(left_s) // abs(right_s)) * (
            -1 if (left_s < 0) ^ (right_s < 0) else 1
        )
        return signed_to_unsigned(quotient, d.size) & res_mask
    elif opcode == ida_hexrays.m_umod:
        return (lv % rv) & res_mask if rv != 0 else None
    elif opcode == ida_hexrays.m_smod:
        if rv == 0:
            return None
        left_s = unsigned_to_signed(lv, ls)
        right_s = unsigned_to_signed(rv, rs)
        if right_s == 0:
            return None
        quotient = (abs(left_s) // abs(right_s)) * (
            -1 if (left_s < 0) ^ (right_s < 0) else 1
        )
        remainder = left_s - (quotient * right_s)
        return signed_to_unsigned(remainder, d.size) & res_mask
    elif opcode == ida_hexrays.m_or:
        return (lv | rv) & res_mask
    elif opcode == ida_hexrays.m_and:
        return (lv & rv) & res_mask
    elif opcode == ida_hexrays.m_xor:
        return (lv ^ rv) & res_mask
    elif opcode == ida_hexrays.m_shl:
        return (lv << rv) & res_mask
    elif opcode == ida_hexrays.m_shr:
        return (lv >> rv) & res_mask
    elif opcode == ida_hexrays.m_sar:
        res_signed = unsigned_to_signed(lv, ls) >> rv
        return signed_to_unsigned(res_signed, d.size) & res_mask
    elif opcode == ida_hexrays.m_cfadd:
        return get_add_cf(lv, rv, ls) & res_mask
    elif opcode == ida_hexrays.m_ofadd:
        return get_add_of(lv, rv, ls) & res_mask
    elif opcode == ida_hexrays.m_seto:
        left_s = unsigned_to_signed(lv, ls)
        right_s = unsigned_to_signed(rv, rs)
        return get_sub_of(left_s, right_s, ls) & res_mask
    elif opcode == ida_hexrays.m_setnz:
        return (1 if lv != rv else 0) & res_mask
    elif opcode == ida_hexrays.m_setz:
        return (1 if lv == rv else 0) & res_mask
    elif opcode == ida_hexrays.m_setae:
        return (1 if lv >= rv else 0) & res_mask
    elif opcode == ida_hexrays.m_setb:
        return (1 if lv < rv else 0) & res_mask
    elif opcode == ida_hexrays.m_seta:
        return (1 if lv > rv else 0) & res_mask
    elif opcode == ida_hexrays.m_setbe:
        return (1 if lv <= rv else 0) & res_mask
    elif opcode == ida_hexrays.m_setg:
        return (1 if unsigned_to_signed(lv, ls) > unsigned_to_signed(rv, rs) else 0) & res_mask
    elif opcode == ida_hexrays.m_setge:
        return (1 if unsigned_to_signed(lv, ls) >= unsigned_to_signed(rv, rs) else 0) & res_mask
    elif opcode == ida_hexrays.m_setl:
        return (1 if unsigned_to_signed(lv, ls) < unsigned_to_signed(rv, rs) else 0) & res_mask
    elif opcode == ida_hexrays.m_setle:
        return (1 if unsigned_to_signed(lv, ls) <= unsigned_to_signed(rv, rs) else 0) & res_mask
    elif opcode == ida_hexrays.m_setp:
        return get_parity_flag(lv, rv, ls) & res_mask

    return None
