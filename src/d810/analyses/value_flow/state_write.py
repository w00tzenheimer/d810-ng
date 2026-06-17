"""Portable microcode constant-folding / state-write evaluation (value-flow).

Extracted from ``d810.backends.hexrays.evidence.condition_chain_analysis`` in the LS6 condition-chain split
(Landing Sequence step 6 / ticket d81-1w16).  This is the PURE constant-folding
core of the condition-chain handler-chain walker: forward evaluation of microcode
instructions to recover the constant value written to a state variable.

Portable-core: no IDA / Hex-Rays imports.  Everything vendor-specific is
supplied by the caller through :class:`MicrocodeEvalSeams` -- the opcode /
operand-type vocabulary (stable lifted identifier names) plus the two
live-mba accessors (an IDB scalar read and an lvar stack-offset resolver).
The Hex-Rays evidence adapter builds the seams from its live maps and
delegates here.  Operands / instructions are duck-typed opaque ``object``
handles; this module never names a Hex-Rays type.

The kill/overwrite semantics are preserved verbatim from the original
walker: ``_store_to_dest`` overwrites the stack/register maps even on an
unresolved source, and an unresolved operand yields ``None`` (a wrong
meet/init here silently wipes folded constants at control-flow merges).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Dict, List, Optional


@dataclass(frozen=True)
class MicrocodeEvalSeams:
    """Vendor-supplied vocabulary + live-mba accessors injected by the backend.

    Keeping these as injected callables is what makes the evaluation core
    portable: the names (``"mop_n"``, ``"m_add"``, ...) are stable lifted
    identifiers, and the two accessors encapsulate the only live-mba touches
    (an IDB scalar read and ``mba.vars[idx].location.stkoff()``).
    """

    mop_type_name: Callable[[object], Optional[str]]
    mop_type_value: Callable[[str, Optional[int]], Optional[int]]
    opcode_value: Callable[[str, Optional[int]], Optional[int]]
    opcode_name: Callable[[object], Optional[str]]
    fetch_stable_global_value: Callable[[int, int], Optional[int]]
    lvar_stkoff: Callable[[object, int], int]


def get_mop_const_value(
    mop: object,
    *,
    mop_type_name: Callable[[object], Optional[str]],
) -> Optional[int]:
    """Extract a constant integer value from a microcode operand if it is a number operand."""
    if mop is None:
        return None
    mop_type = getattr(mop, "t", None)
    if mop_type_name(mop_type) == "mop_n":
        nnn = getattr(mop, "nnn", None)
        if nnn is not None:
            return getattr(nnn, "value", None)
        value = getattr(mop, "value", None)
        if value is not None:
            return int(value)
    return None


def resolve_mop_from_maps(
    mop: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    *,
    seams: MicrocodeEvalSeams,
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
    read_ea: Optional[int] = None,
) -> Optional[int]:
    """Resolve a microcode operand to a concrete value using accumulated forward-eval maps.

    Handles: mop_n (literal), mop_S (stk_map via .s.off), mop_r (reg_map),
    mop_l (stk_map via lvar stkoff), mop_v (stable global), mop_d (recursive
    binop eval).

    ``state_var_gaddr`` names a *global* dispatcher state variable: a read of
    that global resolves through ``stk_map`` (keyed by gaddr) like a stack slot,
    so the handler's own next-state write folds.  ``foldable_global_reads`` maps
    ``read_ea -> {gaddr: initializer}`` (reaching-defs-sound, see
    :mod:`d810.analyses.value_flow.global_init_fold`): a global read at
    ``read_ea`` whose gaddr is listed folds to its static ``.data`` initializer
    -- the only value that can be live there because no store reaches it.
    """
    if mop is None:
        return None

    mop_type = mop.t
    mop_type_name = seams.mop_type_name(mop_type)

    result: Optional[int] = None

    if mop_type_name == "mop_n":
        result = get_mop_const_value(mop, mop_type_name=seams.mop_type_name)
    elif mop_type_name == "mop_S":
        off = getattr(mop, "s", None)
        if off is not None:
            off = getattr(off, "off", None)
        if off is None:
            off = getattr(mop, "stkoff", None)
        if off is not None:
            result = stk_map.get(off)
    elif mop_type_name == "mop_r":
        reg = getattr(mop, "r", None)
        if reg is None:
            reg = getattr(mop, "reg", None)
        if reg is not None:
            result = reg_map.get(reg)
    elif mop_type_name == "mop_l":
        lvar_ref = getattr(mop, "l", None)
        idx = getattr(lvar_ref, "idx", None) if lvar_ref is not None else None
        if idx is not None and state_var_lvar_idx is not None and idx == state_var_lvar_idx:
            # State var itself — look up by its own state in stk_map if available
            pass
        if idx is not None and mba is not None:
            try:
                off = seams.lvar_stkoff(mba, idx)
                result = stk_map.get(off)
            except Exception:
                pass
    elif mop_type_name == "mop_v":
        try:
            addr = int(getattr(mop, "g", 0) or getattr(mop, "gaddr", 0) or 0)
            size = int(getattr(mop, "size", 0) or 0)
            # 1) A value written to this global EARLIER in the same forward scan
            #    (tracked in stk_map under the gaddr key) -- in-block global
            #    dataflow, e.g. ``qword |= M`` then ``state = qword``.
            if addr and addr in stk_map:
                result = stk_map[addr]
            # 2) Reaching-defs-sound static-initializer fold: a global read that
            #    no store can reach resolves to its loader-supplied initializer.
            elif (
                foldable_global_reads is not None
                and read_ea is not None
                and addr
            ):
                init = foldable_global_reads.get(int(read_ea), {}).get(addr)
                if init is not None:
                    result = int(init)
                else:
                    result = seams.fetch_stable_global_value(addr, size)
            else:
                result = seams.fetch_stable_global_value(addr, size)
        except Exception:
            result = None
    elif mop_type_name == "mop_d":
        nested = getattr(mop, "d", None)
        if nested is not None:
            op = getattr(nested, "opcode", None)
            l_mop = getattr(nested, "l", None)
            r_mop = getattr(nested, "r", None)
            lv = resolve_mop_from_maps(
                l_mop,
                stk_map,
                reg_map,
                seams=seams,
                mba=mba,
                state_var_lvar_idx=state_var_lvar_idx,
                diag_lines=diag_lines,
                state_var_gaddr=state_var_gaddr,
                foldable_global_reads=foldable_global_reads,
                read_ea=read_ea,
            )
            if r_mop is not None and getattr(r_mop, "t", None) != 0:
                rv = resolve_mop_from_maps(
                    r_mop,
                    stk_map,
                    reg_map,
                    seams=seams,
                    mba=mba,
                    state_var_lvar_idx=state_var_lvar_idx,
                    diag_lines=diag_lines,
                    state_var_gaddr=state_var_gaddr,
                    foldable_global_reads=foldable_global_reads,
                    read_ea=read_ea,
                )
            else:
                rv = None
            if lv is not None:
                m_add = seams.opcode_value("m_add", 28)
                m_sub = seams.opcode_value("m_sub", 29)
                m_and = seams.opcode_value("m_and", 21)
                m_or = seams.opcode_value("m_or", 22)
                m_xor = seams.opcode_value("m_xor", 31)
                m_mul = seams.opcode_value("m_mul", 30)
                m_xdu = seams.opcode_value("m_xdu", None)
                m_xds = seams.opcode_value("m_xds", None)
                if rv is not None:
                    if op == m_xor:
                        result = (lv ^ rv) & 0xFFFFFFFF
                    elif op == m_sub:
                        result = (lv - rv) & 0xFFFFFFFF
                    elif op == m_add:
                        result = (lv + rv) & 0xFFFFFFFF
                    elif op == m_and:
                        result = (lv & rv) & 0xFFFFFFFF
                    elif op == m_or:
                        result = (lv | rv) & 0xFFFFFFFF
                    elif op == m_mul:
                        result = (lv * rv) & 0xFFFFFFFF
                elif m_xdu is not None and op == m_xdu:
                    out_size = int(getattr(mop, "size", 0) or getattr(nested, "size", 0) or 4)
                    result = int(lv) & ((1 << (out_size * 8)) - 1)
                elif m_xds is not None and op == m_xds:
                    in_size = int(getattr(l_mop, "size", 0) or 4)
                    out_size = int(getattr(mop, "size", 0) or getattr(nested, "size", 0) or in_size)
                    sign_bit = 1 << (in_size * 8 - 1)
                    if int(lv) & sign_bit:
                        result = int(lv) | (
                            ((1 << (out_size * 8)) - 1)
                            ^ ((1 << (in_size * 8)) - 1)
                        )
                    else:
                        result = int(lv)
                    result &= (1 << (out_size * 8)) - 1

    if diag_lines is not None:
        diag_lines.append(
            f"  fwd_resolve: mop_t={mop_type} -> {hex(result) if result is not None else 'None'}"
        )
    return result


def forward_eval_insn(
    insn: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    *,
    seams: MicrocodeEvalSeams,
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
) -> Optional[int]:
    """Evaluate one instruction, updating stk_map/reg_map in-place.

    Returns the resolved constant if this instruction writes the state
    variable; otherwise returns None and updates the maps.

    ``state_var_gaddr`` / ``foldable_global_reads`` enable a *global* dispatcher
    state variable (see :func:`resolve_mop_from_maps`): a write to that global is
    treated as the state-var write, and a reaching-defs-stable global read folds
    to its static initializer.
    """
    if insn is None:
        return None

    op = getattr(insn, "opcode", None)
    if op is None:
        return None

    read_ea: Optional[int] = None
    try:
        ea_val = getattr(insn, "ea", None)
        if ea_val is not None:
            read_ea = int(ea_val)
    except (TypeError, ValueError):
        read_ea = None

    m_mov_op = seams.opcode_value("m_mov", None)
    m_add = seams.opcode_value("m_add", 28)
    m_sub = seams.opcode_value("m_sub", 29)
    m_and = seams.opcode_value("m_and", 21)
    m_or = seams.opcode_value("m_or", 22)
    m_xor = seams.opcode_value("m_xor", 31)
    m_mul = seams.opcode_value("m_mul", 30)
    binary_ops = {m_add, m_sub, m_and, m_or, m_xor, m_mul}
    m_xdu_op = seams.opcode_value("m_xdu", None)
    m_xds_op = seams.opcode_value("m_xds", None)

    mop_S_type = seams.mop_type_value("mop_S", None)
    mop_r_type = seams.mop_type_value("mop_r", 1)
    mop_l_type = seams.mop_type_value("mop_l", 9)
    mop_v_type = seams.mop_type_value("mop_v", None)

    def _store_to_dest(dest: object, val: int) -> bool:
        """Store val into the appropriate map based on dest type. Returns True if state var."""
        dest_t = getattr(dest, "t", None)
        is_state = False
        # A write to a GLOBAL: record it in stk_map under its gaddr key so a
        # later read of the same global in this forward scan resolves to it
        # (in-block global dataflow: ``qword |= M`` then ``state = qword``).  It
        # is the state-var write only when this global IS the state variable.
        if mop_v_type is not None and dest_t == mop_v_type:
            gaddr = int(getattr(dest, "g", 0) or getattr(dest, "gaddr", 0) or 0)
            if gaddr:
                stk_map[gaddr] = val
                if state_var_gaddr is not None and gaddr == int(state_var_gaddr):
                    is_state = True
            return is_state
        if mop_S_type is not None and dest_t == mop_S_type:
            off = getattr(dest, "s", None)
            if off is not None:
                off = getattr(off, "off", None)
            if off is None:
                off = getattr(dest, "stkoff", None)
            if off is not None:
                stk_map[off] = val
                if off == state_var_stkoff:
                    is_state = True
        elif dest_t == mop_r_type:
            reg = getattr(dest, "r", None)
            if reg is None:
                reg = getattr(dest, "reg", None)
            if reg is not None:
                reg_map[reg] = val
        elif mop_l_type is not None and dest_t == mop_l_type:
            lvar_ref = getattr(dest, "l", None)
            idx = getattr(lvar_ref, "idx", None) if lvar_ref is not None else None
            if idx is not None and mba is not None:
                try:
                    off = seams.lvar_stkoff(mba, idx)
                    stk_map[off] = val
                    if off == state_var_stkoff:
                        is_state = True
                except Exception:
                    pass
            if idx is not None and state_var_lvar_idx is not None and idx == state_var_lvar_idx:
                is_state = True
        return is_state

    dest = getattr(insn, "d", None)
    if dest is None:
        return None

    val: Optional[int] = None
    _glb = dict(
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
        read_ea=read_ea,
    )

    if op == m_mov_op:
        src = getattr(insn, "l", None)
        val = resolve_mop_from_maps(
            src, stk_map, reg_map, seams=seams, mba=mba,
            state_var_lvar_idx=state_var_lvar_idx, diag_lines=diag_lines, **_glb,
        )
    elif m_xdu_op is not None and op == m_xdu_op:
        # Zero-extend: value stays the same, just widens the register
        src = getattr(insn, "l", None)
        val = resolve_mop_from_maps(
            src, stk_map, reg_map, seams=seams, mba=mba,
            state_var_lvar_idx=state_var_lvar_idx, diag_lines=diag_lines, **_glb,
        )
    elif m_xds_op is not None and op == m_xds_op:
        # Sign-extend: check high bit of source width, extend if set
        src = getattr(insn, "l", None)
        src_val = resolve_mop_from_maps(
            src, stk_map, reg_map, seams=seams, mba=mba,
            state_var_lvar_idx=state_var_lvar_idx, diag_lines=diag_lines, **_glb,
        )
        if src_val is not None:
            src_size = getattr(src, "size", 4)  # source operand size in bytes
            dst_size = getattr(dest, "size", 8)  # dest operand size in bytes
            sign_bit = 1 << (src_size * 8 - 1)
            if src_val & sign_bit:
                # Negative: fill upper bits with 1s
                mask = (1 << (dst_size * 8)) - (1 << (src_size * 8))
                src_val = src_val | mask
            val = src_val
    elif op in binary_ops:
        l_mop = getattr(insn, "l", None)
        r_mop = getattr(insn, "r", None)
        lv = resolve_mop_from_maps(
            l_mop, stk_map, reg_map, seams=seams, mba=mba,
            state_var_lvar_idx=state_var_lvar_idx, **_glb,
        )
        rv = resolve_mop_from_maps(
            r_mop, stk_map, reg_map, seams=seams, mba=mba,
            state_var_lvar_idx=state_var_lvar_idx, **_glb,
        )
        if lv is not None and rv is not None:
            if op == m_xor:
                val = (lv ^ rv) & 0xFFFFFFFF
            elif op == m_sub:
                val = (lv - rv) & 0xFFFFFFFF
            elif op == m_add:
                val = (lv + rv) & 0xFFFFFFFF
            elif op == m_and:
                val = (lv & rv) & 0xFFFFFFFF
            elif op == m_or:
                val = (lv | rv) & 0xFFFFFFFF
            elif op == m_mul:
                val = (lv * rv) & 0xFFFFFFFF
    else:
        return None

    if val is None:
        return None

    val = val & 0xFFFFFFFF
    is_state = _store_to_dest(dest, val)
    if is_state:
        if diag_lines is not None:
            opcode_name = seams.opcode_name(op) or f"opcode_{op}"
            diag_lines.append(
                f"  fwd_eval_insn: {opcode_name} -> state_var write 0x{val:x}"
            )
        return val
    return None
