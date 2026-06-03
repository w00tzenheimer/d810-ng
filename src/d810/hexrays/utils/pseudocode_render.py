"""Render microcode blocks as C-like pseudocode.

Converts minsn_t instruction lists to human-readable C-like syntax,
suitable for DAG visualization and debugging dumps.
"""

from __future__ import annotations

import ida_hexrays
import ida_name
import re

from d810.core.logging import getLogger
from d810.core.typing import List, Optional

logger = getLogger(__name__)

_SIMPLE_DEREF_ADDR_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

# ---------------------------------------------------------------------------
# Size-to-type helpers for cast rendering
# ---------------------------------------------------------------------------

_SIGNED_TYPE_BY_SIZE = {
    1: "int8_t",
    2: "int16_t",
    4: "int32_t",
    8: "int64_t",
}

_UNSIGNED_TYPE_BY_SIZE = {
    1: "uint8_t",
    2: "uint16_t",
    4: "uint32_t",
    8: "uint64_t",
}

# ---------------------------------------------------------------------------
# Opcode -> C-operator tables
# ---------------------------------------------------------------------------

# Binary operators: opcode -> (operator_string, signed_hint)
_BINARY_OPS = {
    ida_hexrays.m_add:  "+",
    ida_hexrays.m_sub:  "-",
    ida_hexrays.m_mul:  "*",
    ida_hexrays.m_udiv: "/u",
    ida_hexrays.m_sdiv: "/s",
    ida_hexrays.m_umod: "%u",
    ida_hexrays.m_smod: "%s",
    ida_hexrays.m_or:   "|",
    ida_hexrays.m_and:  "&",
    ida_hexrays.m_xor:  "^",
    ida_hexrays.m_shl:  "<<",
    ida_hexrays.m_shr:  ">>u",
    ida_hexrays.m_sar:  ">>s",
}

# Unary operators: opcode -> prefix
_UNARY_OPS = {
    ida_hexrays.m_neg:  "-",
    ida_hexrays.m_lnot: "!",
    ida_hexrays.m_bnot: "~",
}

# Set-condition opcodes: opcode -> C comparison string
_SET_OPS = {
    ida_hexrays.m_setz:  "==",
    ida_hexrays.m_setnz: "!=",
    ida_hexrays.m_setae: ">=u",
    ida_hexrays.m_setb:  "<u",
    ida_hexrays.m_seta:  ">u",
    ida_hexrays.m_setbe: "<=u",
    ida_hexrays.m_setg:  ">s",
    ida_hexrays.m_setge: ">=s",
    ida_hexrays.m_setl:  "<s",
    ida_hexrays.m_setle: "<=s",
}

# Conditional jump opcodes: opcode -> C comparison string
_JCC_OPS = {
    ida_hexrays.m_jnz: "!=",
    ida_hexrays.m_jz:  "==",
    ida_hexrays.m_jae: ">=u",
    ida_hexrays.m_jb:  "<u",
    ida_hexrays.m_ja:  ">u",
    ida_hexrays.m_jbe: "<=u",
    ida_hexrays.m_jg:  ">s",
    ida_hexrays.m_jge: ">=s",
    ida_hexrays.m_jl:  "<s",
    ida_hexrays.m_jle: "<=s",
}


# ---------------------------------------------------------------------------
# Number formatting
# ---------------------------------------------------------------------------

def _format_number(value: int) -> str:
    """Format a numeric value: decimal for 0-9, hex otherwise."""
    if 0 <= value <= 9:
        return str(value)
    return f"0x{value:X}"


# ---------------------------------------------------------------------------
# Operand rendering
# ---------------------------------------------------------------------------


def _format_memory_expr(seg_str: str, addr_str: str) -> str:
    """Render a memory dereference, eliding the default ``ds`` segment."""
    if _SIMPLE_DEREF_ADDR_RE.match(addr_str):
        base = f"*{addr_str}"
    else:
        base = f"*({addr_str})"
    if not seg_str or seg_str == "ds":
        return base
    return f"*({seg_str}:{addr_str})"


def render_mop(mop, as_expression: bool = False) -> str:
    """Render a single microcode operand as a string.

    Args:
        mop: An ``ida_hexrays.mop_t`` operand.
        as_expression: Currently unused; reserved for future use.

    Returns:
        A human-readable string for the operand, or ``""`` for empty
        operands and ``"???"`` on errors.
    """
    if mop is None:
        return "???"

    try:
        mop_type = mop.t
    except Exception:
        return "???"

    # mop_z: empty operand
    if mop_type == ida_hexrays.mop_z:
        return ""

    # mop_r: register
    if mop_type == ida_hexrays.mop_r:
        try:
            name = ida_hexrays.get_mreg_name(mop.r, mop.size)
            if name:
                return name
            return f"reg{mop.r}"
        except Exception:
            return "???"

    # mop_n: immediate number
    if mop_type == ida_hexrays.mop_n:
        try:
            value = mop.nnn.value
            return _format_number(value)
        except Exception:
            return "???"

    # mop_d: sub-instruction result (render inline)
    if mop_type == ida_hexrays.mop_d:
        try:
            sub_ins = mop.d
            if sub_ins is not None:
                expr = render_insn_as_expr(sub_ins)
                return f"({expr})"
            return "???"
        except Exception:
            return "???"

    # mop_S: stack variable
    if mop_type == ida_hexrays.mop_S:
        try:
            s = mop.s
            if s is not None:
                off = s.off
                return f"var_{off:X}"
            return "var_?"
        except Exception:
            return "var_?"

    # mop_v: global variable
    if mop_type == ida_hexrays.mop_v:
        try:
            ea = mop.g
            name = ida_name.get_name(ea)
            if name:
                return name
            return f"$0x{ea:X}"
        except Exception:
            return "???"

    # mop_b: block reference
    if mop_type == ida_hexrays.mop_b:
        try:
            return f"LABEL_{mop.b}"
        except Exception:
            return "LABEL_?"

    # mop_f: call info (function call arguments)
    if mop_type == ida_hexrays.mop_f:
        try:
            f = mop.f
            if f is not None:
                args = getattr(f, "args", None)
                if args is not None:
                    rendered_args = []
                    for arg in args:
                        rendered_args.append(render_mop(arg))
                    return ", ".join(rendered_args)
            return ""
        except Exception:
            return "???"

    # mop_l: local variable
    if mop_type == ida_hexrays.mop_l:
        try:
            lv = mop.l
            if lv is not None:
                v = lv.var()
                if v is not None:
                    name = getattr(v, "name", None)
                    if name:
                        return name
            # Fallback to index
            idx = getattr(lv, "idx", None) if lv is not None else None
            if idx is not None:
                return f"lvar{idx}"
            return "lvar_?"
        except Exception:
            return "lvar_?"

    # mop_a: address of operand
    if mop_type == ida_hexrays.mop_a:
        try:
            inner = mop.a
            if inner is not None:
                return f"&({render_mop(inner)})"
            return "&(???)"
        except Exception:
            return "&(???)"

    # mop_h: helper function name
    if mop_type == ida_hexrays.mop_h:
        try:
            return mop.helper or "???"
        except Exception:
            return "???"

    # mop_str: string literal
    if mop_type == ida_hexrays.mop_str:
        try:
            return f'"{mop.cstr}"'
        except Exception:
            return '"???"'

    # mop_c: switch cases
    if mop_type == ida_hexrays.mop_c:
        try:
            return "cases(...)"
        except Exception:
            return "cases(?)"

    # mop_fn: floating point number
    if mop_type == ida_hexrays.mop_fn:
        try:
            fpc = mop.fpc
            value = getattr(fpc, "fnum", None)
            if value is None:
                value = getattr(fpc, "value", None)
            if value is not None:
                return str(value)
            return "float(?)"
        except Exception:
            return "float(?)"

    # mop_p: pair (high, low)
    if mop_type == ida_hexrays.mop_p:
        try:
            pair = mop.pair
            if pair is not None:
                lo = render_mop(getattr(pair, "lop", None))
                hi = render_mop(getattr(pair, "hop", None))
                return f"({hi}, {lo})"
            return "(?, ?)"
        except Exception:
            return "(?, ?)"

    # Unknown operand type: try dstr fallback
    try:
        return str(mop.dstr())
    except Exception:
        return "???"


# ---------------------------------------------------------------------------
# Instruction rendering (expression form, no assignment)
# ---------------------------------------------------------------------------

def render_insn_as_expr(ins) -> str:
    """Render a microcode instruction as an inline expression (no dest assignment).

    Used for ``mop_d`` sub-instructions where we need just the expression
    part, e.g. ``a + b`` rather than ``d = a + b``.

    Args:
        ins: An ``ida_hexrays.minsn_t`` instruction.

    Returns:
        A C-like expression string.
    """
    if ins is None:
        return "???"

    try:
        opcode = ins.opcode
    except Exception:
        return "???"

    # Binary operators
    if opcode in _BINARY_OPS:
        op = _BINARY_OPS[opcode]
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        return f"{l_str} {op} {r_str}"

    # Unary operators
    if opcode in _UNARY_OPS:
        prefix = _UNARY_OPS[opcode]
        l_str = render_mop(ins.l)
        return f"{prefix}{l_str}"

    # mov
    if opcode == ida_hexrays.m_mov:
        return render_mop(ins.l)

    # Sign-extend (xds)
    if opcode == ida_hexrays.m_xds:
        l_str = render_mop(ins.l)
        try:
            dest_size = ins.d.size if ins.d else 0
        except Exception:
            dest_size = 0
        type_name = _SIGNED_TYPE_BY_SIZE.get(dest_size, f"signed{dest_size * 8}")
        return f"({type_name}){l_str}"

    # Zero-extend (xdu)
    if opcode == ida_hexrays.m_xdu:
        l_str = render_mop(ins.l)
        try:
            dest_size = ins.d.size if ins.d else 0
        except Exception:
            dest_size = 0
        type_name = _UNSIGNED_TYPE_BY_SIZE.get(dest_size, f"unsigned{dest_size * 8}")
        return f"({type_name}){l_str}"

    # Truncate low part (low)
    if opcode == ida_hexrays.m_low:
        l_str = render_mop(ins.l)
        try:
            dest_size = ins.d.size if ins.d else 0
        except Exception:
            dest_size = 0
        type_name = _UNSIGNED_TYPE_BY_SIZE.get(dest_size, f"trunc{dest_size * 8}")
        return f"({type_name}){l_str}"

    # High part (high)
    if opcode == ida_hexrays.m_high:
        l_str = render_mop(ins.l)
        try:
            src_size = ins.l.size if ins.l else 0
            dest_size = ins.d.size if ins.d else 0
        except Exception:
            src_size = 0
            dest_size = 0
        shift_bits = (src_size - dest_size) * 8 if src_size > dest_size else 0
        type_name = _UNSIGNED_TYPE_BY_SIZE.get(dest_size, f"type{dest_size * 8}")
        if shift_bits > 0:
            return f"({type_name})({l_str} >> {shift_bits})"
        return f"({type_name}){l_str}"

    # Set-condition instructions
    if opcode in _SET_OPS:
        cmp = _SET_OPS[opcode]
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        return f"({l_str} {cmp} {r_str})"

    # Memory load (ldx)
    if opcode == ida_hexrays.m_ldx:
        seg = render_mop(ins.l)
        addr = render_mop(ins.r)
        return _format_memory_expr(seg, addr)

    # Memory store (stx) - as expression, just the value
    if opcode == ida_hexrays.m_stx:
        return render_mop(ins.l)

    # Call
    if opcode == ida_hexrays.m_call:
        l_str = render_mop(ins.l)
        args_str = render_mop(ins.d) if ins.d and ins.d.t == ida_hexrays.mop_f else ""
        return f"{l_str}({args_str})"

    # Indirect call
    if opcode == ida_hexrays.m_icall:
        l_str = render_mop(ins.l)
        args_str = render_mop(ins.d) if ins.d and ins.d.t == ida_hexrays.mop_f else ""
        return f"(*{l_str})({args_str})"

    # nop
    if opcode == ida_hexrays.m_nop:
        return "nop"

    # Fallback: try dstr
    try:
        return str(ins._print()).strip()
    except Exception:
        return "???"


# ---------------------------------------------------------------------------
# Instruction rendering (full statement form)
# ---------------------------------------------------------------------------

def render_insn(ins) -> str:
    """Render a single microcode instruction as a C-like statement.

    Args:
        ins: An ``ida_hexrays.minsn_t`` instruction.

    Returns:
        A C-like statement string (e.g. ``"eax = ebx + ecx"``).
    """
    if ins is None:
        return "// <null instruction>"

    try:
        opcode = ins.opcode
    except Exception:
        return "// <error reading opcode>"

    # Check for assert prefix
    prefix = ""
    try:
        if ins.is_assert():
            prefix = "/* assert */ "
    except Exception:
        pass

    # nop: skip
    if opcode == ida_hexrays.m_nop:
        return f"{prefix}/* nop */"

    # goto
    if opcode == ida_hexrays.m_goto:
        l_str = render_mop(ins.l)
        return f"{prefix}goto {l_str}"

    # return
    if opcode == ida_hexrays.m_ret:
        return f"{prefix}return"

    # Conditional jumps
    if opcode in _JCC_OPS:
        cmp = _JCC_OPS[opcode]
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        d_str = render_mop(ins.d)
        return f"{prefix}if ({l_str} {cmp} {r_str}) goto {d_str}"

    # Switch table
    if opcode == ida_hexrays.m_jtbl:
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        return f"{prefix}switch({l_str}) {{{r_str}}}"

    # Memory store (stx): *(seg:addr) = val
    if opcode == ida_hexrays.m_stx:
        val_str = render_mop(ins.l)
        seg_str = render_mop(ins.r)
        addr_str = render_mop(ins.d)
        return f"{prefix}{_format_memory_expr(seg_str, addr_str)} = {val_str}"

    # Call with destination
    if opcode == ida_hexrays.m_call:
        func_str = render_mop(ins.l)
        args_str = render_mop(ins.d) if ins.d and ins.d.t == ida_hexrays.mop_f else ""
        return f"{prefix}{func_str}({args_str})"

    # Indirect call
    if opcode == ida_hexrays.m_icall:
        func_str = render_mop(ins.l)
        args_str = render_mop(ins.d) if ins.d and ins.d.t == ida_hexrays.mop_f else ""
        return f"{prefix}(*{func_str})({args_str})"

    # mov: d = l
    if opcode == ida_hexrays.m_mov:
        l_str = render_mop(ins.l)
        d_str = render_mop(ins.d)
        if d_str:
            return f"{prefix}{d_str} = {l_str}"
        return f"{prefix}{l_str}"

    # Unary operators: d = OP l
    if opcode in _UNARY_OPS:
        op_prefix = _UNARY_OPS[opcode]
        l_str = render_mop(ins.l)
        d_str = render_mop(ins.d)
        if d_str:
            return f"{prefix}{d_str} = {op_prefix}{l_str}"
        return f"{prefix}{op_prefix}{l_str}"

    # Cast/extend operators: xds, xdu, low, high
    if opcode in (ida_hexrays.m_xds, ida_hexrays.m_xdu,
                  ida_hexrays.m_low, ida_hexrays.m_high):
        expr = render_insn_as_expr(ins)
        d_str = render_mop(ins.d)
        if d_str:
            return f"{prefix}{d_str} = {expr}"
        return f"{prefix}{expr}"

    # Binary operators: d = l OP r
    if opcode in _BINARY_OPS:
        op = _BINARY_OPS[opcode]
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        d_str = render_mop(ins.d)
        if d_str:
            return f"{prefix}{d_str} = {l_str} {op} {r_str}"
        return f"{prefix}{l_str} {op} {r_str}"

    # Set-condition instructions: d = (l CMP r)
    if opcode in _SET_OPS:
        cmp = _SET_OPS[opcode]
        l_str = render_mop(ins.l)
        r_str = render_mop(ins.r)
        d_str = render_mop(ins.d)
        if d_str:
            return f"{prefix}{d_str} = ({l_str} {cmp} {r_str})"
        return f"{prefix}({l_str} {cmp} {r_str})"

    # Memory load (ldx): d = *(seg:addr)
    if opcode == ida_hexrays.m_ldx:
        seg_str = render_mop(ins.l)
        addr_str = render_mop(ins.r)
        d_str = render_mop(ins.d)
        mem_expr = _format_memory_expr(seg_str, addr_str)
        if d_str:
            return f"{prefix}{d_str} = {mem_expr}"
        return f"{prefix}{mem_expr}"

    # Fallback: use the expression renderer and add destination
    expr = render_insn_as_expr(ins)
    d_str = render_mop(ins.d) if ins.d else ""
    if d_str and ins.d.t != ida_hexrays.mop_z:
        return f"{prefix}{d_str} = {expr}"
    return f"{prefix}{expr}"


# ---------------------------------------------------------------------------
# Block rendering
# ---------------------------------------------------------------------------

def render_block(blk) -> List[str]:
    """Render all instructions in a microcode block as pseudocode lines.

    Iterates over the linked list of ``minsn_t`` in *blk* (from ``blk.head``
    to ``blk.tail``) and produces one C-like line per instruction.

    Args:
        blk: An ``ida_hexrays.mblock_t`` block.

    Returns:
        A list of C-like statement strings, one per instruction.  Empty
        instructions (nop) are included as comments.
    """
    lines: List[str] = []
    if blk is None:
        return lines

    try:
        ins = blk.head
    except Exception:
        logger.debug("Failed to access blk.head")
        return lines

    while ins is not None:
        try:
            line = render_insn(ins)
            lines.append(line)
        except Exception:
            lines.append("// <render error>")
        try:
            ins = ins.next
        except Exception:
            break

    return lines


def render_branch_condition(blk) -> str:
    """Render the boolean condition of a 2-way block's conditional-jump tail.

    Returns the bare ``l CMP r`` expression (no ``if (...) goto``), for use as a
    ``ConditionRegion`` condition by the structurer. Falls back to ``"cond"``
    when the tail is not a recognized conditional jump.

    Args:
        blk: An ``ida_hexrays.mblock_t`` whose tail is a conditional jump.

    Returns:
        A C-like comparison string, e.g. ``"v52 == 0"``.
    """
    tail = getattr(blk, "tail", None) if blk is not None else None
    if tail is None:
        return "cond"
    try:
        opcode = tail.opcode
    except Exception:
        return "cond"
    if opcode in _JCC_OPS:
        return f"{render_mop(tail.l)} {_JCC_OPS[opcode]} {render_mop(tail.r)}"
    return "cond"


def render_block_str(blk) -> str:
    """Render a block as a single multi-line string.

    Convenience wrapper around :func:`render_block` that joins all lines
    with newline characters.

    Args:
        blk: An ``ida_hexrays.mblock_t`` block.

    Returns:
        A newline-separated string of all rendered instructions.
    """
    return "\n".join(render_block(blk))
