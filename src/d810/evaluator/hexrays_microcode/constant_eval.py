"""Local Hex-Rays microcode constant evaluation helpers."""

from __future__ import annotations

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.core.bits import get_parity_flag
from d810.evaluator.hexrays_microcode.def_search import find_def_in_block
from d810.hexrays.expr.ast import AstBase, AstLeaf, AstNode
from d810.hexrays.ir.mop_utils import mop_to_ast
from d810.hexrays.utils.hexrays_helpers import AND_TABLE, OPCODES_INFO

logger = getLogger(__name__)


def _get_mask(bits: int) -> int:
    """Return an integer mask for a byte size supported by Hex-Rays mops."""
    byte_size = bits // 8
    if byte_size <= 0:
        byte_size = 4
    elif byte_size not in AND_TABLE:
        if byte_size <= 1:
            byte_size = 1
        elif byte_size <= 2:
            byte_size = 2
        elif byte_size <= 4:
            byte_size = 4
        elif byte_size <= 8:
            byte_size = 8
        else:
            byte_size = 16
    return AND_TABLE[byte_size]


def _extract_constant_mop_value(mop: ida_hexrays.mop_t | None, bits: int) -> int | None:
    """Return the integer value when *mop* directly encodes a literal."""
    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value & _get_mask(bits)
    if mop.t == ida_hexrays.mop_f and getattr(mop, "f", None):
        args = mop.f.args
        if (
            args
            and len(args) >= 1
            and args[0] is not None
            and args[0].t == ida_hexrays.mop_n
        ):
            return args[0].nnn.value & _get_mask(bits)
    return None


def _constant_mov_value(ins: "ida_hexrays.minsn_t | None") -> int | None:
    if (
        ins is None
        or ins.opcode != ida_hexrays.m_mov
        or ins.l is None
        or ins.l.t != ida_hexrays.mop_n
    ):
        return None
    return int(ins.l.nnn.value)


def _mop_lvar_index_and_offset(mop: "ida_hexrays.mop_t") -> tuple[int, int] | None:
    try:
        lvar = mop.l
        return int(lvar.idx), int(lvar.off)
    except Exception:
        return None


def _wide_chunk_offset(
    base: "ida_hexrays.mop_t",
    chunk: "ida_hexrays.mop_t",
) -> int | None:
    """Return the byte offset when *chunk* writes part of *base*."""
    if chunk is None or getattr(chunk, "size", 0) <= 0:
        return None
    if int(chunk.size) > int(getattr(base, "size", 0) or 0):
        return None

    if base.t == ida_hexrays.mop_r and chunk.t == ida_hexrays.mop_r:
        try:
            offset = int(chunk.r) - int(base.r)
        except Exception:
            return None
        if 0 <= offset and offset + int(chunk.size) <= int(base.size):
            return offset
        return None

    if base.t == ida_hexrays.mop_l and chunk.t == ida_hexrays.mop_l:
        base_ref = _mop_lvar_index_and_offset(base)
        chunk_ref = _mop_lvar_index_and_offset(chunk)
        if base_ref is None or chunk_ref is None:
            return None
        base_idx, base_off = base_ref
        chunk_idx, chunk_off = chunk_ref
        if base_idx != chunk_idx:
            return None
        offset = chunk_off - base_off
        if 0 <= offset and offset + int(chunk.size) <= int(base.size):
            return offset
        return None

    if base.t == ida_hexrays.mop_S and chunk.t == ida_hexrays.mop_S:
        try:
            offset = int(chunk.s.off) - int(base.s.off)
        except Exception:
            return None
        if 0 <= offset and offset + int(chunk.size) <= int(base.size):
            return offset
        return None

    return None


def _resolve_wide_constant_mop(
    mop: "ida_hexrays.mop_t",
    bits: int,
    blk: "ida_hexrays.mblock_t | None",
    ins: "ida_hexrays.minsn_t | None",
) -> int | None:
    """Resolve a wide register/local/stack scalar from adjacent constant chunks."""
    if blk is None or ins is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    if size <= 8 or bits < size * 8:
        return None
    if mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_l, ida_hexrays.mop_S):
        return None

    chunks: dict[int, tuple[int, int]] = {}
    cur = ins.prev
    while cur is not None:
        dst = getattr(cur, "d", None)
        offset = _wide_chunk_offset(mop, dst)
        if offset is not None and offset not in chunks:
            value = _constant_mov_value(cur)
            if value is None:
                return None
            chunks[offset] = (int(value), int(dst.size))

        covered = 0
        while covered < size and covered in chunks:
            covered += chunks[covered][1]
        if covered >= size:
            result = 0
            for chunk_offset, (value, chunk_size) in chunks.items():
                mask = (1 << (chunk_size * 8)) - 1
                result |= (value & mask) << (chunk_offset * 8)
            return result & _get_mask(bits)

        cur = cur.prev

    return None


def _fold(op: int, a: int, b: int, bits: int) -> int | None:
    mask = _get_mask(bits)
    if op == ida_hexrays.m_add:
        return (a + b) & mask
    if op == ida_hexrays.m_ofadd:
        return (a + b) & mask
    if op == ida_hexrays.m_sub:
        return (a - b) & mask
    if op == ida_hexrays.m_mul:
        return (a * b) & mask
    if op == ida_hexrays.m_and:
        return (a & b) & mask
    if op == ida_hexrays.m_or:
        return (a | b) & mask
    if op == ida_hexrays.m_xor:
        return (a ^ b) & mask
    if op == ida_hexrays.m_shl:
        return (a << b) & mask
    if op == ida_hexrays.m_shr:
        return (a >> b) & mask
    if op == ida_hexrays.m_sar:
        a &= mask
        if a & (1 << (bits - 1)):
            a -= 1 << bits
        return (a >> b) & mask
    if op == ida_hexrays.m_setp:
        nb_bytes = bits // 8 if bits else 1
        return 1 if get_parity_flag(a, b, nb_bytes) else 0

    _mcode_op: dict[str, typing.Any] = OPCODES_INFO[op]
    logger.error(
        "[constant_eval] unknown opcode: %s with args: %s %s and bits: %s",
        _mcode_op["name"],
        a,
        b,
        bits,
    )
    return None


def eval_subtree(
    ast: AstBase | None,
    bits: int,
    blk: "ida_hexrays.mblock_t | None" = None,
    ins: "ida_hexrays.minsn_t | None" = None,
) -> int | None:
    """Return an integer if *ast* is locally provable as constant."""
    if ast is None:
        return None

    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        mop = ast.mop
        if mop is None:
            return None

        const_val = _extract_constant_mop_value(mop, bits)
        if const_val is not None:
            return const_val

        if (
            mop.t == ida_hexrays.mop_d
            and mop.d is not None
            and mop.d.opcode == ida_hexrays.m_ldc
        ):
            ldc_src = mop.d.l
            if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
                return ldc_src.nnn.value & _get_mask(bits)

        if (
            mop.t == ida_hexrays.mop_d
            and mop.d is not None
            and mop.d.opcode == ida_hexrays.m_call
        ):
            dst_mop = getattr(mop.d, "d", None)
            if dst_mop is not None and dst_mop.t == ida_hexrays.mop_n:
                return dst_mop.nnn.value & _get_mask(bits)

        if (
            blk is not None
            and ins is not None
            and mop.t in (ida_hexrays.mop_S, ida_hexrays.mop_r, ida_hexrays.mop_l)
        ):
            try:
                wide_value = _resolve_wide_constant_mop(mop, bits, blk, ins)
                if wide_value is not None:
                    return wide_value

                def_ins = find_def_in_block(mop, blk, ins)
                if def_ins is not None:
                    if (
                        def_ins.opcode == ida_hexrays.m_mov
                        and def_ins.l is not None
                        and def_ins.l.t == ida_hexrays.mop_n
                    ):
                        return def_ins.l.nnn.value & _get_mask(bits)

                    if def_ins.opcode == ida_hexrays.m_mov and def_ins.l is not None:
                        src_ast = mop_to_ast(def_ins.l)
                        if src_ast is not None:
                            resolved = eval_subtree(src_ast, bits, blk=blk, ins=def_ins)
                            if resolved is not None:
                                return resolved
            except Exception:
                pass

        return None

    assert ast.is_node()
    ast = typing.cast(AstNode, ast)
    if ast.right is None:
        if ast.opcode in (ida_hexrays.m_low, ida_hexrays.m_high):
            source_bits = bits * 2
            if ast.left is not None and getattr(ast.left, "dest_size", None):
                source_bits = max(source_bits, int(ast.left.dest_size) * 8)
            val = eval_subtree(ast.left, source_bits, blk=blk, ins=ins)
            if val is None:
                return None
            if ast.opcode == ida_hexrays.m_low:
                return val & _get_mask(bits)
            return (val >> bits) & _get_mask(bits)

        val = eval_subtree(ast.left, bits, blk=blk, ins=ins)
        if val is None:
            return None
        if ast.opcode == ida_hexrays.m_neg:
            return (-val) & _get_mask(bits)
        if ast.opcode == ida_hexrays.m_bnot:
            return (~val) & _get_mask(bits)
        if ast.left and ast.left.dest_size:
            if ast.opcode == ida_hexrays.m_xds:
                left_bits = ast.left.dest_size * 8
                val = eval_subtree(ast.left, left_bits, blk=blk, ins=ins)
                if val is None:
                    return None
                mask = _get_mask(bits)
                sign_bit = 1 << (left_bits - 1)
                if val & sign_bit:
                    val |= ~((1 << left_bits) - 1) & mask
                return val & mask
            if ast.opcode == ida_hexrays.m_xdu:
                left_bits = (
                    ast.left.dest_size * 8
                    if getattr(ast.left, "dest_size", None)
                    else bits
                )
                val = eval_subtree(ast.left, left_bits, blk=blk, ins=ins)
                if val is None:
                    return None
                return val & _get_mask(bits)
        return None

    l = eval_subtree(ast.left, bits, blk=blk, ins=ins)  # type: ignore[arg-type]
    r = eval_subtree(ast.right, bits, blk=blk, ins=ins)  # type: ignore[arg-type]
    if l is None or r is None:
        return None

    if ast.opcode == ida_hexrays.m_call and ast.func_name:
        helper_name = ast.func_name.lstrip("!")
        mask = (1 << bits) - 1
        shift = r % bits
        if helper_name.startswith("__ROL"):
            return ((l << shift) | (l >> (bits - shift))) & mask
        if helper_name.startswith("__ROR"):
            return ((l >> shift) | (l << (bits - shift))) & mask
        logger.error(
            "[constant_eval] unknown rotate helper: %s with args: %s %s and bits: %s",
            helper_name,
            l,
            r,
            bits,
        )
        return None
    return _fold(ast.opcode, l, r, bits)


def eval_mop(
    mop: "ida_hexrays.mop_t | None",
    bits: int,
    blk: "ida_hexrays.mblock_t | None" = None,
    ins: "ida_hexrays.minsn_t | None" = None,
) -> int | None:
    """Return an integer if *mop* is locally provable as constant."""
    if mop is None:
        return None
    ast = mop_to_ast(mop)
    if ast is None:
        return None
    return eval_subtree(ast, bits, blk=blk, ins=ins)
