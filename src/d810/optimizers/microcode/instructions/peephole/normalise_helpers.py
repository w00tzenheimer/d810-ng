from __future__ import annotations

import functools

import ida_hexrays

from d810.core import typing
from d810.core import CacheImpl
from d810.core import getLogger
from d810.core.bits import get_parity_flag
from d810.expr.ast import AstBase, AstLeaf, AstNode, mop_to_ast
from d810.hexrays.hexrays_formatters import (  # noqa: F401 - debug only
    format_mop_t,
    mop_type_to_string,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import (  # already maps size→mask
    AND_TABLE,
    CONTROL_FLOW_OPCODES,
    OPCODES_INFO,
    is_rotate_helper_call,
)
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)


class TransparentCallUnwrapRule(PeepholeSimplificationRule):
    DESCRIPTION = (
        "Unwrap helper calls whose result is stored in their destination expression"
    )
    """
        m_call  l=<helper>  r=<empty>  d=<mop_d expr>

    by the expression stored in *d*.  This turns a value-only helper
    (often emitted by the decompiler for things like casts or wrappers
    around compiler intrinsics) into the real micro-instruction so that
    subsequent passes do not need to care.
    """

    DESCRIPTION = "Unwrap helper calls whose result is directly stored in their destination expression"

    # Run *very* early so that the AST builder never sees the wrapper.
    maturities = [
        # ida_hexrays.MMAT_CALLS,
        # ida_hexrays.MMAT_GLBOPT1,
    ]

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:  # noqa: D401
        """Return a replacement `minsn_t` or None to keep *ins* unchanged."""

        if logger.debug_on:
            logger.debug(
                "[transparent-call] considering ea=%X, opcode=%s l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                format_mop_t(ins.l),
                format_mop_t(ins.r),
                format_mop_t(ins.d),
            )

        # Pattern match -----------------------------------------------------------------
        if ins.opcode != ida_hexrays.m_call:
            return None

        # We only consider *transparent* helpers: no argument list (r is None or mop_z)
        if ins.r is not None and ins.r.t != ida_hexrays.mop_z:
            return None

        # Destination must be a mop_d wrapping an *expression* (another minsn_t)
        if ins.d is None or ins.d.t != ida_hexrays.mop_d or ins.d.d is None:
            return None

        inner: ida_hexrays.minsn_t = typing.cast(ida_hexrays.minsn_t, ins.d.d)

        # Extra guard: do *not* unwrap rotate helper calls - another rule handles them
        if is_rotate_helper_call(inner):
            return None
        # ------------------------------------------------------------------
        # There is no public Python API to *deep-copy* a minsn_t, but Ida's
        # C++ bindings expose the copy-constructor through normal assignment
        # semantics:  new_ins = ida_hexrays.minsn_t(other).  Empirically this
        # produces a full, independent copy.
        # ------------------------------------------------------------------
        new_ins = ida_hexrays.minsn_t(inner)  # type: ignore[arg-type]

        # Preserve the original EA so xrefs / logging stay consistent.
        new_ins.ea = ins.ea
        if logger.debug_on:
            logger.debug(
                "[transparent-call] 0x%X unwrap → %s",
                sanitize_ea(ins.ea),
                opcode_to_string(new_ins.opcode),
            )

        return new_ins


class TypedImmediateCanonicaliseRule(PeepholeSimplificationRule):
    """Turn the various typed-immediate wrappers produced by Hex-Rays into
    plain numeric constants (mop_n).  Handles two frequent patterns:

    - The typed immediate mop_f wrapper::

          <fast:_QWORD #0x42.8,char #4.1>.8

      which is represented as an *mop_f* whose *f.args[0]* is the real
      mop_n literal.

    - An *m_ldc* micro-instruction that loads a constant into a pseudo
      temporal destination - the source literal sits in the *l* operand.
      These appear inside nested expressions (eg. m_call wrappers).
    """

    DESCRIPTION = "Canonicalise typed immediates (mop_f) into plain mop_n literals"

    maturities = [
        # ida_hexrays.MMAT_CALLS,
        # ida_hexrays.MMAT_GLBOPT1,
    ]

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Replace *ins* when all it does is materialise a literal."""

        if logger.debug_on:
            logger.debug(
                "[typed-imm] considering ea=%X, opcode=%s l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                format_mop_t(ins.l),
                format_mop_t(ins.r),
                format_mop_t(ins.d),
            )

        # Skip rotate helper calls - they need special handling
        if is_rotate_helper_call(ins):
            return None

        # ------------------------------------------------------------------
        # Case A - Stand-alone m_ldc that simply moves a literal.
        # ------------------------------------------------------------------
        if (
            ins.opcode == ida_hexrays.m_ldc
            and ins.l is not None
            and ins.l.t == ida_hexrays.mop_n
        ):
            # Up-convert to the canonical representation used by the constant
            # folder:    m_ldc  l=<mop_n>   d=<original dst>  r=mop_z
            # Here the instruction is already in that form - nothing to do.
            return None  # keep as-is

        # ------------------------------------------------------------------
        # Case B - Instruction *operands* that wrap the literal in mop_f.
        #   We normalise *in-place* instead of emitting a new instruction to
        #   keep EA / control-flow untouched.
        # ------------------------------------------------------------------
        changed = False
        for op_name in ("l", "r", "d"):
            mop = getattr(ins, op_name, None)
            if (
                mop is not None
                and mop.t == ida_hexrays.mop_f
                and getattr(mop, "f", None)
            ):
                args = mop.f.args
                if (
                    args
                    and len(args) >= 1
                    and args[0] is not None
                    and args[0].t == ida_hexrays.mop_n
                ):
                    lit = args[0]
                    dup = ida_hexrays.mop_t()
                    dup.make_number(lit.nnn.value, lit.size)
                    setattr(ins, op_name, dup)
                    changed = True
        return ins if changed else None


"""
# Special handling for rotate calls
if mop.t == ida_hexrays.mop_d and _is_rotate_helper_call(mop.d):
    # Layout A: classic helper - arguments are in an mop_f list
    if mop.d.r.t == ida_hexrays.mop_f:
        args = mop.d.r.f.args
        if len(args) == 2 and args[0] is not None and args[1] is not None:
            value_ast = mop_to_ast_internal(args[0], context)
            shift_ast = mop_to_ast_internal(args[1], context)
            tree = AstNode(ida_hexrays.m_call, value_ast, shift_ast)
            tree.func_name = mop.d.l.helper
            tree.mop = mop
            tree.dest_size = mop.size
            tree.ea = sanitize_ea(mop.d.ea)
            new_index = len(context.unique_asts)
            tree.ast_index = new_index
            context.unique_asts.append(tree)
            context.mop_key_to_index[key] = new_index
            return tree
    # Layout B: compact helper - r is value, d is shift amount
    elif mop.d.r is not None and mop.d.d is not None:
        value_ast = mop_to_ast_internal(mop.d.r, context)
        shift_ast = mop_to_ast_internal(mop.d.d, context)
        if value_ast is not None and shift_ast is not None:
            tree = AstNode(ida_hexrays.m_call, value_ast, shift_ast)
            tree.func_name = mop.d.l.helper
            tree.mop = mop
            tree.dest_size = mop.size
            tree.ea = sanitize_ea(mop.d.ea)
            new_index = len(context.unique_asts)
            tree.ast_index = new_index
            context.unique_asts.append(tree)
            context.mop_key_to_index[key] = new_index
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Built compact rotate helper node for ea=0x%X",
                    mop.d.ea if hasattr(mop.d, "ea") else -1,
                )
            return tree
"""


# class RotateHelperInlineRule(PeepholeSimplificationRule):
#     """Replace `__ROL*` / `__ROR*` helper calls by explicit (shl, shr, or) tree.

#     This exposes the rotate to algebraic simplifications and constant
#     folding, removing the need for special-case handling in the AST
#     builder.
#     """

#     DESCRIPTION = "Inline ROL/ROR helper calls into shifts + or"
#     # maturities = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS]

#     @_compat.override
#     def check_and_replace(
#         self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
#     ) -> ida_hexrays.minsn_t | None:
#         if logger.debug_on:
#             logger.debug(
#                 "[RotateHelperInline] considering ea=%X, opcode=%s. is insn helper? %s  l=%s  r=%s",
#                 sanitize_ea(ins.ea),
#                 opcode_to_string(ins.opcode),
#                 is_rotate_helper_call(ins),
#                 format_mop_t(ins.l),
#                 format_mop_t(ins.r),
#             )
#         if not is_rotate_helper_call(ins):
#             return None

#         # Extract helper name and width from helper string (e.g., __ROL4__)
#         helper_name = (ins.l.helper or "").lstrip("!")
#         is_rol = helper_name.startswith("__ROL")

#         # Derive bit width from destination size if possible; fallback 32.
#         bits = (ins.d.size or 4) * 8 if ins.d else 32

#         # --------------------------------------------------------------
#         # Gather operands depending on layout.
#         # Layout A: argument list in mop_f.
#         # Layout B: r == value, d == shift
#         # --------------------------------------------------------------
#         # For rotate helpers, arguments are in ins.r as mop_f
#         func_mop = None
#         if (
#             ins.r is not None
#             and ins.r.t == ida_hexrays.mop_f
#             and getattr(ins.r, "f", None)
#         ):
#             func_mop = ins.r

#         if func_mop:
#             args = func_mop.f.args
#             if len(args) < 2 or args[0] is None or args[1] is None:
#                 return None
#             val_mop = dup_mop(args[0])
#             sh_mop = dup_mop(args[1])
#         else:
#             # compact form
#             val_mop = dup_mop(ins.r)
#             sh_mop = dup_mop(ins.d)
#             if val_mop is None or sh_mop is None:
#                 return None
#         # Build (bits - shift) expression:  sub_ins
#         bits_const = ida_hexrays.mop_t()
#         bits_const.make_number(bits, (bits // 8) if bits // 8 in AND_TABLE else 4)
#         sub_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
#         sub_ins.opcode = ida_hexrays.m_sub
#         sub_ins.l = bits_const
#         sub_ins.r = dup_mop(sh_mop)
#         sub_mop = ida_hexrays.mop_t()
#         sub_mop.create_from_insn(sub_ins)

#         val_mop_for_shl = (
#             ida_hexrays.mop_t()
#             if val_mop and val_mop.t == ida_hexrays.mop_d
#             else dup_mop(val_mop)
#         )
#         if val_mop and val_mop.t == ida_hexrays.mop_d:
#             val_mop_for_shl.t = ida_hexrays.mop_d
#             val_mop_for_shl.d = ida_hexrays.minsn_t(val_mop.d)
#             val_mop_for_shl.size = val_mop.size

#         val_mop_for_shr = (
#             ida_hexrays.mop_t()
#             if val_mop and val_mop.t == ida_hexrays.mop_d
#             else dup_mop(val_mop)
#         )
#         if val_mop and val_mop.t == ida_hexrays.mop_d:
#             val_mop_for_shr.t = ida_hexrays.mop_d
#             val_mop_for_shr.d = ida_hexrays.minsn_t(val_mop.d)
#             val_mop_for_shr.size = val_mop.size

#         # Build left shift: val << sh
#         shl_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
#         shl_ins.opcode = ida_hexrays.m_shl
#         shl_ins.l = val_mop_for_shl
#         shl_ins.r = dup_mop(sh_mop)
#         shl_mop = ida_hexrays.mop_t()
#         shl_mop.create_from_insn(shl_ins)

#         # Build right shift (direction depends on rol/ror)
#         shift_opcode = ida_hexrays.m_shr if is_rol else ida_hexrays.m_shl
#         shr_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
#         shr_ins.opcode = shift_opcode
#         shr_ins.l = val_mop_for_shr
#         shr_ins.r = sub_mop
#         shr_mop = ida_hexrays.mop_t()
#         shr_mop.create_from_insn(shr_ins)

#         # Build final or
#         or_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
#         or_ins.opcode = ida_hexrays.m_or
#         or_ins.l = shl_mop
#         or_ins.r = shr_mop

#         # # Destination: keep original l-value when legal
#         # or_ins.d = ida_hexrays.mop_t()
#         # if ins.d and ins.d.t in {
#         #     ida_hexrays.mop_r,
#         #     ida_hexrays.mop_l,
#         #     ida_hexrays.mop_S,
#         #     ida_hexrays.mop_v,
#         # }:
#         #     or_ins.d.assign(ins.d)
#         # else:
#         #     or_ins.d.erase()
#         # or_ins.d.size = ins.d.size if ins.d else (bits // 8)

#         # Destination: copy the mov‐dest (ins.r) into our new OR‐insn
#         or_ins.r = shr_mop  # temporarily set to something of the right type…
#         or_ins.r.assign(ins.r)
#         or_ins.r.size = ins.r.size

#         # ensure sizes propagate to l/r when they are mop_t (not mop_d)
#         if or_ins.l.t != ida_hexrays.mop_d and or_ins.l.size == 0:
#             or_ins.l.size = or_ins.d.size
#         if or_ins.r.t != ida_hexrays.mop_d and or_ins.r.size == 0:
#             or_ins.r.size = or_ins.d.size

#         # Return brand-new instruction – do not modify *ins* in place.
#         if logger.debug_on:
#             logger.debug(
#                 "[rotate-inline] 0x%X %s inlined into or/shl/shr → %s",
#                 sanitize_ea(ins.ea),
#                 helper_name,
#                 format_minsn_t(or_ins),
#             )
#         return or_ins


# ────────────────────────────────────────────────────────────────────
# Lightweight cache for expensive mop→str conversions (debug only).
# Uses the generic, thread-safe CacheImpl already available in hexrays_helpers
# (bounded LRU by default, max 256 entries).
_MOP_STR_CACHE: CacheImpl[tuple[int, int], str] = CacheImpl(max_size=256)

# ────────────────────────────────────────────────────────────────────
# Debug helpers
# ────────────────────────────────────────────────────────────────────


def _mop_to_str(mop: "ida_hexrays.mop_t | None") -> str:  # noqa: ANN001
    """Return a compact readable string for *mop* suitable for debug logs."""

    if mop is None:
        return "<None>"
    # Fast cache: avoid calling into C++ pretty-printer for the same mop_t
    key = (id(mop), getattr(mop, "valnum", 0))
    try:
        return _MOP_STR_CACHE[key]
    except KeyError:
        pass

    try:
        res = format_mop_t(mop)
        _MOP_STR_CACHE[key] = res
        return res
    except Exception:  # pragma: no cover - logging helper, be robust
        try:
            res = str(mop.dstr())
            _MOP_STR_CACHE[key] = res
            return res
        except Exception:
            logger.error(
                "[fold_const] [_mop_to_str] Error formatting mop, fall: %s", mop
            )
            res = f"<mop_t t={getattr(mop,'t',None)} size={getattr(mop,'size',None)}>"
            _MOP_STR_CACHE[key] = res
            return res


COMMUTATIVE = {
    ida_hexrays.m_add,
    ida_hexrays.m_mul,
    ida_hexrays.m_xor,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
}


def _extract_constant_mop_value(mop: ida_hexrays.mop_t | None, bits: int) -> int | None:
    """Return integer value if *mop* ultimately represents a numeric constant.

    Handles regular `mop_n` as well as the `mop_f` wrappers produced by
    Hex-Rays for typed immediates such as
        <fast:_DWORD #0xDEADBEEF.4,char #4.1>.4
    which encodes the same constant in `f.args[0]`.
    """
    if mop is None:
        return None

    # Plain numeric constant (fast path)
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value & _get_mask(bits)

    # Typed immediate packed in an `mop_f` (func-like wrapper)
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


def _get_mask(bits):
    """Safely get mask from AND_TABLE with bounds checking"""
    byte_size = bits // 8
    # Valid keys in AND_TABLE are {1, 2, 4, 8, 16}
    if byte_size <= 0:
        byte_size = 4  # Default to 32-bit
    elif byte_size not in AND_TABLE:
        # Round up to next valid size
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


def _fold_bottom_up(ast: AstBase, bits) -> tuple[AstBase, bool]:
    """
    Constant-fold every binary/unary node whose children are constants.
    Returns (new_node, changed?).
    """
    changed = False

    # leaves
    if ast.is_leaf():
        return ast, False
    ast = typing.cast(AstNode, ast)

    # recurse first
    if ast.left is not None:
        new_left, ch_left = _fold_bottom_up(ast.left, bits)
        if ch_left:
            ast.left = new_left
            changed = True
    if ast.right is not None:
        new_right, ch_right = _fold_bottom_up(ast.right, bits)
        if ch_right:
            ast.right = new_right
            changed = True

    # now try to collapse this node
    if ast.right is None:
        val = _eval_subtree(ast, bits)
        if val is not None:
            leaf = AstLeaf(val)  # tiny helper; see below
            leaf.mop = ida_hexrays.mop_t()
            leaf.mop.make_number(val, bits // 8)
            return leaf, True
    elif ast.left is not None and ast.right is not None:
        lval = _eval_subtree(ast.left, bits)
        rval = _eval_subtree(ast.right, bits)
        if lval is not None and rval is not None:
            val = _fold(ast.opcode, lval, rval, bits)
            leaf = AstLeaf(val)
            leaf.mop = ida_hexrays.mop_t()
            leaf.mop.make_number(val, bits // 8)
            return leaf, True

    return ast, changed


def _fold(op, a, b, bits):
    mask = _get_mask(bits)
    if op == ida_hexrays.m_add:
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
        mask = _get_mask(bits)
        a &= mask
        if a & (1 << (bits - 1)):
            a -= 1 << bits
        return (a >> b) & mask
    if op == ida_hexrays.m_setp:
        # Parity flag is set when low-byte of (a - b) has even parity (PF=1 → result 1)
        nb_bytes = bits // 8 if bits else 1
        return 1 if get_parity_flag(a, b, nb_bytes) else 0

    _mcode_op: dict[str, typing.Any] = OPCODES_INFO[op]
    logger.error(
        "[fold_const] [_fold] Unknown opcode: %s with args: %s %s and bits: %s",
        _mcode_op["name"],
        a,
        b,
        bits,
    )
    return None


def _eval_subtree(ast: AstBase | None, bits) -> int | None:
    """returns an int if subtree is constant, else None"""
    if ast is None:
        if logger.debug_on:
            logger.debug("[fold_const] [_eval_subtree] ast is None - cannot evaluate")
        return None

    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        mop = ast.mop
        if mop is None:
            if logger.debug_on:
                logger.debug("[fold_const] [_eval_subtree] Leaf with no mop: %s", ast)
            return None

        # Unified constant extraction (handles mop_n and wrapped constants)
        const_val = _extract_constant_mop_value(mop, bits)
        if const_val is not None:
            return const_val

        # Hex-Rays sometimes represents a literal as a one-instruction
        # subtree:   mop_d → m_ldc  ( ldc  #value , dst )
        if (
            mop.t == ida_hexrays.mop_d
            and mop.d is not None
            and mop.d.opcode == ida_hexrays.m_ldc
        ):
            ldc_src = mop.d.l
            if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
                return ldc_src.nnn.value & _get_mask(bits)

        # Helper call already folded by Hex-Rays:  m_call with constant destination
        # Example pattern in log:  l=!__ROL4__  r=<empty>  d=<mop_n  #const>
        if (
            mop.t == ida_hexrays.mop_d
            and mop.d is not None
            and mop.d.opcode == ida_hexrays.m_call
        ):
            dst_mop = getattr(mop.d, "d", None)
            if dst_mop is not None and dst_mop.t == ida_hexrays.mop_n:
                return dst_mop.nnn.value & _get_mask(bits)
        return None

    # unary
    assert ast.is_node()
    ast = typing.cast(AstNode, ast)
    if ast.right is None:
        ast = typing.cast(AstNode, ast)
        val = _eval_subtree(ast.left, bits)
        if val is None:
            return None
        if ast.opcode == ida_hexrays.m_neg:
            return (-val) & _get_mask(bits)
        if ast.opcode == ida_hexrays.m_bnot:
            return (~val) & _get_mask(bits)
        # Extract low/high half-words
        if ast.opcode == ida_hexrays.m_low:
            return val & _get_mask(bits)
        if ast.opcode == ida_hexrays.m_high:
            return (val >> bits) & _get_mask(bits)
        if ast.left and ast.left.dest_size:
            if ast.opcode == ida_hexrays.m_xds:
                left_bits = ast.left.dest_size * 8
                val = _eval_subtree(ast.left, left_bits)
                if val is None:
                    return None
                mask = _get_mask(bits)
                sign_bit = 1 << (left_bits - 1)
                if val & sign_bit:
                    val |= ~((1 << left_bits) - 1) & mask
                return val & mask
            if ast.opcode == ida_hexrays.m_xdu:
                # Zero-extend: just mask the underlying value to the destination size
                left_bits = (
                    ast.left.dest_size * 8
                    if getattr(ast.left, "dest_size", None)
                    else bits
                )
                val = _eval_subtree(ast.left, left_bits)
                if val is None:
                    return None
                return val & _get_mask(bits)
        return None

    # binary
    l = _eval_subtree(ast.left, bits)  # type: ignore
    r = _eval_subtree(ast.right, bits)  # type: ignore
    if l is None or r is None:
        if logger.debug_on:
            logger.debug(
                "[fold_const] [_eval_subtree] Cannot evaluate binary node (%s) because %s is None",
                opcode_to_string(ast.opcode),
                "left" if l is None else "right",
            )
        return None

    # special handling for rotate calls
    if ast.opcode == ida_hexrays.m_call and ast.func_name:
        if logger.debug_on:
            logger.debug(
                "[fold_const] [_eval_subtree] opcode == mcall, func_name: %s",
                ast.func_name,
            )
        helper_name = ast.func_name.lstrip("!")
        mask = (1 << bits) - 1
        shift = r % bits
        if helper_name.startswith("__ROL"):
            return ((l << shift) | (l >> (bits - shift))) & mask
        elif helper_name.startswith("__ROR"):
            return ((l >> shift) | (l << (bits - shift))) & mask
        # if needed, handle specific widths or other variants
        logger.error(
            "[fold_const] [_eval_subtree] Unknown width for rotate call: %s with args: %s %s and bits: %s",
            helper_name,
            l,
            r,
            bits,
        )
        return None
    return _fold(ast.opcode, l, r, bits)  # type: ignore


class FoldPureConstantRule:  # (PeepholeSimplificationRule):
    DESCRIPTION = (
        "Collapse any instruction whose whole expression "
        "is a compile-time constant into a single m_ldc"
    )

    # maturities = [
    #     ida_hexrays.MMAT_GLBOPT2,
    # ]

    # Class-level sentinel so multiple instances of the rule share it.
    _last_mba_id: set[int] = set()

    # @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:

        if blk is None:
            logger.debug(
                "[fold_const] blk is None, ins @ 0x%X with opcode: %s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
            )

        # Skip flow-control instructions that can never be folded to a constant.
        if ins.opcode in CONTROL_FLOW_OPCODES:
            logger.debug("[fold_const] Skipping control flow instruction")
            return None

        # Flush caches whenever we get a new mba.
        if blk is not None:
            if id(blk.mba) not in self._last_mba_id:
                logger.debug("[fold_const] New MBA detected! %s", id(blk.mba))
                self._last_mba_id.add(id(blk.mba))
                _MOP_STR_CACHE.clear()
            else:
                logger.debug("[fold_const] Previous MBA detected! %s", id(blk.mba))

        # Skip instructions that are already in optimal form or would cause infinite loops
        if ins.opcode == ida_hexrays.m_ldc:
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Skipping m_ldc instruction (already optimal)"
                )
            return None

        # Skip mov instructions where source is already a constant (prevents infinite loop)
        if ins.opcode == ida_hexrays.m_mov and ins.l and ins.l.t == ida_hexrays.mop_n:
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Skipping mov with constant source (would create infinite loop)"
                )
            return None

        # Skip binary operations where both operands are already constants
        # (these should be folded to ldc, but if we see them repeatedly, skip to prevent loops)
        if (
            ins.l
            and ins.l.t == ida_hexrays.mop_n
            and ins.r
            and ins.r.t == ida_hexrays.mop_n
            and ins.opcode
            in [
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
            ]
        ):
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Skipping binary op with two constants (would create infinite loop)"
                )
            return None

        # Skip identity operations that don't need folding
        if ins.l and ins.r:
            # add/sub with 0, or/xor with 0, and with -1, mul/div with 1
            if (
                ins.r.t == ida_hexrays.mop_n
                and ins.r.nnn
                and (
                    (
                        ins.opcode
                        in [
                            ida_hexrays.m_add,
                            ida_hexrays.m_sub,
                            ida_hexrays.m_or,
                            ida_hexrays.m_xor,
                        ]
                        and ins.r.nnn.value == 0
                    )
                    or (
                        ins.opcode == ida_hexrays.m_and
                        and ins.r.nnn.value == 0xFFFFFFFFFFFFFFFF
                    )
                    or (
                        ins.opcode
                        in [ida_hexrays.m_mul, ida_hexrays.m_udiv, ida_hexrays.m_sdiv]
                        and ins.r.nnn.value == 1
                    )
                )
            ):
                if logger.debug_on:
                    logger.debug(
                        "[fold_const] Skipping identity operation (should be handled by other rules)"
                    )
                return None

        # Accept additional destination kinds (mop_z = no explicit l-value, mop_f =
        # typed-immediate wrapper).  We can still safely fold those as long as we
        # rebuild a *valid* destination operand below.
        if ins.d is None or ins.d.t not in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
            ida_hexrays.mop_z,  # value-only expression (nested tree)
            ida_hexrays.mop_f,  # typed immediate
            ida_hexrays.mop_d,  # destination is an expression (will be erased)
        }:
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Skipping instruction @ 0x%X with invalid destination: (opcode=%s) (ins.d.t=%s) -- dstr=%s",
                    sanitize_ea(ins.ea),
                    opcode_to_string(ins.opcode),
                    mop_type_to_string(ins.d.t),
                    ins.dstr(),
                )
            return None

        bits = ins.d.size * 8 if ins.d.size else 32
        if logger.debug_on:
            logger.debug(
                "[fold_const] Checking ins @ 0x%X (opcode=%s) l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                _mop_to_str(ins.l),
                _mop_to_str(ins.r),
                _mop_to_str(ins.d),
            )

        # Ensure bits is valid and positive
        if bits <= 0:
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Invalid bits value %d, defaulting to 32", bits
                )
            bits = 32

        # Clamp bits to supported sizes to prevent KeyError in AND_TABLE
        if bits not in [8, 16, 32, 64]:
            # Round up to next supported size
            if bits <= 8:
                bits = 8
            elif bits <= 16:
                bits = 16
            elif bits <= 32:
                bits = 32
            else:
                bits = 64
            if logger.debug_on:
                logger.debug("[fold_const] Adjusted bits to supported size: %d", bits)

        # Try to collapse the *whole* instruction tree.
        # Build AST from just the computation (left and right operands), not the destination
        if ins.opcode == ida_hexrays.m_mov:
            # For mov, evaluate the source operand
            ast = mop_to_ast(ins.l)
        else:
            # For binary operations, build AST from the operation itself
            left_ast = mop_to_ast(ins.l) if ins.l is not None else None
            # Treat mop_z ("empty" operand) as an absent right operand for
            # genuine unary instructions such as xds, xdu, low, high, neg,
            # lnot and bnot.  Hex-Rays represents these as binary-like
            # instructions where the unused operand is a mop_z placeholder.
            # If we keep that placeholder as a real AST leaf the folding
            # engine will mis-classify the instruction as binary and fail to
            # evaluate it.  Detect the pattern early and consider the right
            # operand logically absent.

            right_ast: AstBase | None
            if ins.r is not None and ins.r.t == ida_hexrays.mop_z:
                right_ast = None
            else:
                right_ast = mop_to_ast(ins.r) if ins.r is not None else None

            if left_ast is None and right_ast is None:
                ast = None
            elif right_ast is None:
                # Unary operation
                ast = AstNode(ins.opcode, left_ast)
                ast.dest_size = ins.d.size
                ast.ea = ins.ea
            else:
                # Binary operation
                ast = AstNode(ins.opcode, left_ast, right_ast)
                ast.dest_size = ins.d.size
                ast.ea = ins.ea

        if ast is not None:
            if logger.debug_on:
                logger.debug("[fold_const] AST for ins: %s", ast)
            value = _eval_subtree(ast, bits)
            if logger.debug_on:
                logger.debug("[fold_const] _eval_subtree result: %r", value)
            if value is not None:
                logger.info(
                    "[fold_const] Collapsed ins at 0x%X to constant 0x%X (opcode=%s)",
                    sanitize_ea(ins.ea),
                    value,
                    opcode_to_string(ins.opcode),
                )
                # Build a *fresh* m_ldc instruction rather than mutating a clone of
                # the old one.  Re-using the old `minsn_t` can leave garbage in
                # opcode-specific union fields, which has been observed to crash IDA
                # during later optimisation passes.

                new = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
                new.opcode = ida_hexrays.m_ldc

                # ------------------------------------------------------------------
                # SAFETY: `make_number` expects a *valid* byte size (1,2,4,8,16…).
                # Some micro-instructions have their `d.size` field set to 0 which
                # causes Hex-Rays to crash deep in the C++ layer when we pass it
                # through blindly.  Guard against that by falling back to 4-byte
                # integers if we detect an invalid/zero size.
                # ------------------------------------------------------------------
                size_bytes = 4  # sensible default (32-bit)
                if ins.d and ins.d.size in (1, 2, 4, 8, 16):
                    size_bytes = ins.d.size

                cst = ida_hexrays.mop_t()
                cst.make_number(value, size_bytes)
                new.l = cst

                # Destination operand: keep the *original* one (register, stack var…)
                # but clone it to detach from the existing microcode tree.
                if ins.d:
                    new.d = ida_hexrays.mop_t()

                    # Only copy the original destination when it is a *true* l-value
                    # (register, stack var, global var, heap var).  Expression
                    # destinations such as `mop_f` (typed immediates) or `mop_d`
                    # (nested instruction) are *not* valid for an `m_ldc` and will
                    # fail microcode verification.  In those cases we instead keep
                    # a pure value-only destination by erasing the operand, which
                    # turns it into a genuine `mop_z`.
                    if ins.d.t in {
                        ida_hexrays.mop_r,  # register
                        ida_hexrays.mop_l,  # local stack var
                        ida_hexrays.mop_S,  # global/static var
                        ida_hexrays.mop_v,  # heap (global) var
                    }:
                        # Copy and normalise size
                        new.d.assign(ins.d)
                        new.d.size = size_bytes
                    else:
                        # Any other destination kind: produce a value-only mop_z but
                        # keep size in sync so validation helpers do not complain.
                        new.d.erase()
                        new.d.size = size_bytes
                else:
                    # No destination provided → value-only operand (mop_z).
                    new.d = ida_hexrays.mop_t()
                    new.d.erase()
                    new.d.size = size_bytes
                # Right operand must be the special mop_z ("empty" operand).
                # Using make_number(0, 0) results in a mop_n with size==0, which
                # triggers verifier INTERR 50629.  Instead, create the mop_t and
                # immediately erase() it so Hex-Rays marks it as mop_z.
                new.r = ida_hexrays.mop_t()
                new.r.erase()  # produces a genuine mop_z
                # ------------------------------------------------------------------
                # Debug-only sanity checks
                # ------------------------------------------------------------------
                if logger.debug_on:
                    # Sanity-check: size agreement when destination *has* a size.
                    if new.d.t != ida_hexrays.mop_z and new.d.size not in (0, None):
                        try:
                            assert new.l.size == new.d.size
                        except AssertionError as _e:
                            logger.error(
                                "[fold_const] Built m_ldc with mismatching sizes (l=%d, d=%d): %s",
                                new.l.size,
                                new.d.size,
                                _e,
                                exc_info=True,
                            )
                    assert new.opcode == ida_hexrays.m_ldc
                    # For top-level instructions we can run an expensive verify().
                    if blk is not None:
                        mba = blk.mba
                        # Force a deep verification; will throw ida_hexrays.InternalError50629
                        try:
                            mba.verify(True)
                        except RuntimeError as e:
                            logger.error(
                                "[fold_const] MBA verify failed after folding: %s",
                                e,
                                exc_info=True,
                            )
                            for bb in mba.basic_blocks:
                                for ins2 in bb:
                                    try:
                                        ins2.verify(True)  # verifies one instruction
                                    except RuntimeError as e2:
                                        logger.error(
                                            "[fold_const]  ↳ bad ins 0x%X %s : %s",
                                            ins2.ea,
                                            opcode_to_string(ins2.opcode),
                                            e2,
                                            exc_info=True,
                                        )
                            # Do NOT propagate the exception – it would abort the
                            # entire optimisation pass when DEBUG is enabled.  By
                            # returning None we instruct the peephole engine to
                            # keep the original instruction unchanged.
                            return None
                return new
        else:
            if logger.debug_on:
                logger.debug(
                    "[fold_const] Could not build AST for computation: opcode=%s, dstr=%s",
                    opcode_to_string(ins.opcode),
                    ins.dstr(),
                )

        if logger.debug_on:
            logger.debug(
                "[fold_const] No folding possible for ins at 0x%X (opcode=%s)",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
            )
        # Nothing to do
        return None
