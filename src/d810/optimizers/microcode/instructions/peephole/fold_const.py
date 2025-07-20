from __future__ import annotations

import logging
import typing

import ida_hexrays
import idaapi

from d810.expr.ast import AstBase, AstLeaf, AstNode, minsn_to_ast, mop_to_ast
from d810.expr.utils import (
    get_parity_flag,
    rol1,
    rol2,
    rol4,
    rol8,
    ror1,
    ror2,
    ror4,
    ror8,
)
from d810.hexrays.hexrays_formatters import (
    format_mop_t,
    mop_type_to_string,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import (  # already maps size→mask
    AND_TABLE,
    CONTROL_FLOW_OPCODES,
    OPCODES_INFO,
)
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

peephole_logger = logging.getLogger("D810.optimizer")

# ────────────────────────────────────────────────────────────────────
# Debug helpers
# ────────────────────────────────────────────────────────────────────


def _mop_to_str(mop: "ida_hexrays.mop_t | None") -> str:  # noqa: ANN001
    """Return a compact readable string for *mop* suitable for debug logs."""

    if mop is None:
        return "<None>"
    try:
        return format_mop_t(mop)
    except Exception:  # pragma: no cover - logging helper, be robust
        # Fall back to dstr() if available, else repr
        return str(mop.dstr() if hasattr(mop, "dstr") else mop)


# ────────────────────────────────────────────────────────────────────
# Utility helpers
# ────────────────────────────────────────────────────────────────────
COMMUTATIVE = {
    ida_hexrays.m_add,
    ida_hexrays.m_mul,
    ida_hexrays.m_xor,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
}


# New helper ──────────────────────────────────────────────────────────
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


def _fold_const_in_mop(mop: ida_hexrays.mop_t | None, bits: int) -> bool:
    """
    Walk a mop tree, try to constant-fold, return True if anything changed.
    """
    if mop is None or not isinstance(mop, ida_hexrays.mop_t):
        return False

    changed = False
    if peephole_logger.isEnabledFor(logging.DEBUG):
        peephole_logger.debug(
            "[fold_const] [_fold_const_in_mop] mop: %s", _mop_to_str(mop)
        )

    # Recurse only if this is an embedded instruction (mop_d)
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        ins = mop.d
        changed |= _fold_const_in_mop(ins.l, bits)
        changed |= _fold_const_in_mop(ins.r, bits)

        # After children are folded, see if *this* minsn collapses
        ast = minsn_to_ast(ins)
        val = _eval_subtree(ast, bits)
        if val is not None:
            cst = ida_hexrays.mop_t()
            cst.make_number(val, ins.d.size)

            # Replace the constant at the parent instruction safely, without
            # mutating an operand that still belongs to Hex-Rays internal
            # data structures.
            if ins.l is mop:
                ins.l = cst
            elif ins.r is mop:
                ins.r = cst
            elif ins.d is mop:
                ins.d = cst
            changed = True

    return changed


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
    peephole_logger.error(
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
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[fold_const] [_eval_subtree] ast is None - cannot evaluate"
            )
        return None

    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        mop = ast.mop
        if mop is None:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
                    "[fold_const] [_eval_subtree] Leaf with no mop: %s", ast
                )
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
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[fold_const] [_eval_subtree] Cannot evaluate binary node (%s) because %s is None",
                opcode_to_string(ast.opcode),
                "left" if l is None else "right",
            )
        return None

    # special handling for rotate calls
    if ast.opcode == ida_hexrays.m_call and ast.func_name:
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
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
        peephole_logger.error(
            "[fold_const] [_eval_subtree] Unknown width for rotate call: %s with args: %s %s and bits: %s",
            helper_name,
            l,
            r,
            bits,
        )
        return None
    return _fold(ast.opcode, l, r, bits)  # type: ignore


class FoldPureConstantRule(PeepholeSimplificationRule):
    DESCRIPTION = (
        "Collapse any instruction whose whole expression "
        "is a compile-time constant into a single m_ldc"
    )

    maturities = [
        ida_hexrays.MMAT_GLBOPT2,
    ]

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        # Skip flow-control instructions that can never be folded to a constant.
        if ins.opcode in CONTROL_FLOW_OPCODES:
            return None
        # Skip instructions that are already in optimal form or would cause infinite loops
        if ins.opcode == ida_hexrays.m_ldc:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
                    "[fold_const] Skipping m_ldc instruction (already optimal)"
                )
            return None

        # Skip mov instructions where source is already a constant (prevents infinite loop)
        if ins.opcode == ida_hexrays.m_mov and ins.l and ins.l.t == ida_hexrays.mop_n:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
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
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
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
                if peephole_logger.isEnabledFor(logging.DEBUG):
                    peephole_logger.debug(
                        "[fold_const] Skipping identity operation (should be handled by other rules)"
                    )
                return None

        if ins.d is None or ins.d.t not in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
        }:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
                    "[fold_const] Skipping instruction @ 0x%X with invalid destination: (opcode=%s) (ins.d.t=%s) -- dstr=%s",
                    sanitize_ea(ins.ea),
                    opcode_to_string(ins.opcode),
                    mop_type_to_string(ins.d.t),
                    ins.dstr(),
                )
            return None

        bits = ins.d.size * 8 if ins.d.size else 32
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[fold_const] Checking ins @ 0x%X (opcode=%s) l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                _mop_to_str(ins.l),
                _mop_to_str(ins.r),
                _mop_to_str(ins.d),
            )

        # Ensure bits is valid and positive
        if bits <= 0:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
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
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
                    "[fold_const] Adjusted bits to supported size: %d", bits
                )

        # Try to collapse the *whole* instruction tree.
        # Build AST from just the computation (left and right operands), not the destination
        if ins.opcode == ida_hexrays.m_mov:
            # For mov, evaluate the source operand
            ast = mop_to_ast(ins.l)
        else:
            # For binary operations, build AST from the operation itself
            left_ast = mop_to_ast(ins.l) if ins.l is not None else None
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
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug("[fold_const] AST for ins: %s", ast)
            value = _eval_subtree(ast, bits)
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug("[fold_const] _eval_subtree result: %r", value)
            if value is not None:
                peephole_logger.info(
                    "[fold_const] Collapsed ins at 0x%X to constant 0x%X (opcode=%s)",
                    ins.ea,
                    value,
                    opcode_to_string(ins.opcode),
                )
                # Build a *fresh* m_ldc instruction rather than mutating a clone of
                # the old one.  Re-using the old `minsn_t` can leave garbage in
                # opcode-specific union fields, which has been observed to crash IDA
                # during later optimisation passes.

                # Ensure EA is canonical (masked with BADADDR) to avoid crashes in
                # passes that expect 0-based addresses.

                canonical_ea = ins.ea & idaapi.BADADDR if ins.ea else 0
                new = ida_hexrays.minsn_t(canonical_ea)
                new.opcode = ida_hexrays.m_ldc

                # ------------------------------------------------------------------
                # SAFETY: `make_number` expects a *valid* byte size (1,2,4,8,16…).
                # Some micro-instructions have their `d.size` field set to 0 which
                # causes Hex-Rays to crash deep in the C++ layer when we pass it
                # through blindly.  Guard against that by falling back to 4-byte
                # integers if we detect an invalid/zero size.
                # ------------------------------------------------------------------
                size_bytes = 4  # sensible default (32-bit)
                if getattr(ins, "d", None) is not None and getattr(ins.d, "size", 0):
                    # Keep the original size when it is a positive, supported value.
                    if ins.d.size in [1, 2, 4, 8, 16]:
                        size_bytes = ins.d.size

                cst = ida_hexrays.mop_t()
                cst.make_number(value, size_bytes)

                new.l = cst

                # Destination operand: keep the *original* one (register, stack var…)
                # but clone it to detach from the existing microcode tree.
                if ins.d is not None:
                    new.d = ida_hexrays.mop_t()
                    new.d.assign(ins.d)
                    new.d.size = size_bytes
                else:
                    # Fallback: create an empty destination to keep microcode valid.
                    new.d = ida_hexrays.mop_t()
                    new.d.make_number(0, size_bytes)  # unused dummy

                # Right operand must be the special mop_z ("empty" operand).
                # Using make_number(0, 0) results in a mop_n with size==0, which
                # triggers verifier INTERR 50629.  Instead, create the mop_t and
                # immediately erase() it so Hex-Rays marks it as mop_z.
                new.r = ida_hexrays.mop_t()
                new.r.erase()  # produces a genuine mop_z

                # ------------------------------------------------------------------
                # Debug-only sanity checks
                # ------------------------------------------------------------------
                if peephole_logger.isEnabledFor(logging.DEBUG):
                    try:
                        assert new.l.size == new.d.size
                        assert new.opcode == ida_hexrays.m_ldc
                    except AssertionError as _e:
                        peephole_logger.error(
                            "[fold_const] Built invalid m_ldc: %s", _e
                        )
                if peephole_logger.isEnabledFor(logging.DEBUG):
                    mba = blk.mba
                    # Force a deep verification; will throw ida_hexrays.InternalError50629
                    try:
                        mba.verify(True)
                    except RuntimeError as e:
                        peephole_logger.error(
                            "[fold_const] MBA verify failed after folding: %s",
                            e,
                            exc_info=True,
                        )
                        for bb in mba.basic_blocks:
                            for ins2 in bb:
                                try:
                                    ins2.verify(True)  # verifies one instruction
                                except RuntimeError as e2:
                                    peephole_logger.error(
                                        "[fold_const]  ↳ bad ins 0x%X %s : %s",
                                        ins2.ea,
                                        opcode_to_string(ins2.opcode),
                                        e2,
                                        exc_info=True,
                                    )
                        raise
                return new
        else:
            if peephole_logger.isEnabledFor(logging.DEBUG):
                peephole_logger.debug(
                    "[fold_const] Could not build AST for computation: opcode=%s, dstr=%s",
                    opcode_to_string(ins.opcode),
                    ins.dstr(),
                )

        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[fold_const] No folding possible for ins at 0x%X (opcode=%s)",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
            )
        # Nothing to do
        return None
