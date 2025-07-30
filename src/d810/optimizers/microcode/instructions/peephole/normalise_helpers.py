"""Peephole normalisation passes that remove Hex-Rays helper quirks.

GLBOPT0 rules:
    • TransparentCallUnwrapRule         – unwrap call wrappers whose value is stored in the destination operand.
    • TypedImmediateCanonicaliseRule    – turn typed-immediate wrappers into plain mop_n.

GLBOPT1 rules:
    • ConstantCallResultFoldRule        – collapse helpers that already return a literal into m_ldc.
    • RotateHelperInlineRule            – convert __ROL*/__ROR* helper calls into explicit shift/or tree.

All rules inherit from PeepholeSimplificationRule, therefore are auto-registered.
"""

from __future__ import annotations

import logging
import typing

import ida_hexrays

from d810 import _compat
from d810.hexrays.hexrays_formatters import (  # noqa: F401 – debug only
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

peephole_logger = logging.getLogger("D810.optimizer")

# ---------------------------------------------------------------------------
# Helper utilities -----------------------------------------------------------
# ---------------------------------------------------------------------------


def _is_rotate_helper_call(ins: ida_hexrays.minsn_t | None) -> bool:
    """Return True if *ins* is a call to one of Hex-Rays' synthetic
    rotate helpers (__ROL* / __ROR*)."""

    if (
        ins is None
        or ins.opcode != ida_hexrays.m_call
        or ins.l is None
        or ins.l.t != ida_hexrays.mop_h
    ):
        return False
    helper = (ins.l.helper or "").lstrip("!")
    return helper.startswith("__ROL") or helper.startswith("__ROR")


def _dup_mop(src: ida_hexrays.mop_t) -> ida_hexrays.mop_t:
    """Return a *detached* copy of *src*."""
    dup = ida_hexrays.mop_t()
    dup.assign(src)
    return dup


# ---------------------------------------------------------------------------
# 1. Transparent call unwrapping (GLBOPT0) -----------------------------------
# ---------------------------------------------------------------------------


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
    maturities = [ida_hexrays.MMAT_CALLS]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:  # noqa: D401
        """Return a replacement `minsn_t` or None to keep *ins* unchanged."""

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

        # Extra guard: do *not* unwrap rotate helper calls – another rule handles them
        if _is_rotate_helper_call(inner):
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
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[transparent-call] 0x%X unwrap → %s",
                sanitize_ea(ins.ea),
                opcode_to_string(new_ins.opcode),
            )

        return new_ins


# ---------------------------------------------------------------------------
# 2. Typed-immediate cleanup (GLBOPT0) ---------------------------------------
# ---------------------------------------------------------------------------


class TypedImmediateCanonicaliseRule(PeepholeSimplificationRule):
    """Turn the various typed-immediate wrappers produced by Hex-Rays into
    plain numeric constants (mop_n).  Handles two frequent patterns:

    • The typed immediate mop_f wrapper::

          <fast:_QWORD #0x42.8,char #4.1>.8

      which is represented as an *mop_f* whose *f.args[0]* is the real
      mop_n literal.

    • An *m_ldc* micro-instruction that loads a constant into a pseudo
      temporal destination – the source literal sits in the *l* operand.
      These appear inside nested expressions (eg. m_call wrappers).
    """

    DESCRIPTION = "Canonicalise typed immediates (mop_f) into plain mop_n literals"

    maturities = [ida_hexrays.MMAT_CALLS]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Replace *ins* when all it does is materialise a literal."""

        # ------------------------------------------------------------------
        # Case A – Stand-alone m_ldc that simply moves a literal.
        # ------------------------------------------------------------------
        if (
            ins.opcode == ida_hexrays.m_ldc
            and ins.l is not None
            and ins.l.t == ida_hexrays.mop_n
        ):
            # Up-convert to the canonical representation used by the constant
            # folder:    m_ldc  l=<mop_n>   d=<original dst>  r=mop_z
            # Here the instruction is already in that form – nothing to do.
            return None  # keep as-is

        # ------------------------------------------------------------------
        # Case B – Instruction *operands* that wrap the literal in mop_f.
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


# ---------------------------------------------------------------------------
# 3. Constant-call-result folding (GLBOPT1) ----------------------------------
# ---------------------------------------------------------------------------


def _extract_literal_from_mop(mop: ida_hexrays.mop_t | None) -> tuple[int, int] | None:
    """Return (value, size_bytes) if *mop* ultimately encodes a numeric constant."""

    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value, mop.size

    # m_ldc wrapper (mop_d → minsn_t(ldc …))
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_ldc
        and mop.d.l is not None
        and mop.d.l.t == ida_hexrays.mop_n
    ):
        return mop.d.l.nnn.value, mop.d.l.size

    # typed-immediate mop_f
    if mop.t == ida_hexrays.mop_f and getattr(mop, "f", None):
        args = mop.f.args
        if (
            args
            and len(args) >= 1
            and args[0] is not None
            and args[0].t == ida_hexrays.mop_n
        ):
            return args[0].nnn.value, args[0].size
    return None


class ConstantCallResultFoldRule(PeepholeSimplificationRule):
    """Collapse helper calls whose *result* is already a literal into `m_ldc`."""

    DESCRIPTION = "Fold helper call with literal destination into single m_ldc"

    maturities = [ida_hexrays.MMAT_GLBOPT1]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:

        # Only consider calls.
        if ins.opcode != ida_hexrays.m_call or ins.d is None:
            return None

        extracted = _extract_literal_from_mop(ins.d)
        if extracted is None:
            return None

        value, size_bytes = extracted
        if size_bytes not in AND_TABLE:
            size_bytes = 4

        # if peephole_logger.isEnabledFor(logging.DEBUG):
        #     peephole_logger.debug(
        #         "[const-call] 0x%X collapse call → ldc 0x%X (size=%d)",
        #         sanitize_ea(ins.ea),
        #         value,
        #         size_bytes,
        #     )

        new = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        new.opcode = ida_hexrays.m_ldc
        cst = ida_hexrays.mop_t()
        cst.make_number(value, size_bytes)
        new.l = cst
        # clone destination when it's a real l-value
        if ins.d.t in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
        }:
            new.d = ida_hexrays.mop_t()
            new.d.assign(ins.d)
            new.d.size = size_bytes
        else:
            new.d = ida_hexrays.mop_t()
            new.d.erase()
            new.d.size = size_bytes
        new.r = ida_hexrays.mop_t()
        new.r.erase()
        new.r.size = size_bytes
        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[const-call] 0x%X call→ldc 0x%X (size=%d)",
                sanitize_ea(ins.ea),
                value,
                size_bytes,
            )
        return new


# ---------------------------------------------------------------------------
# 4. Rotate helper inlining (GLBOPT1) ----------------------------------------
# ---------------------------------------------------------------------------

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


class RotateHelperInlineRule(PeepholeSimplificationRule):
    """Replace `__ROL*` / `__ROR*` helper calls by explicit (shl, shr, or) tree.

    This exposes the rotate to algebraic simplifications and constant
    folding, removing the need for special-case handling in the AST
    builder.
    """

    DESCRIPTION = "Inline ROL/ROR helper calls into shifts + or"
    maturities = [ida_hexrays.MMAT_GLBOPT1]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        if not _is_rotate_helper_call(ins):
            return None

        # Extract helper name and width from helper string (e.g., __ROL4__)
        helper_name = (ins.l.helper or "").lstrip("!")
        is_rol = helper_name.startswith("__ROL")

        # Derive bit width from destination size if possible; fallback 32.
        bits = (ins.d.size or 4) * 8 if ins.d else 32

        # --------------------------------------------------------------
        # Gather operands depending on layout.
        # Layout A: argument list in mop_f.
        # Layout B: r == value, d == shift
        # --------------------------------------------------------------
        if (
            ins.r is not None
            and ins.r.t == ida_hexrays.mop_f
            and getattr(ins.r, "f", None)
        ):
            args = ins.r.f.args
            if len(args) < 2 or args[0] is None or args[1] is None:
                return None  # malformed, bail
            val_mop = _dup_mop(args[0])
            sh_mop = _dup_mop(args[1])
        else:
            # compact form
            val_mop = _dup_mop(ins.r)
            sh_mop = _dup_mop(ins.d)
            if val_mop is None or sh_mop is None:
                return None
        # Build (bits - shift) expression:  sub_ins
        bits_const = ida_hexrays.mop_t()
        bits_const.make_number(bits, (bits // 8) if bits // 8 in AND_TABLE else 4)
        sub_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        sub_ins.opcode = ida_hexrays.m_sub
        sub_ins.l = bits_const
        sub_ins.r = _dup_mop(sh_mop)
        sub_mop = ida_hexrays.mop_t()
        sub_mop.create_from_insn(sub_ins)

        # Build left shift: val << sh
        shl_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        shl_ins.opcode = ida_hexrays.m_shl
        shl_ins.l = _dup_mop(val_mop)
        shl_ins.r = _dup_mop(sh_mop)
        shl_mop = ida_hexrays.mop_t()
        shl_mop.create_from_insn(shl_ins)

        # Build right shift (direction depends on rol/ror)
        shift_opcode = ida_hexrays.m_shr if is_rol else ida_hexrays.m_shl
        shr_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        shr_ins.opcode = shift_opcode
        shr_ins.l = _dup_mop(val_mop)
        shr_ins.r = sub_mop
        shr_mop = ida_hexrays.mop_t()
        shr_mop.create_from_insn(shr_ins)

        # Build final or
        or_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        or_ins.opcode = ida_hexrays.m_or
        or_ins.l = shl_mop
        or_ins.r = shr_mop

        # Destination: keep original l-value when legal
        or_ins.d = ida_hexrays.mop_t()
        if ins.d and ins.d.t in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
        }:
            or_ins.d.assign(ins.d)
        else:
            or_ins.d.erase()
        or_ins.d.size = ins.d.size if ins.d else (bits // 8)

        if peephole_logger.isEnabledFor(logging.DEBUG):
            peephole_logger.debug(
                "[rotate-inline] 0x%X %s inlined into or/shl/shr",
                sanitize_ea(ins.ea),
                helper_name,
            )
        return or_ins
