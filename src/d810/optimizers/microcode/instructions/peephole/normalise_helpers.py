"""Peephole normalisation passes that remove Hex-Rays helper quirks.

MMAT_CALLS rules:
    - TransparentCallUnwrapRule         - unwrap call wrappers whose value is stored in the destination operand.
    - TypedImmediateCanonicaliseRule    - turn typed-immediate wrappers into plain mop_n.

GLBOPT1 rules:
    - ConstantCallResultFoldRule        - collapse helpers that already return a literal into m_ldc.
    - RotateHelperInlineRule            - convert __ROL*/__ROR* helper calls into explicit shift/or tree.

All rules inherit from PeepholeSimplificationRule, therefore are auto-registered.
"""

from __future__ import annotations

import functools
import typing

import ida_hexrays

from d810 import _compat
from d810.conf.loggers import getLogger
from d810.expr import utils
from d810.hexrays.hexrays_formatters import (  # noqa: F401 - debug only
    format_minsn_t,
    format_mop_t,
    log_mop_tree,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import AND_TABLE, dup_mop, is_rotate_helper_call
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__, default_level=10)

# ---------------------------------------------------------------------------
# 1. Transparent call unwrapping (MMAT_CALLS) -----------------------------------
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
    maturities = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]

    @_compat.override
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


# ---------------------------------------------------------------------------
# 2. Typed-immediate cleanup (MMAT_CALLS) ---------------------------------------
# ---------------------------------------------------------------------------


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
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]

    @_compat.override
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


# ---------------------------------------------------------------------------
# 3. Constant-call-result folding (GLBOPT1) ----------------------------------
# ---------------------------------------------------------------------------


def _extract_literal_from_mop(
    mop: ida_hexrays.mop_t | None,
) -> list[tuple[int, int]] | None:
    """Return (value, size_bytes) if *mop* ultimately encodes a numeric constant."""

    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return [(mop.nnn.value, mop.size)]

    # m_ldc wrapper (mop_d → minsn_t(ldc …))
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_ldc
        and mop.d.l is not None
        and mop.d.l.t == ida_hexrays.mop_n
    ):
        return [(mop.d.l.nnn.value, mop.d.l.size)]

    # typed-immediate mop_f
    if mop.t == ida_hexrays.mop_f and getattr(mop, "f", None):
        args = mop.f.args
        if args:
            rval: list[tuple[int, int]] = []
            for arg in args:
                if arg is not None and arg.t == ida_hexrays.mop_n:
                    rval.append((arg.nnn.value, arg.size))
                else:
                    break
            else:
                # for else here means *every* arg is a literal
                # and there was no early break in the for loop
                # which means all the args are literals
                return rval

    return None


def example(msg: str) -> typing.Callable:
    def decorator(func: typing.Callable) -> typing.Callable:
        @functools.wraps(func)
        def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            return func(*args, **kwargs)

        return wrapper

    return decorator


class ConstantCallResultFoldRule(PeepholeSimplificationRule):
    """Collapse helper calls whose *result* is already a literal into a constant"""

    DESCRIPTION = (
        "Fold helper calls with literal destination into single constant expression"
    )

    maturities = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS]

    @example(
        "opcode=call l=<mop_t type=mop_h size=-1 dstr=!__ROL8__> r=<mop_t type=mop_z size=-1 dstr=> d=<mop_t type=mop_f size=8 dstr=<fast:_QWORD #0x33637E66.8,char #4.1>.8>"
    )
    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:

        if logger.debug_on:
            logger.debug(
                "[const-call] considering ea=%X, opcode=%s l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                format_mop_t(ins.l),
                format_mop_t(ins.r),
                format_mop_t(ins.d),
            )

        # Only consider calls.
        if ins.opcode != ida_hexrays.m_call or ins.d is None:
            return None

        # only consider rotate helper calls (for now)
        if not is_rotate_helper_call(ins.l.d):
            logger.info(
                "[const-call] not a rotate helper call, it is a %s",
                ins.l.dstr(),
            )
            return None

        # extract helper name and width from helper string (e.g., __ROL4__)
        helper_name = (ins.l.d.helper or "").lstrip("!")
        if not helper_name:
            logger.debug(
                "[const-call] helper name is None, bail out",
                format_mop_t(ins.l.d),
            )
            return None

        extracted = _extract_literal_from_mop(ins.d)
        if not extracted:
            if logger.debug_on:
                logger.debug(
                    "[const-call] no extracted literals",
                    format_mop_t(ins.d),
                )
            return None

        if len(extracted) != 2:
            if logger.debug_on:
                logger.debug("[const-call] unexpected arg count: %d", len(extracted))
            return None

        lhs_val, lhs_size = extracted[0]
        rhs_val, _ = extracted[1]

        if lhs_size > ins.d.size:
            logger.warning(
                "[const-call] lhs_size > ins.d.size, will have to truncate!",
                lhs_size,
                ins.d.size,
            )

        helper_func = getattr(utils, helper_name)
        result = helper_func(lhs_val, rhs_val) & AND_TABLE[ins.d.size]

        new = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        new.opcode = ida_hexrays.m_ldc
        cst = ida_hexrays.mop_t()
        cst.make_number(result, ins.d.size)
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
            new.d.size = ins.d.size
        else:
            new.d = ida_hexrays.mop_t()
            new.d.erase()
            new.d.size = ins.d.size
        new.r = ida_hexrays.mop_t()
        new.r.erase()
        new.r.size = ins.d.size
        if logger.debug_on:
            logger.debug(
                "[const-call] 0x%X call -> ldc 0x%X (size=%d)",
                sanitize_ea(ins.ea),
                result,
                ins.d.size,
            )
        return new


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


@example(
    "mov l=call !__ROL8__<fast:_QWORD #-0x41675E3C1408CD87.8,char #0xE.1>.8 r= d=rax.8{62}"
)
class RotateHelperInlineRule(PeepholeSimplificationRule):
    DESCRIPTION = (
        "mov  l=m_call <helper>  r=  d=<register> -> mov  l=<constant>  d=<register>"
    )
    """
        mov  l=m_call <helper>  r=  d=<register>

    This turns a value-only helper (often emitted by the decompiler for things like casts or wrappers
    around compiler intrinsics) into the real micro-instruction so that
    subsequent passes can optimize it.
    """

    # Run *very* early so that the AST builder never sees the wrapper.
    maturities = [ida_hexrays.MMAT_LOCOPT]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:  # noqa: D401
        """Return a replacement `minsn_t` or None to keep *ins* unchanged."""

        if logger.debug_on:
            logger.debug(
                "[RotateHelperInline] considering ea=%X, opcode=%s is insn.l.d a helper? %s  l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                is_rotate_helper_call(ins.l.d),
                format_mop_t(ins.l),
                format_mop_t(ins.r),
                format_mop_t(ins.d),
            )

        # mov call, register
        if ins.opcode != ida_hexrays.m_mov:
            return None

        left: ida_hexrays.mop_t = ins.l
        dest: ida_hexrays.mop_t = ins.d

        if (
            left is None
            or dest is None
            or dest.t != ida_hexrays.mop_r
            or left.t != ida_hexrays.mop_d
            or left.d.opcode != ida_hexrays.m_call
            or not is_rotate_helper_call(left.d)
        ):
            # we are looking for:
            #   mov call !helper, register
            # bail out if the helper is not a rotate helper
            return None

        register_size = AND_TABLE[dest.size]
        # log_mop_tree(left)
        insn_helper: ida_hexrays.mop_t = left.d.l  # so confusing.
        # extract helper name and width from helper string (e.g., __ROL4__)
        helper_name = (insn_helper.helper or "").lstrip("!")
        if not helper_name:
            logger.debug(
                "[RotateHelperInline] helper name is None, bail out",
                format_mop_t(insn_helper),
            )
            return None

        args_list = []
        # Determine argument list depending on call layout. Standard layout stores
        # the argument list in a typed-immediate mop_f wrapper sitting in the
        # right operand (left.r).  However, Hex-Rays sometimes emits a compact
        # form where *left.r* and *left.d* directly hold the two operands.  We
        # must guard against both variants to avoid AttributeErrors.
        call_ins = left.d  # the inner m_call instruction

        # Pattern A: arguments packed in a mop_f stored in call_ins.r
        if (
            call_ins.r is not None
            and call_ins.r.t == ida_hexrays.mop_f
            and hasattr(call_ins.r, "f")
            and call_ins.r.f is not None
        ):
            # args_list = call_ins.r.f.args
            args_list = _extract_literal_from_mop(call_ins.r)

        # Pattern B: arguments packed in a mop_f stored in call_ins.d (observed when call_ins.r is mop_z)
        elif (
            call_ins.d is not None
            and call_ins.d.t == ida_hexrays.mop_f
            and hasattr(call_ins.d, "f")
            and call_ins.d.f is not None
        ):
            # args_list = call_ins.d.f.args
            args_list = _extract_literal_from_mop(call_ins.d)

        # Pattern C: compact helper – r is value, d is shift amount
        elif call_ins.r is not None and call_ins.d is not None:
            # args_list = [call_ins.r, call_ins.d]
            args_list = _extract_literal_from_mop(call_ins.r)
            if args_list:
                shift_list = _extract_literal_from_mop(call_ins.d)
                if shift_list:
                    args_list.extend(shift_list)
        else:
            logger.debug(
                "[RotateHelperInline] unable to determine helper arguments (call_ins.l=%s r=%s d=%s), bail out",
                format_mop_t(call_ins.l),
                format_mop_t(call_ins.r),
                format_mop_t(call_ins.d),
            )
            return None

        if logger.debug_on:
            logger.debug(
                "[RotateHelperInline] considering ea=%X, opcode=%s. evaluating helper %s with args %s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                helper_name,
                args_list,
            )

        helper_func = getattr(utils, helper_name)

        # Safely extract literal values from the two arguments.  If either is not a
        # literal we cannot evaluate the helper at this stage.
        if not args_list:
            if logger.debug_on:
                logger.debug("[RotateHelperInline] no args list")
            return None

        if len(args_list) != 2:
            if logger.debug_on:
                logger.debug(
                    "[RotateHelperInline] unexpected arg count: %d", len(args_list)
                )
            return None

        lhs_val, _ = args_list[0]
        rhs_val, _ = args_list[1]

        result = helper_func(lhs_val, rhs_val) & register_size
        if logger.debug_on:
            logger.debug(
                "[RotateHelperInline] evaluating helper %s with args %s -> %s",
                helper_name,
                args_list,
                result,
            )

        # build the new insn
        new_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
        new_ins.opcode = ida_hexrays.m_mov
        new_ins.l = ida_hexrays.mop_t()
        new_ins.l.make_number(result, dest.size)
        new_ins.d = dest
        return new_ins


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
