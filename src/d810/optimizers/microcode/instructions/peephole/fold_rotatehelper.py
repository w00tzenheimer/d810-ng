from __future__ import annotations

import functools
import typing

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.core import bits as rotate_helpers
from d810.hexrays.hexrays_formatters import format_mop_t, opcode_to_string, sanitize_ea
from d810.hexrays.hexrays_helpers import AND_TABLE  # already maps size→mask
from d810.hexrays.hexrays_helpers import extract_literal_from_mop, is_rotate_helper_call
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)


def example(msg: str) -> typing.Callable:
    def decorator(func: typing.Callable) -> typing.Callable:
        @functools.wraps(func)
        def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            return func(*args, **kwargs)

        return wrapper

    return decorator


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

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        # Run *very* early so that the AST builder never sees the wrapper.
        self.maturities = [ida_hexrays.MMAT_LOCOPT]

    @typing.override
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
            args_list = extract_literal_from_mop(call_ins.r)

        # Pattern B: arguments packed in a mop_f stored in call_ins.d (observed when call_ins.r is mop_z)
        elif (
            call_ins.d is not None
            and call_ins.d.t == ida_hexrays.mop_f
            and hasattr(call_ins.d, "f")
            and call_ins.d.f is not None
        ):
            # args_list = call_ins.d.f.args
            args_list = extract_literal_from_mop(call_ins.d)

        # Pattern C: compact helper – r is value, d is shift amount
        elif call_ins.r is not None and call_ins.d is not None:
            # args_list = [call_ins.r, call_ins.d]
            args_list = extract_literal_from_mop(call_ins.r)
            if args_list:
                shift_list = extract_literal_from_mop(call_ins.d)
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

        helper_func = getattr(rotate_helpers, helper_name, None)
        if helper_func is None:
            if logger.debug_on:
                logger.debug("[RotateHelperInline] helper %s not found in rotate_helpers", helper_name)
            return None

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
