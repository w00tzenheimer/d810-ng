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


class ConstantCallResultFoldRule(PeepholeSimplificationRule):
    """Collapse helper calls whose *result* is already a literal into a constant"""

    DESCRIPTION = (
        "Fold helper calls with literal destination into single constant expression"
    )

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ]

    @example(
        "opcode=call l=<mop_t type=mop_h size=-1 dstr=!__ROL8__> r=<mop_t type=mop_z size=-1 dstr=> d=<mop_t type=mop_f size=8 dstr=<fast:_QWORD #0x33637E66.8,char #4.1>.8>"
    )
    @typing.override
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

        # Only consider calls that have a destination result
        if ins.opcode != ida_hexrays.m_call or ins.d is None:
            return None

        # log_mop_tree(ins.l)
        # log_mop_tree(ins.r)
        # log_mop_tree(ins.d)
        # only consider rotate helper calls (for now)
        if not is_rotate_helper_call(ins):
            if logger.debug_on:
                logger.debug(
                    "[const-call] not a rotate helper call, it is a %s",
                    ins.dstr(),
                )
            return None

        # extract helper name and width from helper string (e.g., __ROL4__)
        helper_name = (ins.l.helper or "").lstrip("!")
        if not helper_name:
            if logger.debug_on:
                logger.debug(
                    "[const-call] helper name is None, bail out",
                    format_mop_t(ins.l.d),
                )
            return None

        extracted = extract_literal_from_mop(ins.d)
        if not extracted:
            if logger.debug_on:
                logger.debug(
                    "[const-call] no extracted literals from %s",
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

        helper_func = getattr(rotate_helpers, helper_name, None)
        if helper_func is None:
            if logger.debug_on:
                logger.debug("[const-call] helper %s not found in rotate_helpers", helper_name)
            return None
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
        # 'r' is unused for m_ldc. Keep it as a mop_z with size 0 so that
        # later optimizers (e.g. stack-var propagation) can update it safely
        # without breaking the size invariants.
        new.r = ida_hexrays.mop_t()
        new.r.erase()  # will set t=mop_z and size=0
        if logger.debug_on:
            logger.debug(
                "[const-call] 0x%X call -> ldc 0x%X (size=%d)",
                sanitize_ea(ins.ea),
                result,
                ins.d.size,
            )
        return new
