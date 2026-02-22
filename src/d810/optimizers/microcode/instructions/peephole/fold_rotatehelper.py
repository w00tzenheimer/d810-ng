from __future__ import annotations

import functools
from d810.core import typing

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.evaluator.helpers.rotate import _RotateHelper as _HelperLookup
from d810.expr.ast import mop_to_ast
from d810.hexrays.hexrays_formatters import format_mop_t, opcode_to_string, sanitize_ea
from d810.hexrays.hexrays_helpers import AND_TABLE  # already maps size->mask
from d810.hexrays.hexrays_helpers import extract_literal_from_mop, is_rotate_helper_call
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)
from d810.optimizers.microcode.instructions.peephole.normalise_helpers import (
    _eval_subtree,
)

logger = getLogger(__name__)


def _try_eval_mop(mop: "ida_hexrays.mop_t | None", bits: int) -> "tuple[int, int] | None":
    """Try to evaluate *mop* as a constant, returning (value, size_bytes) or None.

    First tries the fast path via ``extract_literal_from_mop`` (handles plain
    mop_n and simple wrappers).  If that fails, falls back to building a full
    AST and evaluating it with ``_eval_subtree``, which handles nested constant
    expression trees such as ``__ROL4__(0x6EBCBAA1, 4) + 0x6B9F6F9A``.
    """
    if mop is None:
        return None

    # Fast path: plain literal or simple wrapper.
    lit = extract_literal_from_mop(mop)
    if lit and len(lit) == 1:
        return lit[0]  # (value, size_bytes)

    # Slow path: full AST evaluation for nested constant expressions.
    try:
        ast = mop_to_ast(mop)
        if ast is not None:
            val = _eval_subtree(ast, bits)
            if val is not None:
                return (val, mop.size)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(
            "[RotateHelperInline] _try_eval_mop AST fallback failed for mop=%s: %s",
            format_mop_t(mop),
            exc,
        )
    return None


def _extract_args_from_mop_f(
    mop_f: "ida_hexrays.mop_t", bits: int
) -> "list[tuple[int, int]] | None":
    """Extract two (value, size) pairs from an mop_f argument list.

    Each argument is evaluated via :func:`_try_eval_mop` so that nested
    constant expression trees are handled in addition to plain literals.
    Returns a 2-element list or None if any argument cannot be evaluated.
    """
    if mop_f is None or mop_f.t != ida_hexrays.mop_f or getattr(mop_f, "f", None) is None:
        return None
    args = mop_f.f.args
    if not args or len(args) < 2:
        return None
    result: list[tuple[int, int]] = []
    for i in range(2):
        try:
            arg = args[i]
        except (IndexError, TypeError):
            return None
        ev = _try_eval_mop(arg, bits)
        if ev is None:
            return None
        result.append(ev)
    return result


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
        # Run at LOCOPT (early) and GLBOPT3 (safe — unflattener does not run
        # at GLBOPT3, only at CALLS/GLBOPT1/GLBOPT2).
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            getattr(ida_hexrays, "MMAT_GLBOPT3", ida_hexrays.MMAT_CALLS),
        ]

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

        # Bit-width of the destination (used for AST evaluation fallback).
        _bits: int = dest.size * 8 if dest.size else 32

        # Pattern A: arguments packed in a mop_f stored in call_ins.r
        if (
            call_ins.r is not None
            and call_ins.r.t == ida_hexrays.mop_f
            and hasattr(call_ins.r, "f")
            and call_ins.r.f is not None
        ):
            # Try the fast literal path first; fall back to per-arg AST eval.
            args_list = extract_literal_from_mop(call_ins.r) or _extract_args_from_mop_f(call_ins.r, _bits)

        # Pattern B: arguments packed in a mop_f stored in call_ins.d (observed when call_ins.r is mop_z)
        elif (
            call_ins.d is not None
            and call_ins.d.t == ida_hexrays.mop_f
            and hasattr(call_ins.d, "f")
            and call_ins.d.f is not None
        ):
            args_list = extract_literal_from_mop(call_ins.d) or _extract_args_from_mop_f(call_ins.d, _bits)

        # Pattern C: compact helper - r is value, d is shift amount
        elif call_ins.r is not None and call_ins.d is not None:
            val_ev = _try_eval_mop(call_ins.r, _bits)
            shift_ev = _try_eval_mop(call_ins.d, _bits)
            if val_ev is not None and shift_ev is not None:
                args_list = [val_ev, shift_ev]
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

        helper_func = _HelperLookup.lookup(helper_name)
        if helper_func is None:
            if logger.debug_on:
                logger.debug("[RotateHelperInline] helper %s not found in registry", helper_name)
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
