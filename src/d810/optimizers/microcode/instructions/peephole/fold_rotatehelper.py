from __future__ import annotations

import functools
from d810.core import typing

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.evaluator.helpers.rotate import _RotateHelper as _HelperLookup
from d810.hexrays.expr.ast import mop_to_ast
from d810.hexrays.expr.z3_utils import _find_def_in_block
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


def _resolve_mop_to_constant(
    mop: "ida_hexrays.mop_t",
    blk: "ida_hexrays.mblock_t | None",
    ins: "ida_hexrays.minsn_t | None",
    bits: int = 32,
) -> "int | None":
    """Resolve *mop* to a concrete integer constant, following def-chains.

    Resolution order:

    1. If *mop* is an immediate (``mop_n``): return its value directly.
    2. If *mop* is a register (``mop_r``) and *blk* is available: use
       :func:`_find_def_in_block` to locate the defining instruction.

       - If the def is ``mov #const -> reg``: return the constant.
       - If the def is a ROL/ROR call with all-constant args: evaluate and
         return the result.

    3. Otherwise fall back to ``_try_eval_mop`` (AST evaluation).

    Returns:
        The resolved integer value, or ``None`` if resolution failed.
    """
    if mop is None:
        return None

    # Fast path: immediate constant.
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value

    # Register def-search path (requires block context).
    if mop.t == ida_hexrays.mop_r and blk is not None and ins is not None:
        def_ins = _find_def_in_block(mop, blk, ins)
        if def_ins is not None:
            # Case 1: simple mov #const, reg
            if (
                def_ins.opcode == ida_hexrays.m_mov
                and def_ins.l is not None
                and def_ins.l.t == ida_hexrays.mop_n
            ):
                return def_ins.l.nnn.value

            # Case 2: mov call !ROL/ROR<const, const>, reg
            if (
                def_ins.opcode == ida_hexrays.m_mov
                and def_ins.l is not None
                and def_ins.l.t == ida_hexrays.mop_d
                and def_ins.l.d is not None
                and def_ins.l.d.opcode == ida_hexrays.m_call
                and is_rotate_helper_call(def_ins.l.d)
            ):
                inner_call = def_ins.l.d
                inner_helper_name = (
                    (inner_call.l.helper or "").lstrip("!")
                    if inner_call.l is not None
                    else ""
                )
                inner_helper_func = _HelperLookup.lookup(inner_helper_name) if inner_helper_name else None
                if inner_helper_func is not None:
                    # Try to extract args from the inner call.
                    inner_args = None
                    if (
                        inner_call.r is not None
                        and inner_call.r.t == ida_hexrays.mop_f
                        and getattr(inner_call.r, "f", None) is not None
                    ):
                        inner_args = (
                            extract_literal_from_mop(inner_call.r)
                            or _extract_args_from_mop_f(inner_call.r, bits)
                        )
                    elif (
                        inner_call.d is not None
                        and inner_call.d.t == ida_hexrays.mop_f
                        and getattr(inner_call.d, "f", None) is not None
                    ):
                        inner_args = (
                            extract_literal_from_mop(inner_call.d)
                            or _extract_args_from_mop_f(inner_call.d, bits)
                        )
                    elif inner_call.r is not None and inner_call.d is not None:
                        val_ev = _try_eval_mop(inner_call.r, bits)
                        shift_ev = _try_eval_mop(inner_call.d, bits)
                        if val_ev is not None and shift_ev is not None:
                            inner_args = [val_ev, shift_ev]
                    if inner_args and len(inner_args) == 2:
                        lhs_val, _ = inner_args[0]
                        rhs_val, _ = inner_args[1]
                        inner_size = def_ins.d.size if def_ins.d is not None else (bits // 8)
                        mask = AND_TABLE.get(inner_size, 0xFFFFFFFF)
                        return inner_helper_func(lhs_val, rhs_val) & mask

    # Slow path: AST evaluation (handles nested constant expressions).
    ev = _try_eval_mop(mop, bits)
    if ev is not None:
        return ev[0]
    return None


def _extract_args_from_mop_f(
    mop_f: "ida_hexrays.mop_t",
    bits: int,
    blk: "ida_hexrays.mblock_t | None" = None,
    ins: "ida_hexrays.minsn_t | None" = None,
) -> "list[tuple[int, int]] | None":
    """Extract two (value, size) pairs from an mop_f argument list.

    Each argument is evaluated via :func:`_try_eval_mop` so that nested
    constant expression trees are handled in addition to plain literals.
    When *blk* and *ins* are provided, falls back to :func:`_resolve_mop_to_constant`
    for register operands that can be resolved via def-search.
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
        if ev is None and blk is not None and ins is not None:
            v = _resolve_mop_to_constant(arg, blk, ins, bits)
            ev = (v, arg.size) if v is not None else None
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
        # Run at LOCOPT (early), GLBOPT1/GLBOPT2 (where IDA has already
        # propagated constants into helper call args), and GLBOPT3.
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
            getattr(ida_hexrays, "MMAT_GLBOPT2", ida_hexrays.MMAT_CALLS),
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

        # Broader path: for arithmetic, comparison, and conditional-jump
        # opcodes, scan l and r for mop_d sub-operands containing ROL/ROR
        # calls with constant args, and replace them in-place with mop_n
        # constants.
        _SCAN_OPCODES = frozenset({
            # Arithmetic
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_xor,
            ida_hexrays.m_or,
            ida_hexrays.m_and,
            ida_hexrays.m_mul,
            # Comparisons (set-cc)
            ida_hexrays.m_setnz,
            ida_hexrays.m_setz,
            ida_hexrays.m_setl,
            ida_hexrays.m_setle,
            ida_hexrays.m_setae,
            ida_hexrays.m_seta,
            ida_hexrays.m_setb,
            ida_hexrays.m_setbe,
            ida_hexrays.m_sets,
            # Conditional jumps
            ida_hexrays.m_jnz,
            ida_hexrays.m_jz,
            ida_hexrays.m_jl,
            ida_hexrays.m_jle,
            ida_hexrays.m_jae,
            ida_hexrays.m_ja,
            ida_hexrays.m_jb,
            ida_hexrays.m_jbe,
        })

        if ins.opcode in _SCAN_OPCODES:
            # Collect mutations to apply: list of (slot_index, result, slot_size)
            # where slot_index 0 = l, 1 = r.  We do NOT mutate `ins` in-place
            # because check_and_replace's contract requires returning a *new*
            # minsn_t so the caller can do ins.swap(new_ins) without it
            # becoming a self-swap (which corrupts the instruction, INTERR 50835).
            _bits_arith: int = ins.d.size * 8 if (ins.d is not None and ins.d.size) else 32
            pending: list[tuple[int, int, int]] = []  # (slot_index, result, slot_size)
            for slot_index, slot in enumerate((ins.l, ins.r)):
                if (
                    slot is None
                    or slot.t != ida_hexrays.mop_d
                    or slot.d is None
                    or slot.d.opcode != ida_hexrays.m_call
                    or not is_rotate_helper_call(slot.d)
                ):
                    continue
                call_ins = slot.d
                insn_helper_mop: ida_hexrays.mop_t = call_ins.l
                helper_name = (insn_helper_mop.helper or "").lstrip("!")
                if not helper_name:
                    continue
                # Extract args using same patterns as m_mov path
                args_list = None
                if (
                    call_ins.r is not None
                    and call_ins.r.t == ida_hexrays.mop_f
                    and hasattr(call_ins.r, "f")
                    and call_ins.r.f is not None
                ):
                    args_list = extract_literal_from_mop(call_ins.r) or _extract_args_from_mop_f(call_ins.r, _bits_arith, blk, ins)
                elif (
                    call_ins.d is not None
                    and call_ins.d.t == ida_hexrays.mop_f
                    and hasattr(call_ins.d, "f")
                    and call_ins.d.f is not None
                ):
                    args_list = extract_literal_from_mop(call_ins.d) or _extract_args_from_mop_f(call_ins.d, _bits_arith, blk, ins)
                elif call_ins.r is not None and call_ins.d is not None:
                    val_ev = _try_eval_mop(call_ins.r, _bits_arith)
                    if val_ev is None:
                        v = _resolve_mop_to_constant(call_ins.r, blk, ins, _bits_arith)
                        val_ev = (v, call_ins.r.size) if v is not None else None
                    shift_ev = _try_eval_mop(call_ins.d, _bits_arith)
                    if shift_ev is None:
                        s = _resolve_mop_to_constant(call_ins.d, blk, ins, _bits_arith)
                        shift_ev = (s, call_ins.d.size) if s is not None else None
                    if val_ev is not None and shift_ev is not None:
                        args_list = [val_ev, shift_ev]
                if not args_list or len(args_list) != 2:
                    continue
                helper_func = _HelperLookup.lookup(helper_name)
                if helper_func is None:
                    continue
                lhs_val, _ = args_list[0]
                rhs_val, _ = args_list[1]
                slot_size = slot.size if slot.size else (ins.d.size if ins.d else 4)
                mask = AND_TABLE.get(slot_size, 0xFFFFFFFF)
                result = helper_func(lhs_val, rhs_val) & mask
                if logger.debug_on:
                    logger.debug(
                        "[RotateHelperInline] arith ea=%X opcode=%s: folding %s(%s,%s) -> 0x%X in sub-operand",
                        sanitize_ea(ins.ea),
                        opcode_to_string(ins.opcode),
                        helper_name,
                        lhs_val,
                        rhs_val,
                        result,
                    )
                pending.append((slot_index, result, slot_size))
            if pending:
                # Build a fresh copy so the caller's ins.swap(new_ins) is not a
                # self-swap.  Apply the folded constants to the copy's slots.
                new_ins = ida_hexrays.minsn_t(ins)
                copy_slots = (new_ins.l, new_ins.r)
                for slot_index, result, slot_size in pending:
                    copy_slots[slot_index].make_number(result, slot_size)
                return new_ins

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
            args_list = extract_literal_from_mop(call_ins.r) or _extract_args_from_mop_f(call_ins.r, _bits, blk, ins)

        # Pattern B: arguments packed in a mop_f stored in call_ins.d (observed when call_ins.r is mop_z)
        elif (
            call_ins.d is not None
            and call_ins.d.t == ida_hexrays.mop_f
            and hasattr(call_ins.d, "f")
            and call_ins.d.f is not None
        ):
            args_list = extract_literal_from_mop(call_ins.d) or _extract_args_from_mop_f(call_ins.d, _bits, blk, ins)

        # Pattern C: compact helper - r is value, d is shift amount
        elif call_ins.r is not None and call_ins.d is not None:
            val_ev = _try_eval_mop(call_ins.r, _bits)
            if val_ev is None:
                v = _resolve_mop_to_constant(call_ins.r, blk, ins, _bits)
                val_ev = (v, call_ins.r.size) if v is not None else None
            shift_ev = _try_eval_mop(call_ins.d, _bits)
            if shift_ev is None:
                s = _resolve_mop_to_constant(call_ins.d, blk, ins, _bits)
                shift_ev = (s, call_ins.d.size) if s is not None else None
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
