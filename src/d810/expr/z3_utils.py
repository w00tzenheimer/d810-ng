"""IDA-specific Z3 utilities for microcode verification.

This module provides Z3 verification for IDA Pro microcode (AstNode, mop_t, minsn_t).
It is used at RUNTIME during deobfuscation to verify transformations are correct.

=============================================================================
ARCHITECTURE: Two Z3 Modules in d810
=============================================================================

There are TWO separate Z3 utility modules in d810, serving different purposes:

1. d810.mba.backends.z3 (PURE - no IDA)
   --------------------------------------
   Purpose: Verify optimization rules using pure symbolic expressions.
   Input:   d810.mba.dsl.SymbolicExpression (platform-independent DSL)
   Use:     Unit tests, CI, TDD rule development, mathematical verification

   Key exports:
   - Z3VerificationVisitor: Converts SymbolicExpression → Z3 BitVec
   - prove_equivalence(): Prove two SymbolicExpressions are equivalent
   - verify_rule(): Verify a rule's PATTERN equals its REPLACEMENT

2. THIS FILE: d810.expr.z3_utils (IDA-SPECIFIC)
   ---------------------------------------------
   Purpose: Z3 verification of actual IDA microcode during deobfuscation.
   Input:   d810.expr.ast.AstNode (wraps IDA mop_t/minsn_t)
   Use:     Runtime verification inside IDA Pro plugin

   Key exports:
   - ast_to_z3_expression(): Converts AstNode → Z3 BitVec
   - z3_check_mop_equality(): Check if two mop_t are semantically equivalent
   - z3_check_mop_inequality(): Check if two mop_t are NOT equivalent
   - log_z3_instructions(): Debug logging for Z3 verification

=============================================================================
WHY TWO MODULES?
=============================================================================

The separation enables:
1. Unit testing rules WITHOUT IDA Pro license
2. CI/CD pipeline verification (GitHub Actions)
3. TDD workflow: write rule → verify with Z3 → integrate with IDA
4. Clear dependency boundaries (mba/ never imports IDA modules)

If you need to verify a SymbolicExpression (from d810.mba.dsl), use:
    from d810.mba.backends.z3 import prove_equivalence

If you need to verify actual IDA microcode (AstNode/mop_t), use this module:
    from d810.expr.z3_utils import z3_check_mop_equality

=============================================================================
TODO: Refactor to Visitor Pattern
=============================================================================

This module is technical debt. It uses procedural functions (ast_to_z3_expression,
z3_prove_equivalence, etc.) instead of a clean visitor pattern like
Z3VerificationVisitor in mba/backends/z3.py.

The ideal architecture would be:

    class AstNodeZ3Visitor:
        '''Visitor that converts AstNode to Z3 for IDA microcode verification.'''
        def visit(self, node: AstNode) -> z3.BitVecRef: ...

This would:
1. Mirror the clean design of Z3VerificationVisitor
2. Make the code more maintainable and testable
3. Allow easier extension for new opcodes
4. Consolidate the scattered ast_to_z3_expression logic

Low priority since this code works and is only used at runtime inside IDA.
=============================================================================
"""

from __future__ import annotations

import functools
import typing
from typing import TYPE_CHECKING, Dict, Tuple

import ida_hexrays

from d810.core import getLogger
from d810.errors import D810Z3Exception
from d810.expr.ast import AstLeaf, AstNode, minsn_to_ast, mop_to_ast
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    opcode_to_string,
)
from d810.hexrays.hexrays_helpers import get_mop_index, structural_mop_hash
from d810.hexrays.mop_snapshot import MopSnapshot

logger = getLogger(__name__)
z3_file_logger = getLogger("D810.z3_test")

try:
    import z3

    Z3_INSTALLED = True
    # Since version 4.8.2, when Z3 is creating a BitVec, it relies on _str_to_bytes which uses sys.stdout.encoding
    # However, in IDA Pro (7.6sp1) sys.stdout is an object of type IDAPythonStdOut
    # which doesn't have a 'encoding' attribute, thus we set it to something, so that Z3 works
    import sys

    try:
        x = sys.stdout.encoding
    except AttributeError:
        logger.debug("Couldn't find sys.stdout.encoding, setting it to utf-8")
        sys.stdout.encoding = "utf-8"  # type: ignore
except ImportError:
    logger.info("Z3 features disabled. Install Z3 to enable them")
    Z3_INSTALLED = False


@functools.lru_cache(maxsize=1)
def requires_z3_installed(func: typing.Callable[..., typing.Any]):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not Z3_INSTALLED:
            raise D810Z3Exception("Z3 is not installed")
        return func(*args, **kwargs)

    return wrapper


@requires_z3_installed
@functools.lru_cache(maxsize=1)
def get_solver() -> z3.Solver:
    s = z3.Solver()
    # Bound solver work to prevent pathological slowdowns in hot paths.
    # 50ms per query is generally enough for our simple equalities and keeps
    # total time bounded in large functions.
    try:
        p = z3.ParamsRef()
        p.set("timeout", 50)  # milliseconds
        s.set(params=p)
    except Exception:
        # Older z3 versions or API quirks – ignore and keep default settings.
        pass
    return s


@requires_z3_installed
def create_z3_vars(leaf_list: list[AstLeaf]):
    known_leaf_list = []
    known_leaf_z3_var_list = []
    for leaf in leaf_list:
        if leaf.is_constant() or leaf.mop is None:
            continue
        leaf_index = get_mop_index(leaf.mop, known_leaf_list)
        if leaf_index == -1:
            known_leaf_list.append(leaf.mop)
            leaf_index = len(known_leaf_list) - 1
            if leaf.mop.size in [1, 2, 4, 8]:
                # Normally, we should create variable based on their size
                # but for now it can cause issue when instructions like XDU are used, hence this ugly fix
                # known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 8 * leaf.mop.size))
                known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
                pass
            else:
                known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
        leaf.z3_var = known_leaf_z3_var_list[leaf_index]
        leaf.z3_var_name = "x_{0}".format(leaf_index)
    return known_leaf_z3_var_list


@requires_z3_installed
def ast_to_z3_expression(ast: AstNode | AstLeaf | None, use_bitvecval=False):
    if ast is None:
        raise ValueError("ast is None")

    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        if ast.is_constant():
            # Check if this is a pattern-matching constant with z3_var assigned
            # (e.g., Const("c_1") without concrete value)
            if hasattr(ast, 'z3_var') and ast.z3_var is not None:
                return ast.z3_var  # Use symbolic Z3 variable
            # Concrete constant (e.g., Const("ONE", 1))
            return z3.BitVecVal(ast.value, 32)
        return ast.z3_var

    ast = typing.cast(AstNode, ast)
    left = ast_to_z3_expression(ast.left, use_bitvecval)
    right = ast_to_z3_expression(ast.right, use_bitvecval) if ast.right else None

    match ast.opcode:
        case ida_hexrays.m_neg:
            return -left
        case ida_hexrays.m_lnot:
            # Logical NOT (!) returns 1 when the operand is zero, otherwise 0.
            # Implemented via a 32-bit conditional expression to avoid casting the
            # symbolic BitVec to a Python bool (which would raise a Z3 exception).
            return z3.If(
                left == z3.BitVecVal(0, 32),
                z3.BitVecVal(1, 32),
                z3.BitVecVal(0, 32),
            )
        case ida_hexrays.m_bnot:
            return ~left
        case ida_hexrays.m_add:
            return left + right
        case ida_hexrays.m_sub:
            return left - right
        case ida_hexrays.m_mul:
            return left * right
        case ida_hexrays.m_udiv:
            return z3.UDiv(
                ast_to_z3_expression(ast.left, use_bitvecval=True),
                ast_to_z3_expression(ast.right, use_bitvecval=True),
            )
        case ida_hexrays.m_sdiv:
            return left / right
        case ida_hexrays.m_umod:
            return z3.URem(left, right)
        case ida_hexrays.m_smod:
            return left % right
        case ida_hexrays.m_or:
            return left | right
        case ida_hexrays.m_and:
            return left & right
        case ida_hexrays.m_xor:
            return left ^ right
        case ida_hexrays.m_shl:
            return left << right
        case ida_hexrays.m_shr:
            return z3.LShR(left, right)
        case ida_hexrays.m_sar:
            return left >> right
        case ida_hexrays.m_setnz:
            return z3.If(
                left != z3.BitVecVal(0, 32), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)
            )
        case ida_hexrays.m_setz:
            return z3.If(
                left == z3.BitVecVal(0, 32), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)
            )
        case ida_hexrays.m_setae:
            return z3.If(z3.UGE(left, right), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setb:
            return z3.If(z3.ULT(left, right), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_seta:
            return z3.If(z3.UGT(left, right), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setbe:
            return z3.If(z3.ULE(left, right), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setg:
            return z3.If(left > right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setge:
            return z3.If(left >= right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setl:
            return z3.If(left < right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setle:
            return z3.If(left <= right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_setp:
            # 1) isolate the low byte
            lo_byte = typing.cast(z3.BitVecRef, z3.Extract(7, 0, left))
            # 2) XOR-reduce the eight single-bit slices to get 1 → odd, 0 → even
            bit0 = typing.cast(z3.BitVecRef, z3.Extract(0, 0, lo_byte))
            parity_bv = bit0  # 1-bit BitVec
            for i in range(1, 8):
                parity_bv = parity_bv ^ z3.Extract(i, i, lo_byte)
            # 3) PF is set (==1) when the parity is EVEN, i.e. parity_bv == 0
            pf_is_set = parity_bv == z3.BitVecVal(0, 1)  # Bool
            # 4) widen to 32-bit {1,0}
            return z3.If(pf_is_set, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_sets:
            val = left  # BitVec(32)
            is_negative = val < z3.BitVecVal(
                0, 32
            )  # ordinary "<" is signed-less-than in Z3Py
            return z3.If(is_negative, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        case ida_hexrays.m_xdu | ida_hexrays.m_xds:
            # Extend or keep the same width; in our simplified model we just forward.
            return left
        case ida_hexrays.m_low:
            # Extract the lower half (dest_size) bits of the operand.
            dest_bits = (ast.dest_size or 4) * 8  # default 32-bit
            # Ensure we do not attempt to extract beyond the source width
            high_bit = min(dest_bits - 1, left.size() - 1)
            extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, left))
            # Zero-extend to 32-bit so subsequent operations (which assume 32-bit) do not
            # trigger sort-mismatch errors when combined with other 32-bit expressions.
            if extracted.size() < 32:
                extracted = typing.cast(
                    z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
                )
            return extracted
        case ida_hexrays.m_high:
            # Extract the upper half of the operand by shifting right by dest_bits
            dest_bits = (ast.dest_size or 4) * 8  # default 32-bit
            shifted = z3.LShR(left, dest_bits)
            high_bit = min(dest_bits - 1, shifted.size() - 1)
            extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, shifted))
            # Zero-extend to 32-bit for consistency with the rest of the engine.
            if extracted.size() < 32:
                extracted = typing.cast(
                    z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
                )
            return extracted
        case _:
            # Gracefully fail on unknown opcode; avoid type issues in logging
            op = getattr(ast, "opcode", None)
            op_str = opcode_to_string(int(op)) if isinstance(op, int) else str(op)
            raise D810Z3Exception(f"Z3 evaluation: Unknown opcode {op_str} for {ast}")


@requires_z3_installed
def mop_list_to_z3_expression_list(mop_list: list[ida_hexrays.mop_t]):
    if logger.debug_on:
        logger.debug(
            "mop_list_to_z3_expression_list: mop_list: %s",
            [format_mop_t(mop) for mop in mop_list],
        )
    ast_list = [mop_to_ast(mop) for mop in mop_list]
    # Filter out None ASTs - callers check length to detect conversion failures
    valid_ast_list = [ast for ast in ast_list if ast is not None]
    if len(valid_ast_list) != len(ast_list):
        logger.debug(
            "mop_list_to_z3_expression_list: %d of %d mops failed AST conversion",
            len(ast_list) - len(valid_ast_list),
            len(ast_list),
        )
    ast_leaf_list = []
    for ast in valid_ast_list:
        ast_leaf_list += ast.get_leaf_list()
    _ = create_z3_vars(ast_leaf_list)
    if logger.debug_on:
        logger.debug(
            "mop_list_to_z3_expression_list: ast_leaf_list: %s",
            ast_leaf_list,
        )
    return [ast_to_z3_expression(ast) for ast in valid_ast_list]


# Module-level memoization for Z3 checks
_Z3_EQ_CACHE: Dict[Tuple[Tuple[int, int, int|str], Tuple[int, int, int|str]], bool] = {}


@requires_z3_installed
def z3_check_mop_equality(
    mop1: ida_hexrays.mop_t | None,
    mop2: ida_hexrays.mop_t | None,
    solver: z3.Solver | None = None,
) -> bool:
    if mop1 is None or mop2 is None:
        return False
    # Convert MopSnapshot to mop_t at boundary
    if isinstance(mop1, MopSnapshot):
        mop1 = mop1.to_mop()
    if isinstance(mop2, MopSnapshot):
        mop2 = mop2.to_mop()
    # Validate SWIG objects before accessing their attributes
    # Invalid/freed SWIG objects will not have essential attributes
    if not hasattr(mop1, 't') or not hasattr(mop1, 'size'):
        logger.warning("z3_check_mop_equality: mop1 is invalid or freed SWIG object")
        return False
    if not hasattr(mop2, 't') or not hasattr(mop2, 'size'):
        logger.warning("z3_check_mop_equality: mop2 is invalid or freed SWIG object")
        return False
    # TODO(w00tzenheimer): should we use this?
    # # Quick positives when both operands share type/size.
    # if mop1.t == mop2.t and mop1.size == mop2.size:
    #     if mop1.t == mop_n:
    #         return mop1.nnn.value == mop2.nnn.value
    #     if mop1.t == mop_r:
    #         return mop1.r == mop2.r
    #     if mop1.t == mop_S:
    #         # Direct comparison of stack var refs suffices.
    #         return mop1.s == mop2.s
    #     if mop1.t == mop_v:
    #         return mop1.g == mop2.g
    #     if mop1.t == mop_d:
    #         return mop1.dstr() == mop2.dstr()
    # If quick checks didn't decide, fall back to Z3 even when types differ.
    if logger.debug_on:
        logger.debug(
            "z3_check_mop_equality: mop1: %s, mop2: %s",
            format_mop_t(mop1),
            format_mop_t(mop2),
        )
        logger.debug(
            "z3_check_mop_equality:\n\tmop1.dstr(): %s\n\tmop2.dstr(): %s\n\thashes: %016X vs %016X",
            mop1.dstr(),
            mop2.dstr(),
            structural_mop_hash(mop1, 0),
            structural_mop_hash(mop2, 0),
        )
    # If pre-filters don't apply, fall back to Z3 with a memoized check keyed by
    # a cheap representation of the operands.
    try:
        k1 = (int(mop1.t), int(mop1.size), structural_mop_hash(mop1, 0))
        k2 = (int(mop2.t), int(mop2.size), structural_mop_hash(mop2, 0))
    except Exception:
        k1 = (int(mop1.t), int(mop1.size), mop1.dstr() if hasattr(mop1, 'dstr') else repr(mop1))
        k2 = (int(mop2.t), int(mop2.size), mop2.dstr() if hasattr(mop2, 'dstr') else repr(mop2))
    if k2 < k1:
        k1, k2 = k2, k1
    cache_key = (k1, k2)
    cached = _Z3_EQ_CACHE.get(cache_key)
    if cached is not None:
        return cached
    exprs = mop_list_to_z3_expression_list([mop1, mop2])
    if len(exprs) != 2:
        return False
    z3_mop1, z3_mop2 = exprs
    _solver = solver if solver is not None else get_solver()
    _solver.push()
    _solver.add(z3.Not(z3_mop1 == z3_mop2))
    is_equal = _solver.check() == z3.unsat
    _solver.pop()
    _Z3_EQ_CACHE[cache_key] = is_equal
    return is_equal


_Z3_NEQ_CACHE: Dict[Tuple[Tuple[int, int, int|str], Tuple[int, int, int|str]], bool] = {}

_Z3_ALWAYS_ZERO_CACHE: Dict[Tuple[int, int, int|str], bool] = {}
_Z3_ALWAYS_NONZERO_CACHE: Dict[Tuple[int, int, int|str], bool] = {}


@requires_z3_installed
def z3_check_mop_inequality(
    mop1: ida_hexrays.mop_t | None,
    mop2: ida_hexrays.mop_t | None,
    solver: z3.Solver | None = None,
) -> bool:
    if mop1 is None or mop2 is None:
        return True
    # Convert MopSnapshot to mop_t at boundary
    if isinstance(mop1, MopSnapshot):
        mop1 = mop1.to_mop()
    if isinstance(mop2, MopSnapshot):
        mop2 = mop2.to_mop()
    # Validate SWIG objects before accessing their attributes
    # Invalid/freed SWIG objects will not have essential attributes
    if not hasattr(mop1, 't') or not hasattr(mop1, 'size'):
        logger.warning("z3_check_mop_inequality: mop1 is invalid or freed SWIG object")
        return True
    if not hasattr(mop2, 't') or not hasattr(mop2, 'size'):
        logger.warning("z3_check_mop_inequality: mop2 is invalid or freed SWIG object")
        return True
    # TODO(w00tzenheimer): should we use this?
    # if mop1.t == mop2.t and mop1.size == mop2.size:
    #     # Quick negatives when structure same.
    #     if mop1.t == mop_n:
    #         return mop1.nnn.value != mop2.nnn.value
    #     if mop1.t == mop_r:
    #         return mop1.r != mop2.r
    #     if mop1.t == mop_S:
    #         return mop1.s != mop2.s
    #     if mop1.t == mop_v:
    #         return mop1.g != mop2.g
    #     if mop1.t == mop_d:
    #         return mop1.dstr() != mop2.dstr()
    # Otherwise fall back to Z3 (also handles differing types).
    if logger.debug_on:
        logger.debug(
            "z3_check_mop_inequality: mop1: %s, mop2: %s",
            format_mop_t(mop1),
            format_mop_t(mop2),
        )
        logger.debug(
            "z3_check_mop_inequality:\n\tmop1.dstr(): %s\n\tmop2.dstr(): %s\n\thashes: %016X vs %016X",
            mop1.dstr(),
            mop2.dstr(),
            structural_mop_hash(mop1, 0),
            structural_mop_hash(mop2, 0),
        )
    # If pre-filters don't apply, fall back to Z3 with a memoized check keyed by
    # a cheap representation of the operands.
    try:
        k1 = (int(mop1.t), int(mop1.size), structural_mop_hash(mop1, 0))
        k2 = (int(mop2.t), int(mop2.size), structural_mop_hash(mop2, 0))
    except Exception:
        k1 = (int(mop1.t), int(mop1.size), mop1.dstr() if hasattr(mop1, 'dstr') else repr(mop1))
        k2 = (int(mop2.t), int(mop2.size), mop2.dstr() if hasattr(mop2, 'dstr') else repr(mop2))
    if k2 < k1:
        k1, k2 = k2, k1
    if k2 < k1:
        k1, k2 = k2, k1
    cache_key = (k1, k2)
    cached = _Z3_NEQ_CACHE.get(cache_key)
    if cached is not None:
        return cached
    exprs = mop_list_to_z3_expression_list([mop1, mop2])
    if len(exprs) != 2:
        return True
    z3_mop1, z3_mop2 = exprs
    _solver = solver if solver is not None else get_solver()
    _solver.push()
    _solver.add(z3_mop1 == z3_mop2)
    is_unequal = _solver.check() == z3.unsat
    _solver.pop()
    _Z3_NEQ_CACHE[cache_key] = is_unequal
    return is_unequal


def _resolve_memory_load_via_store(
    ldx_ins: ida_hexrays.minsn_t,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
) -> "AstNode | AstLeaf | None":
    """Resolve a memory load (m_ldx) to its defining store (m_stx).

    When we have an m_ldx instruction that loads from memory, we search backward
    to find the m_stx instruction that stored to the same memory location.

    Args:
        ldx_ins: The m_ldx instruction to resolve
        blk: The block containing the instruction
        ins: The instruction where the load is used

    Returns:
        The AST of the stored value, or None if not found
    """
    # m_ldx format: ldx result, segment, address
    # m_stx format: stx value, segment, address
    # We need to match the address operand (r) between load and store

    load_addr = ldx_ins.r  # Address being loaded from

    if load_addr is None:
        return None

    # Search backward through the block for a matching store
    cur_ins = ins.prev if ins else blk.tail

    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_stx:
            # m_stx format: stx value, segment, address
            store_addr = cur_ins.r  # Address being stored to

            # Check if addresses match
            if store_addr is not None and load_addr is not None:
                # Simple equality check - compare address operands
                try:
                    from d810.hexrays.hexrays_helpers import equal_mops_ignore_size
                    if equal_mops_ignore_size(load_addr, store_addr):
                        # Found matching store - return AST of stored value
                        # The stored value is in ldx_ins.l for stx
                        stored_value = cur_ins.l
                        if stored_value is not None:
                            ast = mop_to_ast(stored_value)
                            if logger.debug_on:
                                logger.debug(
                                    "_resolve_memory_load_via_store: Resolved ldx to stx: %s -> %s",
                                    format_minsn_t(ldx_ins),
                                    format_minsn_t(cur_ins)
                                )
                            return ast
                except Exception as e:
                    logger.debug("_resolve_memory_load_via_store: Error comparing mops: %s", e)

        cur_ins = cur_ins.prev

    logger.debug(
        "_resolve_memory_load_via_store: No matching store found for %s",
        format_minsn_t(ldx_ins)
    )
    return None


def _resolve_mop_to_ast_via_tracker(
    mop: ida_hexrays.mop_t,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
) -> "AstNode | AstLeaf | None":
    """Use MopTracker to find the instruction that defines mop, return its AST.

    This function is used to resolve register/stack variables to their defining
    expressions. For example, if we have:
        eax.4 = (x.4 * (x.4 - 1.4)) & 1.4
        setz eax.4, 0.4, cf.1

    When analyzing the setz instruction, eax.4 is just a register (mop_r), but
    by tracking backward we can find that it's actually the expression
    (x * (x-1)) & 1, which we can then prove is always 0.

    Also handles mop_d with m_ldx (memory loads). When we have:
        ADD(LDX(mem1), LDX(mem2))
    The loads read from memory locations. We track backward to find the stores
    that wrote to those locations and return the AST of the stored values.

    Args:
        mop: The mop_t to resolve (typically a register or stack variable,
             or mop_d with m_ldx for memory loads)
        blk: The block containing the instruction
        ins: The instruction where mop is used

    Returns:
        The AST of the defining instruction's RHS, or None if not found
    """
    # Handle mop_d with m_ldx - resolve memory loads to their defining stores
    if mop.t == ida_hexrays.mop_d:
        nested = mop.d
        if nested is not None and nested.opcode == ida_hexrays.m_ldx:
            # m_ldx format: ldx result, segment, address
            # The destination (nested.d) is where the loaded value goes
            # We need to track that destination backwards to find its definition
            if nested.d is not None:
                dest_mop = nested.d
                # If the destination is a register or stack var, track it
                if dest_mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S):
                    # Recursively resolve using the destination
                    return _resolve_mop_to_ast_via_tracker(dest_mop, blk, ins)
            # If we can't resolve via destination, try the address operand
            # to find a matching store (m_stx) instruction
            return _resolve_memory_load_via_store(nested, blk, ins)
        # For other mop_d types, no resolution possible
        return None

    # Only track register/stack variables - other types already have full AST info
    if mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
        return None

    try:
        from d810.hexrays.tracker import MopTracker
    except ImportError:
        logger.debug("_resolve_mop_to_ast_via_tracker: MopTracker not available")
        return None

    # Create tracker for this mop with limited scope (block-local only)
    # max_nb_block=1 ensures we only search within the current block
    # max_path=1 limits to a single path (no branching)
    try:
        MopTracker.reset()  # Reset global path counter
        tracker = MopTracker([mop], max_nb_block=1, max_path=1)
        histories = tracker.search_backward(blk, ins)
    except Exception as e:
        logger.debug("_resolve_mop_to_ast_via_tracker: Tracker failed: %s", e)
        return None

    if not histories:
        logger.debug("_resolve_mop_to_ast_via_tracker: No history found for %s",
                     format_mop_t(mop))
        return None

    # Get the first (and only) history
    history = histories[0]

    # Look for the defining instruction in the history
    # The history contains BlockInfo objects with instruction lists
    for blk_info in history.history:
        for def_ins in blk_info.ins_list:
            # Check if this instruction defines our mop
            # The defining instruction writes to our mop as its destination
            if def_ins.d is not None and def_ins.d.t == mop.t:
                # For registers, check if it's the same register
                if mop.t == ida_hexrays.mop_r and def_ins.d.r == mop.r:
                    # Build AST from the instruction's source operands
                    ast = minsn_to_ast(def_ins)
                    if logger.debug_on:
                        logger.debug(
                            "_resolve_mop_to_ast_via_tracker: Resolved %s to %s from %s",
                            format_mop_t(mop), ast, format_minsn_t(def_ins)
                        )
                    return ast
                # For stack variables, compare the stack offset
                elif mop.t == ida_hexrays.mop_S:
                    try:
                        if def_ins.d.s.off == mop.s.off:
                            ast = minsn_to_ast(def_ins)
                            if logger.debug_on:
                                logger.debug(
                                    "_resolve_mop_to_ast_via_tracker: Resolved %s to %s from %s",
                                    format_mop_t(mop), ast, format_minsn_t(def_ins)
                                )
                            return ast
                    except AttributeError:
                        pass

    logger.debug("_resolve_mop_to_ast_via_tracker: No defining instruction found for %s",
                 format_mop_t(mop))
    return None


def _recursively_resolve_ast(
    ast: "AstNode | AstLeaf | None",
    blk: "ida_hexrays.mblock_t",
    ins: "ida_hexrays.minsn_t",
    depth: int = 0,
    max_depth: int = 10,
) -> "AstNode | AstLeaf | None":
    """Recursively resolve register/stack leaves in an AST to their defining expressions.

    This function handles multi-instruction expressions like:
        t1 = sub(x, 1)
        t2 = mul(t1, x)
        t3 = and(t2, 1)
        setz(t3, 0)

    Without recursive resolution, we'd only get `and(t2, 1)` where `t2` is still
    a register. With recursive resolution, we get the full expression:
        `and(mul(sub(x, 1), x), 1)` which Z3 can prove is always 0.

    Args:
        ast: The AST to resolve
        blk: Current block for backward search
        ins: Current instruction for backward search
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent infinite loops

    Returns:
        AST with register/stack leaves replaced by their defining expressions
    """
    if depth >= max_depth:
        return ast

    if ast is None:
        return None

    # If it's a leaf with a register/stack mop or memory load, try to resolve it
    if ast.is_leaf():
        ast_leaf = typing.cast(AstLeaf, ast)
        if ast_leaf.mop is not None:
            # Check for resolvable mop types: registers, stack vars, or memory loads
            is_resolvable = ast_leaf.mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
            # Also check for mop_d with m_ldx (memory loads)
            if not is_resolvable and ast_leaf.mop.t == ida_hexrays.mop_d:
                nested = ast_leaf.mop.d
                if nested is not None and nested.opcode == ida_hexrays.m_ldx:
                    is_resolvable = True

            if is_resolvable:
                resolved = _resolve_mop_to_ast_via_tracker(ast_leaf.mop, blk, ins)
                if resolved is not None and resolved is not ast:
                    # Recursively resolve the new AST
                    return _recursively_resolve_ast(resolved, blk, ins, depth + 1, max_depth)
        return ast

    # For non-leaf nodes, recursively resolve children
    ast_node = typing.cast(AstNode, ast)

    new_left = _recursively_resolve_ast(ast_node.left, blk, ins, depth, max_depth) if ast_node.left else None
    new_right = _recursively_resolve_ast(ast_node.right, blk, ins, depth, max_depth) if ast_node.right else None

    # If children changed, create new AST node
    if new_left is not ast_node.left or new_right is not ast_node.right:
        # Create a new AstNode with the same opcode but resolved children
        new_ast = AstNode(ast_node.opcode, new_left, new_right)
        new_ast.mop = ast_node.mop  # Preserve original mop info
        new_ast.dest_size = ast_node.dest_size
        new_ast.ea = ast_node.ea
        if logger.debug_on:
            logger.debug(
                "_recursively_resolve_ast: Rebuilt AST node: %s -> %s",
                ast_node, new_ast
            )
        return new_ast

    return ast


@requires_z3_installed
def z3_check_always_zero(
    mop: ida_hexrays.mop_t,
    blk: ida_hexrays.mblock_t | None = None,
    ins: ida_hexrays.minsn_t | None = None,
) -> bool:
    """Prove that mop evaluates to 0 for ALL possible inputs.

    Used to detect opaque predicates like (x * (x-1)) & 1 which is always 0.

    If mop is a register/stack variable and blk/ins are provided, uses MopTracker
    to find the defining expression and prove that is always zero.

    Args:
        mop: The microcode operand to analyze.
        blk: Optional block containing the instruction (for backward tracking).
        ins: Optional instruction where mop is used (for backward tracking).

    Returns:
        True if proven always zero, False otherwise.
    """
    if mop is None:
        return False
    # Convert MopSnapshot to mop_t at boundary
    if isinstance(mop, MopSnapshot):
        mop = mop.to_mop()
    # Validate SWIG object
    if not hasattr(mop, 't') or not hasattr(mop, 'size'):
        logger.warning("z3_check_always_zero: mop is invalid or freed SWIG object")
        return False

    # Check cache first
    try:
        cache_key = (int(mop.t), int(mop.size), structural_mop_hash(mop, 0))
    except Exception:
        cache_key = (int(mop.t), int(mop.size), mop.dstr() if hasattr(mop, 'dstr') else repr(mop))

    cached = _Z3_ALWAYS_ZERO_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # First try direct AST conversion
    ast = mop_to_ast(mop)

    # Determine if mop is resolvable (register/stack var or memory load)
    is_resolvable = mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
    if not is_resolvable and mop.t == ida_hexrays.mop_d:
        nested = mop.d
        if nested is not None and nested.opcode == ida_hexrays.m_ldx:
            is_resolvable = True

    # If mop is resolvable and we have context, try to find its definition
    if ast is None or (hasattr(ast, 'is_leaf') and ast.is_leaf() and is_resolvable):
        if blk is not None and ins is not None:
            resolved_ast = _resolve_mop_to_ast_via_tracker(mop, blk, ins)
            if resolved_ast is not None:
                ast = resolved_ast
                if logger.debug_on:
                    logger.debug(
                        "z3_check_always_zero: Resolved %s via tracker to AST: %s",
                        format_mop_t(mop), ast
                    )

    # Recursively resolve any register/stack leaves in the AST
    if ast is not None and blk is not None and ins is not None:
        ast = _recursively_resolve_ast(ast, blk, ins)
        if logger.debug_on:
            logger.debug(
                "z3_check_always_zero: After recursive resolution: %s",
                ast
            )

    if ast is None:
        _Z3_ALWAYS_ZERO_CACHE[cache_key] = False
        return False

    leaf_list = ast.get_leaf_list()
    create_z3_vars(leaf_list)

    try:
        z3_expr = ast_to_z3_expression(ast)
    except Exception as e:
        logger.debug("z3_check_always_zero: Failed to convert to Z3: %s", e)
        _Z3_ALWAYS_ZERO_CACHE[cache_key] = False
        return False

    if z3_expr is None:
        _Z3_ALWAYS_ZERO_CACHE[cache_key] = False
        return False

    solver = get_solver()
    solver.push()
    try:
        # Try to find ANY input where expr != 0
        # If unsat, expr is always 0
        solver.add(z3_expr != z3.BitVecVal(0, z3_expr.size()))
        result = solver.check() == z3.unsat
    except Exception as e:
        logger.debug("z3_check_always_zero: Z3 solver error: %s", e)
        result = False
    finally:
        solver.pop()

    _Z3_ALWAYS_ZERO_CACHE[cache_key] = result
    return result


@requires_z3_installed
def z3_check_always_nonzero(
    mop: ida_hexrays.mop_t,
    blk: ida_hexrays.mblock_t | None = None,
    ins: ida_hexrays.minsn_t | None = None,
) -> bool:
    """Prove that mop evaluates to non-zero for ALL possible inputs.

    If mop is a register/stack variable and blk/ins are provided, uses MopTracker
    to find the defining expression and prove that is always nonzero.

    Args:
        mop: The microcode operand to analyze.
        blk: Optional block containing the instruction (for backward tracking).
        ins: Optional instruction where mop is used (for backward tracking).

    Returns:
        True if proven always nonzero, False otherwise.
    """
    if mop is None:
        return False
    # Convert MopSnapshot to mop_t at boundary
    if isinstance(mop, MopSnapshot):
        mop = mop.to_mop()
    # Validate SWIG object
    if not hasattr(mop, 't') or not hasattr(mop, 'size'):
        logger.warning("z3_check_always_nonzero: mop is invalid or freed SWIG object")
        return False

    # Check cache first
    try:
        cache_key = (int(mop.t), int(mop.size), structural_mop_hash(mop, 0))
    except Exception:
        cache_key = (int(mop.t), int(mop.size), mop.dstr() if hasattr(mop, 'dstr') else repr(mop))

    cached = _Z3_ALWAYS_NONZERO_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # First try direct AST conversion
    ast = mop_to_ast(mop)

    # Determine if mop is resolvable (register/stack var or memory load)
    is_resolvable = mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
    if not is_resolvable and mop.t == ida_hexrays.mop_d:
        nested = mop.d
        if nested is not None and nested.opcode == ida_hexrays.m_ldx:
            is_resolvable = True

    # If mop is resolvable and we have context, try to find its definition
    if ast is None or (hasattr(ast, 'is_leaf') and ast.is_leaf() and is_resolvable):
        if blk is not None and ins is not None:
            resolved_ast = _resolve_mop_to_ast_via_tracker(mop, blk, ins)
            if resolved_ast is not None:
                ast = resolved_ast
                if logger.debug_on:
                    logger.debug(
                        "z3_check_always_nonzero: Resolved %s via tracker to AST: %s",
                        format_mop_t(mop), ast
                    )

    # Recursively resolve any register/stack leaves in the AST
    if ast is not None and blk is not None and ins is not None:
        ast = _recursively_resolve_ast(ast, blk, ins)
        if logger.debug_on:
            logger.debug(
                "z3_check_always_nonzero: After recursive resolution: %s",
                ast
            )

    if ast is None:
        _Z3_ALWAYS_NONZERO_CACHE[cache_key] = False
        return False

    leaf_list = ast.get_leaf_list()
    create_z3_vars(leaf_list)

    try:
        z3_expr = ast_to_z3_expression(ast)
    except Exception as e:
        logger.debug("z3_check_always_nonzero: Failed to convert to Z3: %s", e)
        _Z3_ALWAYS_NONZERO_CACHE[cache_key] = False
        return False

    if z3_expr is None:
        _Z3_ALWAYS_NONZERO_CACHE[cache_key] = False
        return False

    solver = get_solver()
    solver.push()
    try:
        # Try to find ANY input where expr == 0
        # If unsat, expr is always nonzero
        solver.add(z3_expr == z3.BitVecVal(0, z3_expr.size()))
        result = solver.check() == z3.unsat
    except Exception as e:
        logger.debug("z3_check_always_nonzero: Z3 solver error: %s", e)
        result = False
    finally:
        solver.pop()

    _Z3_ALWAYS_NONZERO_CACHE[cache_key] = result
    return result


@requires_z3_installed
def rename_leafs(leaf_list: list[AstLeaf]) -> list[str]:
    known_leaf_list = []
    for leaf in leaf_list:
        if leaf.is_constant() or leaf.mop is None:
            continue

        if leaf.mop.t == ida_hexrays.mop_z:
            continue

        leaf_index = get_mop_index(leaf.mop, known_leaf_list)
        if leaf_index == -1:
            known_leaf_list.append(leaf.mop)
            leaf_index = len(known_leaf_list) - 1
        leaf.z3_var_name = "x_{0}".format(leaf_index)

    return [
        "x_{0} = BitVec('x_{0}', {1})".format(i, 8 * leaf.size)
        for i, leaf in enumerate(known_leaf_list)
    ]


@requires_z3_installed
def log_z3_instructions(
    original_ins: ida_hexrays.minsn_t, new_ins: ida_hexrays.minsn_t
):
    orig_mba_tree = minsn_to_ast(original_ins)
    new_mba_tree = minsn_to_ast(new_ins)
    if orig_mba_tree is None or new_mba_tree is None:
        return None
    orig_leaf_list = orig_mba_tree.get_leaf_list()
    new_leaf_list = new_mba_tree.get_leaf_list()

    var_def_list = rename_leafs(orig_leaf_list + new_leaf_list)

    z3_file_logger.info(
        "print('Testing: {0} == {1}')".format(
            format_minsn_t(original_ins), format_minsn_t(new_ins)
        )
    )
    for var_def in var_def_list:
        z3_file_logger.info("{0}".format(var_def))

    removed_xdu = "{0}".format(orig_mba_tree).replace("xdu", "")
    z3_file_logger.info("original_expr = {0}".format(removed_xdu))
    removed_xdu = "{0}".format(new_mba_tree).replace("xdu", "")
    z3_file_logger.info("new_expr = {0}".format(removed_xdu))
    z3_file_logger.info("prove(original_expr == new_expr)\n")


@requires_z3_installed
def z3_prove_equivalence(
    pattern_ast: AstNode | AstLeaf,
    replacement_ast: AstNode | AstLeaf,
    z3_vars: dict[str, typing.Any] | None = None,
    constraints: list[typing.Any] | None = None,
    bit_width: int = 32,
) -> tuple[bool, dict[str, int] | None]:
    """Prove that two AST patterns are semantically equivalent using Z3.

    This function creates Z3 symbolic variables for each unique variable in the
    patterns, converts both patterns to Z3 expressions, and attempts to prove
    that they are equivalent for all possible variable values (subject to any
    provided constraints).

    Args:
        pattern_ast: The first AST pattern (typically the pattern to match).
        replacement_ast: The second AST pattern (typically the replacement).
        z3_vars: Optional pre-created Z3 variables mapping names to Z3 BitVec objects.
                 If None, variables will be created automatically.
        constraints: Optional list of Z3 constraint expressions that must hold for
                     the equivalence to be valid. For example, [c2 == ~c1] to indicate
                     that constant c2 must be the bitwise NOT of constant c1.
        bit_width: The bit width for symbolic variables (default 32).

    Returns:
        A tuple of (is_equivalent, counterexample):
        - is_equivalent: True if the patterns are proven equivalent, False otherwise.
        - counterexample: If not equivalent, a dict mapping variable names to values
                         that demonstrate the difference. None if equivalent.

    Example:
        >>> from d810.expr.ast import AstNode, AstLeaf
        >>> from ida_hexrays import m_add, m_sub, m_xor, m_or, m_and
        >>> # Pattern: (x | y) - (x & y)
        >>> pattern = AstNode(m_sub,
        ...     AstNode(m_or, AstLeaf("x"), AstLeaf("y")),
        ...     AstNode(m_and, AstLeaf("x"), AstLeaf("y")))
        >>> # Replacement: x ^ y
        >>> replacement = AstNode(m_xor, AstLeaf("x"), AstLeaf("y"))
        >>> is_equiv, counter = z3_prove_equivalence(pattern, replacement)
        >>> assert is_equiv  # These are mathematically equivalent
    """
    # Get all leaf nodes from both patterns to find variables
    pattern_leaves = pattern_ast.get_leaf_list()
    replacement_leaves = replacement_ast.get_leaf_list()
    all_leaves = pattern_leaves + replacement_leaves

    # If z3_vars not provided, create them
    if z3_vars is None:
        # Extract unique variable names (excluding constants)
        var_names = set()
        for leaf in all_leaves:
            if not leaf.is_constant() and hasattr(leaf, 'name'):
                var_names.add(leaf.name)

        # Create Z3 BitVec for each variable
        z3_vars = {name: z3.BitVec(name, bit_width) for name in sorted(var_names)}

        # Map the z3_vars to the leaves for conversion
        for leaf in all_leaves:
            if not leaf.is_constant() and hasattr(leaf, 'name') and leaf.name in z3_vars:
                leaf.z3_var = z3_vars[leaf.name]
                leaf.z3_var_name = leaf.name
    else:
        # Use provided z3_vars (includes both variables and pattern-matching constants)
        for leaf in all_leaves:
            if not hasattr(leaf, 'name'):
                continue

            # Assign z3_var to regular variables
            if not leaf.is_constant() and leaf.name in z3_vars:
                leaf.z3_var = z3_vars[leaf.name]
                leaf.z3_var_name = leaf.name
            # Also assign z3_var to pattern-matching constants (symbolic constants)
            elif leaf.is_constant() and leaf.name in z3_vars:
                # Pattern-matching constant like Const("c_1") - treat as symbolic
                if hasattr(leaf, 'expected_value') and leaf.expected_value is None:
                    leaf.z3_var = z3_vars[leaf.name]
                    leaf.z3_var_name = leaf.name

    # Convert both AST patterns to Z3 expressions
    try:
        pattern_z3 = ast_to_z3_expression(pattern_ast)
        replacement_z3 = ast_to_z3_expression(replacement_ast)
    except Exception as e:
        logger.error(
            "Failed to convert AST to Z3 expression: %s",
            e,
            exc_info=True,
        )
        return False, None

    # Create a solver and add constraints if any
    solver = z3.Solver()
    if constraints:
        for constraint in constraints:
            solver.add(constraint)

    # To prove equivalence, we check if NOT(pattern == replacement) is unsatisfiable
    # If it's unsatisfiable, then pattern == replacement for all valid inputs
    solver.add(z3.Not(pattern_z3 == replacement_z3))

    result = solver.check()

    if result == z3.unsat:
        # Patterns are equivalent
        return True, None
    elif result == z3.sat:
        # Patterns are NOT equivalent, get counterexample
        model = solver.model()
        counterexample = {}
        for var_name, var in z3_vars.items():
            if model[var] is not None:
                counterexample[var_name] = model[var].as_long()
        return False, counterexample
    else:
        # Unknown result (timeout, etc.)
        logger.warning("Z3 returned unknown result for equivalence check")
        return False, None
