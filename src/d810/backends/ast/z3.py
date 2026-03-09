"""IDA-specific Z3 verification via AstNode/mop_t operands.

=============================================================================
ARCHITECTURE: Two Z3 Modules in d810
=============================================================================

There are TWO separate Z3 utility modules in d810, serving different purposes:

1. d810.backends.mba.z3 (PURE - no IDA)
   --------------------------------------
   Purpose: Verify optimization rules using pure symbolic expressions.
   Input:   d810.mba.dsl.SymbolicExpression (platform-independent DSL)
   Use:     Unit tests, CI, TDD rule development, mathematical verification

   Key exports:
   - Z3VerificationVisitor: Converts SymbolicExpression -> Z3 BitVec
   - prove_equivalence(): Prove two SymbolicExpressions are equivalent
   - verify_rule(): Verify a rule's PATTERN equals its REPLACEMENT

2. THIS FILE: d810.backends.ast.z3 (IDA-SPECIFIC)
   ------------------------------------------------
   Purpose: Z3 verification of actual IDA microcode during deobfuscation.
   Input:   d810.hexrays.expr.ast.AstNode (wraps IDA mop_t/minsn_t)
   Use:     Runtime verification inside IDA Pro plugin

   Key exports:
   - Z3MopProver: Stateful prover with caching and optional CFG context
   - AstNodeZ3Visitor: Converts AstNode -> Z3 BitVec
   - Z3_INSTALLED: Whether z3 is available at runtime

=============================================================================
WHY TWO MODULES?
=============================================================================

The separation enables:
1. Unit testing rules WITHOUT IDA Pro license
2. CI/CD pipeline verification (GitHub Actions)
3. TDD workflow: write rule -> verify with Z3 -> integrate with IDA
4. Clear dependency boundaries (mba/ never imports IDA modules)

If you need to verify a SymbolicExpression (from d810.mba.dsl), use:
    from d810.backends.mba.z3 import prove_equivalence

If you need to verify actual IDA microcode (AstNode/mop_t), use this module:
    from d810.backends.ast.z3 import Z3MopProver

=============================================================================
"""

from __future__ import annotations

import functools
import sys

import ida_hexrays
import idaapi

from d810.core import getLogger, typing
from d810.core.typing import TYPE_CHECKING, Dict, Tuple
from d810.errors import D810Z3Exception
from d810.evaluator.hexrays_microcode.def_search import (
    recursively_resolve_ast as _recursively_resolve_ast,
)
from d810.evaluator.hexrays_microcode.def_search import (
    resolve_mop_to_ast as _resolve_mop_to_ast,
)
from d810.hexrays.expr.ast import AstLeaf, AstNode
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.ir.mop_utils import mop_to_ast
from d810.hexrays.utils.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    opcode_to_string,
)
from d810.hexrays.utils.hexrays_helpers import get_mop_index, structural_mop_hash
from d810.speedups.bootstrap import ensure_speedups_on_path

logger = getLogger(__name__)

ensure_speedups_on_path()

# Since version 4.8.2, when Z3 is creating a BitVec, it relies on _str_to_bytes which uses sys.stdout.encoding
# However, in IDA Pro (7.6sp1) sys.stdout is an object of type IDAPythonStdOut
# which doesn't have a 'encoding' attribute, thus we set it to something, so that Z3 works

try:
    x = sys.stdout.encoding
except AttributeError:
    logger.debug("Couldn't find sys.stdout.encoding, setting it to utf-8")
    sys.stdout.encoding = "utf-8"  # type: ignore

try:
    import z3

    Z3_INSTALLED = True

except (ImportError, AttributeError, OSError) as e:
    logger.warning("Z3 import failed (%s). Z3 features disabled.", e)
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
        # Older z3 versions or API quirks - ignore and keep default settings.
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


class AstNodeZ3Visitor:
    """Visitor that converts AstNode/AstLeaf to Z3 expressions."""

    def __init__(self, use_bitvecval: bool = False):
        # Reserved for visitor configuration if width/sign modes are split later.
        self.use_bitvecval = use_bitvecval

    def visit(self, ast: AstNode | AstLeaf | None):
        if ast is None:
            raise ValueError("ast is None")

        if ast.is_leaf():
            return self._visit_leaf(typing.cast(AstLeaf, ast))

        return self._visit_node(typing.cast(AstNode, ast))

    def _visit_leaf(self, ast: AstLeaf):
        if ast.is_constant():
            # Pattern-matching symbolic constant (e.g., Const("c_1") with z3_var).
            if hasattr(ast, "z3_var") and ast.z3_var is not None:
                return ast.z3_var
            # Concrete constant (e.g., Const("ONE", 1)).
            return z3.BitVecVal(ast.value, 32)
        return ast.z3_var

    def _visit_udiv_operand(self, node: AstNode | AstLeaf | None):
        # Preserve existing behavior by using a dedicated traversal path.
        return AstNodeZ3Visitor(use_bitvecval=True).visit(node)

    def _visit_node(self, ast: AstNode):
        left = self.visit(ast.left)
        right = self.visit(ast.right) if ast.right else None

        match ast.opcode:
            case ida_hexrays.m_neg:
                return -left
            case ida_hexrays.m_lnot:
                # Logical NOT (!) returns 1 when the operand is zero, otherwise 0.
                # Implemented via a 32-bit conditional expression to avoid casting
                # the symbolic BitVec to a Python bool (which would raise a Z3
                # exception).
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
                    self._visit_udiv_operand(ast.left),
                    self._visit_udiv_operand(ast.right),
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
                    left != z3.BitVecVal(0, 32),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setz:
                return z3.If(
                    left == z3.BitVecVal(0, 32),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setae:
                return z3.If(
                    z3.UGE(left, right),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setb:
                return z3.If(
                    z3.ULT(left, right),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_seta:
                return z3.If(
                    z3.UGT(left, right),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setbe:
                return z3.If(
                    z3.ULE(left, right),
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setg:
                return z3.If(left > right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
            case ida_hexrays.m_setge:
                return z3.If(
                    left >= right,
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setl:
                return z3.If(left < right, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
            case ida_hexrays.m_setle:
                return z3.If(
                    left <= right,
                    z3.BitVecVal(1, 32),
                    z3.BitVecVal(0, 32),
                )
            case ida_hexrays.m_setp:
                # 1) isolate the low byte
                lo_byte = typing.cast(z3.BitVecRef, z3.Extract(7, 0, left))
                # 2) XOR-reduce single-bit slices to get 1 -> odd, 0 -> even
                bit0 = typing.cast(z3.BitVecRef, z3.Extract(0, 0, lo_byte))
                parity_bv = bit0
                for i in range(1, 8):
                    parity_bv = parity_bv ^ z3.Extract(i, i, lo_byte)
                # 3) PF is set when the parity is even (parity_bv == 0)
                pf_is_set = parity_bv == z3.BitVecVal(0, 1)
                # 4) widen bool-like result to 32-bit {1,0}
                return z3.If(pf_is_set, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
            case ida_hexrays.m_sets:
                is_negative = left < z3.BitVecVal(0, 32)
                return z3.If(is_negative, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
            case ida_hexrays.m_xdu | ida_hexrays.m_xds:
                # Extend or keep the same width; in this simplified model we
                # forward the operand directly.
                return left
            case ida_hexrays.m_low:
                # Extract the lower half (dest_size) bits of the operand.
                dest_bits = (ast.dest_size or 4) * 8
                # Ensure we do not extract beyond source width.
                high_bit = min(dest_bits - 1, left.size() - 1)
                extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, left))
                # Zero-extend to 32-bit to avoid sort mismatches downstream.
                if extracted.size() < 32:
                    extracted = typing.cast(
                        z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
                    )
                return extracted
            case ida_hexrays.m_high:
                # Extract the upper half by shifting right by dest_bits.
                dest_bits = (ast.dest_size or 4) * 8
                shifted = z3.LShR(left, dest_bits)
                high_bit = min(dest_bits - 1, shifted.size() - 1)
                extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, shifted))
                # Zero-extend to 32-bit for consistency with the rest of the engine.
                if extracted.size() < 32:
                    extracted = typing.cast(
                        z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
                    )
                return extracted
            case ida_hexrays.m_call:
                # Handle rotate helper calls (__ROL*/__ROR*) emitted by mop_to_ast.
                # These AstNodes carry a func_name attribute set during AST construction.
                func_name = getattr(ast, "func_name", "")
                if func_name.startswith("__ROL"):
                    return z3.RotateLeft(left, right)
                elif func_name.startswith("__ROR"):
                    return z3.RotateRight(left, right)
                raise D810Z3Exception(
                    f"Z3 evaluation: Unknown m_call helper '{func_name}' for {ast}"
                )
            case _:
                # Gracefully fail on unknown opcode; avoid type issues in logging.
                op = getattr(ast, "opcode", None)
                op_str = opcode_to_string(int(op)) if isinstance(op, int) else str(op)
                raise D810Z3Exception(
                    f"Z3 evaluation: Unknown opcode {op_str} for {ast}"
                )


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
    visitor = AstNodeZ3Visitor()
    return [visitor.visit(ast) for ast in valid_ast_list]


class Z3MopProver:
    """Stateful Z3 prover for IDA microcode operand queries.

    Optional CFG context (blk, ins) enables backward register resolution
    via def_search. Without context, operates on AST structure only.

    Args:
        blk: Default mblock_t for backward resolution.
        ins: Default minsn_t for backward resolution.
    """

    def __init__(
        self,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
    ):
        self._blk = blk
        self._ins = ins
        self._eq_cache: Dict[
            typing.Tuple[
                typing.Tuple[int, int, int | str], typing.Tuple[int, int, int | str]
            ],
            bool,
        ] = {}
        self._neq_cache: Dict[
            typing.Tuple[
                typing.Tuple[int, int, int | str], typing.Tuple[int, int, int | str]
            ],
            bool,
        ] = {}
        self._always_zero_cache: Dict[typing.Tuple[int, int, int | str], bool] = {}
        self._always_nonzero_cache: Dict[typing.Tuple[int, int, int | str], bool] = {}

    def _resolve_context(
        self,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t | None,
    ) -> tuple[ida_hexrays.mblock_t | None, ida_hexrays.minsn_t | None]:
        """Per-call blk/ins override constructor defaults."""
        return (
            blk if blk is not None else self._blk,
            ins if ins is not None else self._ins,
        )

    @requires_z3_installed
    def are_equal(
        self,
        mop1: ida_hexrays.mop_t | None,
        mop2: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> bool:
        """Prove mop1 == mop2 for all inputs. Replaces z3_check_mop_equality."""
        if mop1 is None or mop2 is None:
            return False
        # Convert MopSnapshot to mop_t at boundary
        if isinstance(mop1, MopSnapshot):
            mop1 = mop1.to_mop()
        if isinstance(mop2, MopSnapshot):
            mop2 = mop2.to_mop()
        # Validate SWIG objects before accessing their attributes
        if not hasattr(mop1, "t") or not hasattr(mop1, "size"):
            logger.warning("are_equal: mop1 is invalid or freed SWIG object")
            return False
        if not hasattr(mop2, "t") or not hasattr(mop2, "size"):
            logger.warning("are_equal: mop2 is invalid or freed SWIG object")
            return False
        if logger.debug_on:
            logger.debug(
                "are_equal: mop1: %s, mop2: %s",
                format_mop_t(mop1),
                format_mop_t(mop2),
            )
            logger.debug(
                "are_equal:\n\tmop1.dstr(): %s\n\tmop2.dstr(): %s\n\thashes: %016X vs %016X",
                mop1.dstr(),
                mop2.dstr(),
                structural_mop_hash(mop1, 0),
                structural_mop_hash(mop2, 0),
            )
        try:
            k1 = (int(mop1.t), int(mop1.size), structural_mop_hash(mop1, 0))
            k2 = (int(mop2.t), int(mop2.size), structural_mop_hash(mop2, 0))
        except Exception:
            k1 = (
                int(mop1.t),
                int(mop1.size),
                mop1.dstr() if hasattr(mop1, "dstr") else repr(mop1),
            )
            k2 = (
                int(mop2.t),
                int(mop2.size),
                mop2.dstr() if hasattr(mop2, "dstr") else repr(mop2),
            )
        if k2 < k1:
            k1, k2 = k2, k1
        cache_key = (k1, k2)
        cached = self._eq_cache.get(cache_key)
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
        self._eq_cache[cache_key] = is_equal
        return is_equal

    @requires_z3_installed
    def are_unequal(
        self,
        mop1: ida_hexrays.mop_t | None,
        mop2: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> bool:
        """Prove mop1 != mop2 for all inputs. Replaces z3_check_mop_inequality."""
        if mop1 is None or mop2 is None:
            return True
        # Convert MopSnapshot to mop_t at boundary
        if isinstance(mop1, MopSnapshot):
            mop1 = mop1.to_mop()
        if isinstance(mop2, MopSnapshot):
            mop2 = mop2.to_mop()
        # Validate SWIG objects
        if not hasattr(mop1, "t") or not hasattr(mop1, "size"):
            logger.warning("are_unequal: mop1 is invalid or freed SWIG object")
            return True
        if not hasattr(mop2, "t") or not hasattr(mop2, "size"):
            logger.warning("are_unequal: mop2 is invalid or freed SWIG object")
            return True
        if logger.debug_on:
            logger.debug(
                "are_unequal: mop1: %s, mop2: %s",
                format_mop_t(mop1),
                format_mop_t(mop2),
            )
            logger.debug(
                "are_unequal:\n\tmop1.dstr(): %s\n\tmop2.dstr(): %s\n\thashes: %016X vs %016X",
                mop1.dstr(),
                mop2.dstr(),
                structural_mop_hash(mop1, 0),
                structural_mop_hash(mop2, 0),
            )
        try:
            k1 = (int(mop1.t), int(mop1.size), structural_mop_hash(mop1, 0))
            k2 = (int(mop2.t), int(mop2.size), structural_mop_hash(mop2, 0))
        except Exception:
            k1 = (
                int(mop1.t),
                int(mop1.size),
                mop1.dstr() if hasattr(mop1, "dstr") else repr(mop1),
            )
            k2 = (
                int(mop2.t),
                int(mop2.size),
                mop2.dstr() if hasattr(mop2, "dstr") else repr(mop2),
            )
        if k2 < k1:
            k1, k2 = k2, k1
        cache_key = (k1, k2)
        cached = self._neq_cache.get(cache_key)
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
        self._neq_cache[cache_key] = is_unequal
        return is_unequal

    @requires_z3_installed
    def is_always_zero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
    ) -> bool:
        """Prove mop == 0 for all inputs. Replaces z3_check_always_zero."""
        if mop is None:
            return False
        blk, ins = self._resolve_context(blk, ins)
        # Convert MopSnapshot to mop_t at boundary
        if isinstance(mop, MopSnapshot):
            mop = mop.to_mop()
        # Validate SWIG object
        if not hasattr(mop, "t") or not hasattr(mop, "size"):
            logger.warning("is_always_zero: mop is invalid or freed SWIG object")
            return False

        # Check cache first
        try:
            cache_key = (int(mop.t), int(mop.size), structural_mop_hash(mop, 0))
        except Exception:
            cache_key = (
                int(mop.t),
                int(mop.size),
                mop.dstr() if hasattr(mop, "dstr") else repr(mop),
            )

        cached = self._always_zero_cache.get(cache_key)
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
        if ast is None or (hasattr(ast, "is_leaf") and ast.is_leaf() and is_resolvable):
            if blk is not None and ins is not None:

                resolved_ast = _resolve_mop_to_ast(mop, blk, ins)
                if resolved_ast is not None:
                    ast = resolved_ast
                    if logger.debug_on:
                        logger.debug(
                            "is_always_zero: Resolved %s via tracker to AST: %s",
                            format_mop_t(mop),
                            ast,
                        )

        # Recursively resolve any register/stack leaves in the AST
        if ast is not None and blk is not None and ins is not None:

            ast = _recursively_resolve_ast(ast, blk, ins)
            if logger.debug_on:
                logger.debug("is_always_zero: After recursive resolution: %s", ast)

        if ast is None:
            self._always_zero_cache[cache_key] = False
            return False

        leaf_list = ast.get_leaf_list()
        create_z3_vars(leaf_list)

        try:
            z3_expr = AstNodeZ3Visitor().visit(ast)
        except Exception as e:
            logger.debug("is_always_zero: Failed to convert to Z3: %s", e)
            self._always_zero_cache[cache_key] = False
            return False

        if z3_expr is None:
            self._always_zero_cache[cache_key] = False
            return False

        solver = get_solver()
        solver.push()
        try:
            # Try to find ANY input where expr != 0
            # If unsat, expr is always 0
            solver.add(z3_expr != z3.BitVecVal(0, z3_expr.size()))
            result = solver.check() == z3.unsat
        except Exception as e:
            logger.debug("is_always_zero: Z3 solver error: %s", e)
            result = False
        finally:
            solver.pop()

        self._always_zero_cache[cache_key] = result
        return result

    @requires_z3_installed
    def is_always_nonzero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
    ) -> bool:
        """Prove mop != 0 for all inputs. Replaces z3_check_always_nonzero."""
        if mop is None:
            return False
        blk, ins = self._resolve_context(blk, ins)
        # Convert MopSnapshot to mop_t at boundary
        if isinstance(mop, MopSnapshot):
            mop = mop.to_mop()
        # Validate SWIG object
        if not hasattr(mop, "t") or not hasattr(mop, "size"):
            logger.warning("is_always_nonzero: mop is invalid or freed SWIG object")
            return False

        # Check cache first
        try:
            cache_key = (int(mop.t), int(mop.size), structural_mop_hash(mop, 0))
        except Exception:
            cache_key = (
                int(mop.t),
                int(mop.size),
                mop.dstr() if hasattr(mop, "dstr") else repr(mop),
            )

        cached = self._always_nonzero_cache.get(cache_key)
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
        if ast is None or (hasattr(ast, "is_leaf") and ast.is_leaf() and is_resolvable):
            if blk is not None and ins is not None:
                resolved_ast = _resolve_mop_to_ast(mop, blk, ins)
                if resolved_ast is not None:
                    ast = resolved_ast
                    if logger.debug_on:
                        logger.debug(
                            "is_always_nonzero: Resolved %s via tracker to AST: %s",
                            format_mop_t(mop),
                            ast,
                        )

        # Recursively resolve any register/stack leaves in the AST
        if ast is not None and blk is not None and ins is not None:

            ast = _recursively_resolve_ast(ast, blk, ins)
            if logger.debug_on:
                logger.debug("is_always_nonzero: After recursive resolution: %s", ast)

        if ast is None:
            self._always_nonzero_cache[cache_key] = False
            return False

        leaf_list = ast.get_leaf_list()
        create_z3_vars(leaf_list)

        try:
            z3_expr = AstNodeZ3Visitor().visit(ast)
        except Exception as e:
            logger.debug("is_always_nonzero: Failed to convert to Z3: %s", e)
            self._always_nonzero_cache[cache_key] = False
            return False

        if z3_expr is None:
            self._always_nonzero_cache[cache_key] = False
            return False

        solver = get_solver()
        solver.push()
        try:
            # Try to find ANY input where expr == 0
            # If unsat, expr is always nonzero
            solver.add(z3_expr == z3.BitVecVal(0, z3_expr.size()))
            result = solver.check() == z3.unsat
        except Exception as e:
            logger.debug("is_always_nonzero: Z3 solver error: %s", e)
            result = False
        finally:
            solver.pop()

        self._always_nonzero_cache[cache_key] = result
        return result

    @requires_z3_installed
    def prove_equivalence(
        self,
        pattern_ast: AstNode | AstLeaf,
        replacement_ast: AstNode | AstLeaf,
        z3_vars: dict[str, typing.Any] | None = None,
        constraints: list[typing.Any] | None = None,
        bit_width: int = 32,
    ) -> tuple[bool, dict[str, int] | None]:
        """Prove two AST patterns are equivalent. Replaces z3_prove_equivalence."""
        # Get all leaf nodes from both patterns to find variables
        pattern_leaves = pattern_ast.get_leaf_list()
        replacement_leaves = replacement_ast.get_leaf_list()
        all_leaves = pattern_leaves + replacement_leaves

        # If z3_vars not provided, create them
        if z3_vars is None:
            # Extract unique variable names (excluding constants)
            var_names = set()
            for leaf in all_leaves:
                if not leaf.is_constant() and hasattr(leaf, "name"):
                    var_names.add(leaf.name)

            # Create Z3 BitVec for each variable
            z3_vars = {name: z3.BitVec(name, bit_width) for name in sorted(var_names)}

            # Map the z3_vars to the leaves for conversion
            for leaf in all_leaves:
                if (
                    not leaf.is_constant()
                    and hasattr(leaf, "name")
                    and leaf.name in z3_vars
                ):
                    leaf.z3_var = z3_vars[leaf.name]
                    leaf.z3_var_name = leaf.name
        else:
            # Use provided z3_vars (includes both variables and pattern-matching constants)
            for leaf in all_leaves:
                if not hasattr(leaf, "name"):
                    continue

                # Assign z3_var to regular variables
                if not leaf.is_constant() and leaf.name in z3_vars:
                    leaf.z3_var = z3_vars[leaf.name]
                    leaf.z3_var_name = leaf.name
                # Also assign z3_var to pattern-matching constants (symbolic constants)
                elif leaf.is_constant() and leaf.name in z3_vars:
                    # Pattern-matching constant like Const("c_1") - treat as symbolic
                    if hasattr(leaf, "expected_value") and leaf.expected_value is None:
                        leaf.z3_var = z3_vars[leaf.name]
                        leaf.z3_var_name = leaf.name

        # Convert both AST patterns to Z3 expressions
        try:
            visitor = AstNodeZ3Visitor()
            pattern_z3 = visitor.visit(pattern_ast)
            replacement_z3 = visitor.visit(replacement_ast)
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

    def clear_caches(self) -> None:
        """Clear all memoization caches. Call on decompilation start."""
        self._eq_cache.clear()
        self._neq_cache.clear()
        self._always_zero_cache.clear()
        self._always_nonzero_cache.clear()
