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
import time

import ida_hexrays

from d810.core import getLogger, typing
from d810.core.typing import Dict
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
    format_mop_t,
    opcode_to_string,
)
from d810.hexrays.utils.hexrays_helpers import get_mop_index, structural_mop_hash
from d810.speedups.bootstrap import ensure_speedups_on_path
from d810.backends.ast.z3_proof_policy import (
    Z3ExpressionNodeBudget,
    Z3NodeLimitExceeded,
    Z3ProofAbstentionReason,
    Z3ProofPolicy,
    Z3ProofResult,
    Z3ProofStatus,
)

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


def _new_query_solver(
    policy: Z3ProofPolicy | None, solver: z3.Solver | None = None
) -> z3.Solver:
    """Return the solver for one query.

    Policy-scoped proofs always receive a fresh solver.  In particular, they
    never mutate the process-global ``get_solver()`` instance, even when a
    caller supplies a solver for an unbounded compatibility query.
    """

    if policy is None:
        return solver if solver is not None else get_solver()

    query_solver = z3.Solver()
    if solver is not None:
        try:
            query_solver.add(*solver.assertions())
        except Exception as exc:
            raise D810Z3Exception(
                "bounded proof solver must expose copyable assertions"
            ) from exc
    query_solver.set(timeout=policy.proof_timeout_ms)
    return query_solver


def _solver_unknown_reason(
    solver: z3.Solver, policy: Z3ProofPolicy | None, elapsed_ms: float
) -> Z3ProofAbstentionReason:
    """Classify an explicit ``unknown`` result without treating it as false."""

    try:
        reason = str(solver.reason_unknown()).lower()
    except Exception:
        reason = ""
    if any(token in reason for token in ("timeout", "canceled", "cancelled")):
        return Z3ProofAbstentionReason.TIMEOUT
    if policy is not None and elapsed_ms >= policy.proof_timeout_ms:
        return Z3ProofAbstentionReason.TIMEOUT
    return Z3ProofAbstentionReason.SOLVER_UNKNOWN


def _classify_solver_result(
    check_result: object,
    solver: z3.Solver,
    policy: Z3ProofPolicy | None,
    started_at: float,
    observed_expression_nodes: int | None,
) -> Z3ProofResult:
    elapsed_ms = (time.perf_counter() - started_at) * 1000.0
    if check_result == z3.unsat:
        return Z3ProofResult(
            status=Z3ProofStatus.PROVED,
            reason=None,
            observed_expression_nodes=observed_expression_nodes,
            elapsed_ms=elapsed_ms,
        )
    if check_result == z3.sat:
        return Z3ProofResult(
            status=Z3ProofStatus.DISPROVED,
            reason=None,
            observed_expression_nodes=observed_expression_nodes,
            elapsed_ms=elapsed_ms,
        )
    return Z3ProofResult(
        status=Z3ProofStatus.ABSTAINED,
        reason=_solver_unknown_reason(
            solver,
            policy,
            elapsed_ms,
        ),
        observed_expression_nodes=observed_expression_nodes,
        elapsed_ms=elapsed_ms,
    )


def _unsupported_result(
    started_at: float, observed_expression_nodes: int | None = None
) -> Z3ProofResult:
    return Z3ProofResult(
        status=Z3ProofStatus.ABSTAINED,
        reason=Z3ProofAbstentionReason.UNSUPPORTED_EXPRESSION,
        observed_expression_nodes=observed_expression_nodes,
        elapsed_ms=(time.perf_counter() - started_at) * 1000.0,
    )


def _node_limit_result(
    started_at: float, budget: Z3ExpressionNodeBudget
) -> Z3ProofResult:
    return Z3ProofResult(
        status=Z3ProofStatus.ABSTAINED,
        reason=Z3ProofAbstentionReason.NODE_LIMIT,
        observed_expression_nodes=budget.observed_nodes,
        elapsed_ms=(time.perf_counter() - started_at) * 1000.0,
    )


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
            width = int(getattr(leaf, "dest_size", None) or leaf.mop.size or 4) * 8
            if width not in {8, 16, 32, 64, 128}:
                width = 32
            known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), width))
        leaf.z3_var = known_leaf_z3_var_list[leaf_index]
        leaf.z3_var_name = "x_{0}".format(leaf_index)
    return known_leaf_z3_var_list


class AstNodeZ3Visitor:
    """Visitor that converts AstNode/AstLeaf to Z3 expressions."""

    def __init__(
        self,
        use_bitvecval: bool = False,
        node_budget: Z3ExpressionNodeBudget | None = None,
    ):
        # Reserved for visitor configuration if width/sign modes are split later.
        self.use_bitvecval = use_bitvecval
        self.node_budget = node_budget

    @staticmethod
    def _ast_bits(ast: AstNode | AstLeaf | None, fallback_bits: int = 32) -> int:
        size = getattr(ast, "dest_size", None)
        if isinstance(size, int) and size in {1, 2, 4, 8, 16}:
            return size * 8
        return fallback_bits

    @staticmethod
    def _unsigned_resize(value: z3.BitVecRef, bits: int) -> z3.BitVecRef:
        if value.size() == bits:
            return value
        if value.size() > bits:
            return typing.cast(z3.BitVecRef, z3.Extract(bits - 1, 0, value))
        return typing.cast(z3.BitVecRef, z3.ZeroExt(bits - value.size(), value))

    @staticmethod
    def _signed_resize(value: z3.BitVecRef, bits: int) -> z3.BitVecRef:
        if value.size() == bits:
            return value
        if value.size() > bits:
            return typing.cast(z3.BitVecRef, z3.Extract(bits - 1, 0, value))
        return typing.cast(z3.BitVecRef, z3.SignExt(bits - value.size(), value))

    def _flag(
        self, ast: AstNode, condition: z3.BoolRef, fallback_bits: int
    ) -> z3.BitVecRef:
        bits = self._ast_bits(ast, fallback_bits)
        return typing.cast(
            z3.BitVecRef,
            z3.If(condition, z3.BitVecVal(1, bits), z3.BitVecVal(0, bits)),
        )

    def visit(self, ast: AstNode | AstLeaf | None):
        if ast is None:
            raise ValueError("ast is None")
        if self.node_budget is not None:
            self.node_budget.consume()

        if ast.is_leaf():
            return self._visit_leaf(typing.cast(AstLeaf, ast))

        return self._visit_node(typing.cast(AstNode, ast))

    def _visit_leaf(self, ast: AstLeaf):
        bits = self._ast_bits(ast)
        if ast.is_constant():
            # Pattern-matching symbolic constant (e.g., Const("c_1") with z3_var).
            if hasattr(ast, "z3_var") and ast.z3_var is not None:
                return self._unsigned_resize(ast.z3_var, bits)
            # Concrete constant (e.g., Const("ONE", 1)).
            return z3.BitVecVal(ast.value, bits)
        return self._unsigned_resize(ast.z3_var, bits)

    def _visit_udiv_operand(self, node: AstNode | AstLeaf | None):
        # Preserve existing behavior by using a dedicated traversal path.
        return AstNodeZ3Visitor(
            use_bitvecval=True, node_budget=self.node_budget
        ).visit(node)

    def _visit_node(self, ast: AstNode):
        left = self.visit(ast.left)
        right = self.visit(ast.right) if ast.right else None
        operand_bits = left.size()
        result_bits = self._ast_bits(ast, operand_bits)
        if right is not None:
            if right.size() != operand_bits and ast.opcode not in {
                ida_hexrays.m_shl,
                ida_hexrays.m_shr,
                ida_hexrays.m_sar,
                ida_hexrays.m_call,
            }:
                raise D810Z3Exception(
                    "Z3 evaluation: mixed-width operands for "
                    f"{opcode_to_string(ast.opcode)}: "
                    f"{operand_bits} and {right.size()} bits"
                )
            right = self._unsigned_resize(right, operand_bits)

        match ast.opcode:
            case ida_hexrays.m_mov:
                return self._unsigned_resize(left, result_bits)
            case ida_hexrays.m_neg:
                return self._unsigned_resize(-left, result_bits)
            case ida_hexrays.m_lnot:
                return self._flag(
                    ast, left == z3.BitVecVal(0, operand_bits), operand_bits
                )
            case ida_hexrays.m_bnot:
                return self._unsigned_resize(~left, result_bits)
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
                return z3.SRem(left, right)
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
                compared = (
                    right if right is not None else z3.BitVecVal(0, operand_bits)
                )
                return self._flag(ast, left != compared, operand_bits)
            case ida_hexrays.m_setz:
                compared = (
                    right if right is not None else z3.BitVecVal(0, operand_bits)
                )
                return self._flag(ast, left == compared, operand_bits)
            case ida_hexrays.m_setae:
                return self._flag(ast, z3.UGE(left, right), operand_bits)
            case ida_hexrays.m_setb:
                return self._flag(ast, z3.ULT(left, right), operand_bits)
            case ida_hexrays.m_seta:
                return self._flag(ast, z3.UGT(left, right), operand_bits)
            case ida_hexrays.m_setbe:
                return self._flag(ast, z3.ULE(left, right), operand_bits)
            case ida_hexrays.m_setg:
                return self._flag(ast, left > right, operand_bits)
            case ida_hexrays.m_setge:
                return self._flag(ast, left >= right, operand_bits)
            case ida_hexrays.m_setl:
                return self._flag(ast, left < right, operand_bits)
            case ida_hexrays.m_setle:
                return self._flag(ast, left <= right, operand_bits)
            case ida_hexrays.m_setp:
                # PF is the parity of the low byte of (left - right).
                difference = left - right
                lo_byte = typing.cast(z3.BitVecRef, z3.Extract(7, 0, difference))
                # 2) XOR-reduce single-bit slices to get 1 -> odd, 0 -> even
                bit0 = typing.cast(z3.BitVecRef, z3.Extract(0, 0, lo_byte))
                parity_bv = bit0
                for i in range(1, 8):
                    parity_bv = parity_bv ^ z3.Extract(i, i, lo_byte)
                # 3) PF is set when the parity is even (parity_bv == 0)
                pf_is_set = parity_bv == z3.BitVecVal(0, 1)
                return self._flag(ast, pf_is_set, operand_bits)
            case ida_hexrays.m_sets:
                is_negative = left < z3.BitVecVal(0, operand_bits)
                return self._flag(ast, is_negative, operand_bits)
            case ida_hexrays.m_seto:
                # Signed-subtraction overflow flag OF(left - right): set when the
                # operands differ in sign and the result's sign differs from the
                # minuend's. Mirrors d810.core.bits.get_sub_of (the Cython
                # evaluator's m_seto): msb((op1 ^ res) & (op1 ^ op2)). Required to
                # prove signed-comparison opaque predicates -- Hex-Rays lowers a
                # signed compare to its raw flags, so (y >=s c) | (y <s c) == 1
                # reaches the prover as flag ops (<s expands to SF ^ OF). Without
                # this case the conversion aborts ("Unknown opcode seto") and the
                # tautology (an OLLVM/Tigress BCF opaque predicate) is never folded.
                compared = right if right is not None else z3.BitVecVal(0, operand_bits)
                difference = left - compared
                overflow_bit = z3.Extract(
                    operand_bits - 1,
                    operand_bits - 1,
                    (left ^ difference) & (left ^ compared),
                )
                return self._flag(ast, overflow_bit == z3.BitVecVal(1, 1), operand_bits)
            case ida_hexrays.m_cfadd:
                return self._flag(ast, z3.ULT(left + right, left), operand_bits)
            case ida_hexrays.m_ofadd:
                result = left + right
                overflow_bit = z3.Extract(
                    operand_bits - 1,
                    operand_bits - 1,
                    (left ^ result) & ~(left ^ right),
                )
                return self._flag(ast, overflow_bit == z3.BitVecVal(1, 1), operand_bits)
            case ida_hexrays.m_xdu:
                return self._unsigned_resize(left, result_bits)
            case ida_hexrays.m_xds:
                return self._signed_resize(left, result_bits)
            case ida_hexrays.m_low:
                return self._unsigned_resize(left, result_bits)
            case ida_hexrays.m_high:
                shifted = z3.LShR(left, result_bits)
                return self._unsigned_resize(shifted, result_bits)
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
def mop_list_to_z3_expression_list(
    mop_list: list[ida_hexrays.mop_t],
    *,
    node_budget: Z3ExpressionNodeBudget | None = None,
):
    if logger.debug_on:
        logger.debug(
            "mop_list_to_z3_expression_list: mop_list: %s",
            [format_mop_t(mop) for mop in mop_list],
        )
    if node_budget is None:
        ast_list = [mop_to_ast(mop) for mop in mop_list]
    else:
        ast_list = [mop_to_ast(mop, node_budget=node_budget) for mop in mop_list]
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


def _translate_mop_pair(
    mop1: ida_hexrays.mop_t,
    mop2: ida_hexrays.mop_t,
    *,
    operation: str,
    node_budget: Z3ExpressionNodeBudget | None = None,
) -> tuple[z3.BitVecRef, z3.BitVecRef] | None:
    try:
        if node_budget is None:
            expressions = mop_list_to_z3_expression_list([mop1, mop2])
        else:
            expressions = mop_list_to_z3_expression_list(
                [mop1, mop2], node_budget=node_budget
            )
    except Z3NodeLimitExceeded:
        raise
    except Exception as exc:
        logger.debug("%s: failed to translate operands to Z3: %s", operation, exc)
        return None
    if len(expressions) != 2:
        return None
    return expressions[0], expressions[1]


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
        policy: Z3ProofPolicy | None = None,
    ):
        if policy is not None and not isinstance(policy, Z3ProofPolicy):
            raise TypeError("policy must be a Z3ProofPolicy or None")
        self._blk = blk
        self._ins = ins
        self._policy = policy
        self._eq_cache: Dict[
            typing.Tuple[
                Z3ProofPolicy | None,
                typing.Tuple[int, int, int | str],
                typing.Tuple[int, int, int | str],
            ],
            Z3ProofResult,
        ] = {}
        self._neq_cache: Dict[
            typing.Tuple[
                Z3ProofPolicy | None,
                typing.Tuple[int, int, int | str],
                typing.Tuple[int, int, int | str],
            ],
            Z3ProofResult,
        ] = {}
        self._comparison_cache: Dict[
            typing.Tuple[
                str,
                Z3ProofPolicy | None,
                typing.Tuple[int, int, int | str],
                typing.Tuple[int, int, int | str],
            ],
            bool | None,
        ] = {}
        self._always_zero_cache: Dict[
            typing.Tuple[Z3ProofPolicy | None, int, int, int | str], Z3ProofResult
        ] = {}
        self._always_nonzero_cache: Dict[
            typing.Tuple[Z3ProofPolicy | None, int, int, int | str], Z3ProofResult
        ] = {}

    @property
    def policy(self) -> Z3ProofPolicy | None:
        """Immutable policy used by this prover, if it is bounded."""

        return self._policy

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

    @staticmethod
    def _operand_key(mop: ida_hexrays.mop_t) -> tuple[int, int, int | str]:
        try:
            identity = structural_mop_hash(mop, 0)
        except Exception:
            identity = mop.dstr() if hasattr(mop, "dstr") else repr(mop)
        return (int(mop.t), int(mop.size), identity)

    def _ordered_pair_key(
        self, mop1: ida_hexrays.mop_t, mop2: ida_hexrays.mop_t
    ) -> tuple[
        Z3ProofPolicy | None,
        tuple[int, int, int | str],
        tuple[int, int, int | str],
    ]:
        k1 = self._operand_key(mop1)
        k2 = self._operand_key(mop2)
        try:
            if k2 < k1:
                k1, k2 = k2, k1
        except TypeError:
            if repr(k2) < repr(k1):
                k1, k2 = k2, k1
        return self._policy, k1, k2

    @staticmethod
    def _cache_is_context_free(
        *operands: ida_hexrays.mop_t | MopSnapshot | None,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t | None,
        solver: z3.Solver | None,
    ) -> bool:
        """Allow reuse only when no semantic context can affect a proof."""

        return (
            blk is None
            and ins is None
            and solver is None
            and not any(isinstance(operand, MopSnapshot) for operand in operands)
        )

    def _prepare_operand_pair(
        self,
        mop1: ida_hexrays.mop_t | MopSnapshot | None,
        mop2: ida_hexrays.mop_t | MopSnapshot | None,
        *,
        blk: ida_hexrays.mblock_t | None,
        operation: str,
    ) -> tuple[ida_hexrays.mop_t, ida_hexrays.mop_t, int] | None:
        if mop1 is None or mop2 is None:
            return None
        destination_mba = getattr(blk, "mba", None)
        if isinstance(mop1, MopSnapshot):
            mop1 = mop1.to_mop(destination_mba)
        if isinstance(mop2, MopSnapshot):
            mop2 = mop2.to_mop(destination_mba)
        if not hasattr(mop1, "t") or not hasattr(mop1, "size"):
            logger.warning("%s: mop1 is invalid or freed SWIG object", operation)
            return None
        if not hasattr(mop2, "t") or not hasattr(mop2, "size"):
            logger.warning("%s: mop2 is invalid or freed SWIG object", operation)
            return None
        native_size = int(mop1.size)
        if native_size not in {1, 2, 4, 8, 16} or native_size != int(mop2.size):
            return None
        return mop1, mop2, native_size

    def _prove_operand_pair(
        self,
        mop1: ida_hexrays.mop_t | MopSnapshot | None,
        mop2: ida_hexrays.mop_t | MopSnapshot | None,
        *,
        equality: bool,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t | None,
        solver: z3.Solver | None,
        operation: str,
    ) -> Z3ProofResult:
        started_at = time.perf_counter()
        try:
            prepared = self._prepare_operand_pair(
                mop1,
                mop2,
                blk=blk,
                operation=operation,
            )
        except Exception as exc:
            logger.debug("%s: failed to prepare operands: %s", operation, exc)
            return _unsupported_result(started_at)
        if prepared is None:
            return _unsupported_result(started_at)
        left_mop, right_mop, native_size = prepared
        cache_allowed = self._cache_is_context_free(
            mop1,
            mop2,
            blk=blk,
            ins=ins,
            solver=solver,
        )
        cache_key = self._ordered_pair_key(left_mop, right_mop)
        cache = self._eq_cache if equality else self._neq_cache
        if cache_allowed:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached

        budget = (
            Z3ExpressionNodeBudget(self._policy)
            if self._policy is not None
            else None
        )
        try:
            expressions = _translate_mop_pair(
                left_mop,
                right_mop,
                operation=operation,
                node_budget=budget,
            )
        except Z3NodeLimitExceeded:
            assert budget is not None
            return _node_limit_result(started_at, budget)
        if expressions is None:
            return _unsupported_result(
                started_at,
                budget.observed_nodes if budget is not None else None,
            )
        z3_mop1, z3_mop2 = expressions
        native_bits = native_size * 8
        try:
            if z3_mop1.size() != native_bits or z3_mop2.size() != native_bits:
                return _unsupported_result(
                    started_at,
                    budget.observed_nodes if budget is not None else None,
                )
            predicate = z3_mop1 == z3_mop2
            query = z3.Not(predicate) if equality else predicate
            query_solver = _new_query_solver(self._policy, solver)
            query_solver.push()
            try:
                query_solver.add(query)
                check_result = query_solver.check()
            finally:
                query_solver.pop()
        except Exception as exc:
            logger.debug("%s: failed to discharge query: %s", operation, exc)
            result = Z3ProofResult(
                status=Z3ProofStatus.ABSTAINED,
                reason=Z3ProofAbstentionReason.SOLVER_UNKNOWN,
                observed_expression_nodes=(
                    budget.observed_nodes if budget is not None else None
                ),
                elapsed_ms=(time.perf_counter() - started_at) * 1000.0,
            )
        else:
            result = _classify_solver_result(
                check_result,
                query_solver,
                self._policy,
                started_at,
                budget.observed_nodes if budget is not None else None,
            )
        if cache_allowed and result.status in {
            Z3ProofStatus.PROVED,
            Z3ProofStatus.DISPROVED,
        }:
            cache[cache_key] = result
        return result

    @requires_z3_installed
    def prove_equal(
        self,
        mop1: ida_hexrays.mop_t | None,
        mop2: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> Z3ProofResult:
        """Return the structured result for a universal equality proof."""

        blk, ins = self._resolve_context(blk, ins)
        return self._prove_operand_pair(
            mop1,
            mop2,
            equality=True,
            blk=blk,
            ins=ins,
            solver=solver,
            operation="prove_equal",
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
        """Compatibility wrapper returning ``True`` only for ``PROVED``."""

        return (
            self.prove_equal(mop1, mop2, blk=blk, ins=ins, solver=solver).status
            is Z3ProofStatus.PROVED
        )

    @requires_z3_installed
    def prove_unequal(
        self,
        mop1: ida_hexrays.mop_t | None,
        mop2: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> Z3ProofResult:
        """Return the structured result for a universal inequality proof."""

        blk, ins = self._resolve_context(blk, ins)
        return self._prove_operand_pair(
            mop1,
            mop2,
            equality=False,
            blk=blk,
            ins=ins,
            solver=solver,
            operation="prove_unequal",
        )

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
        """Compatibility wrapper returning ``True`` only for ``PROVED``."""

        return (
            self.prove_unequal(mop1, mop2, blk=blk, ins=ins, solver=solver).status
            is Z3ProofStatus.PROVED
        )

    @requires_z3_installed
    def prove_comparison(
        self,
        mop1: ida_hexrays.mop_t | None,
        mop2: ida_hexrays.mop_t | None,
        comparison: str,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> bool | None:
        """Prove an exact two-operand comparison, or abstain.

        Returns ``True`` when the predicate is valid for every model,
        ``False`` when its negation is valid for every model, and ``None``
        when either direction is satisfiable or cannot be discharged.  The
        supported vocabulary is deliberately closed: ``eq``, ``ne``, the
        unsigned ``ult``/``ule``/``ugt``/``uge`` relations, and the signed
        ``slt``/``sle``/``sgt``/``sge`` relations.

        Both the predicate and its negation are checked.  This detects an
        inconsistent caller-supplied solver instead of certifying both sides
        from an already-unsatisfiable base context.
        """
        comparison_builders = {
            "eq": lambda left, right: left == right,
            "ne": lambda left, right: left != right,
            "ult": z3.ULT,
            "ule": z3.ULE,
            "ugt": z3.UGT,
            "uge": z3.UGE,
            "slt": lambda left, right: left < right,
            "sle": lambda left, right: left <= right,
            "sgt": lambda left, right: left > right,
            "sge": lambda left, right: left >= right,
        }
        build_predicate = comparison_builders.get(comparison)
        if build_predicate is None or mop1 is None or mop2 is None:
            return None

        blk, ins = self._resolve_context(blk, ins)
        cache_allowed = self._cache_is_context_free(
            mop1,
            mop2,
            blk=blk,
            ins=ins,
            solver=solver,
        )
        destination_mba = getattr(blk, "mba", None)
        if isinstance(mop1, MopSnapshot):
            mop1 = mop1.to_mop(destination_mba)
        if isinstance(mop2, MopSnapshot):
            mop2 = mop2.to_mop(destination_mba)
        if not hasattr(mop1, "t") or not hasattr(mop1, "size"):
            logger.warning("prove_comparison: mop1 is invalid or freed SWIG object")
            return None
        if not hasattr(mop2, "t") or not hasattr(mop2, "size"):
            logger.warning("prove_comparison: mop2 is invalid or freed SWIG object")
            return None

        # The symbolic sort must exactly attest to the native operand width.
        # Mixed-width comparisons are not a native mcode value operation and
        # are rejected rather than silently extending either side.
        native_size = int(mop1.size)
        if native_size not in {1, 2, 4, 8, 16} or native_size != int(mop2.size):
            return None

        def _operand_key(mop):
            try:
                identity = structural_mop_hash(mop, 0)
            except Exception:
                identity = mop.dstr() if hasattr(mop, "dstr") else repr(mop)
            return (int(mop.t), int(mop.size), identity)

        cache_key = (
            comparison,
            self._policy,
            _operand_key(mop1),
            _operand_key(mop2),
        )
        if cache_allowed and cache_key in self._comparison_cache:
            return self._comparison_cache[cache_key]

        budget = (
            Z3ExpressionNodeBudget(self._policy)
            if self._policy is not None
            else None
        )
        try:
            expressions = _translate_mop_pair(
                mop1,
                mop2,
                operation="prove_comparison",
                node_budget=budget,
            )
        except Z3NodeLimitExceeded:
            return None
        if expressions is None:
            return None
        left, right = expressions
        native_bits = native_size * 8
        if left.size() != native_bits or right.size() != native_bits:
            return None
        _solver = _new_query_solver(self._policy, solver)
        try:
            predicate = build_predicate(left, right)

            _solver.push()
            try:
                _solver.add(z3.Not(predicate))
                negated_result = _solver.check()
            finally:
                _solver.pop()

            _solver.push()
            try:
                _solver.add(predicate)
                predicate_result = _solver.check()
            finally:
                _solver.pop()
        except Exception as exc:
            logger.debug(
                "prove_comparison: failed to discharge %s: %s", comparison, exc
            )
            result = None
        else:
            if (
                negated_result == z3.unknown
                or predicate_result == z3.unknown
            ):
                result = None
            else:
                predicate_valid = negated_result == z3.unsat
                predicate_impossible = predicate_result == z3.unsat
                if predicate_valid == predicate_impossible:
                    result = None
                else:
                    result = predicate_valid

        if cache_allowed and result is not None:
            self._comparison_cache[cache_key] = result
        return result

    def _prepare_single_ast(
        self,
        mop: ida_hexrays.mop_t | MopSnapshot | None,
        *,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t | None,
        operation: str,
    ) -> tuple[
        ida_hexrays.mop_t,
        AstNode | AstLeaf,
        Z3ExpressionNodeBudget | None,
        bool,
    ] | None:
        mop = self._coerce_single_operand(mop, blk=blk, operation=operation)
        if mop is None:
            return None
        budget = (
            Z3ExpressionNodeBudget(self._policy)
            if self._policy is not None
            else None
        )
        if budget is None:
            ast = mop_to_ast(mop)
        else:
            ast = mop_to_ast(mop, node_budget=budget)
        visitor_needs_budget = False

        is_resolvable = mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
        if not is_resolvable and mop.t == ida_hexrays.mop_d:
            nested = mop.d
            if nested is not None and nested.opcode == ida_hexrays.m_ldx:
                is_resolvable = True

        if ast is None or (hasattr(ast, "is_leaf") and ast.is_leaf() and is_resolvable):
            if blk is not None and ins is not None:
                resolved_ast = _resolve_mop_to_ast(mop, blk, ins)
                if resolved_ast is not None:
                    ast = resolved_ast
                    if self._policy is not None:
                        # The resolver may expand a definition tree that is
                        # not present in the original mop.  Discard the
                        # builder's one-occurrence charge and count the real
                        # resolved tree at the visitor recursion seam.
                        budget = Z3ExpressionNodeBudget(self._policy)
                        visitor_needs_budget = True
                    if logger.debug_on:
                        logger.debug(
                            "%s: Resolved %s via tracker to AST: %s",
                            operation,
                            format_mop_t(mop),
                            ast,
                        )

        if ast is not None and blk is not None and ins is not None:
            ast = _recursively_resolve_ast(ast, blk, ins)
            if logger.debug_on:
                logger.debug("%s: After recursive resolution: %s", operation, ast)
        if ast is None:
            return None
        return mop, ast, budget, visitor_needs_budget

    def _coerce_single_operand(
        self,
        mop: ida_hexrays.mop_t | MopSnapshot | None,
        *,
        blk: ida_hexrays.mblock_t | None,
        operation: str,
    ) -> ida_hexrays.mop_t | None:
        if mop is None:
            return None
        if isinstance(mop, MopSnapshot):
            mop = mop.to_mop(getattr(blk, "mba", None))
        if not hasattr(mop, "t") or not hasattr(mop, "size"):
            logger.warning("%s: mop is invalid or freed SWIG object", operation)
            return None
        return mop

    def _prove_always_zero_or_nonzero(
        self,
        mop: ida_hexrays.mop_t | MopSnapshot | None,
        *,
        nonzero: bool,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t | None,
        solver: z3.Solver | None,
    ) -> Z3ProofResult:
        started_at = time.perf_counter()
        operation = "prove_always_nonzero" if nonzero else "prove_always_zero"
        try:
            native_mop = self._coerce_single_operand(
                mop, blk=blk, operation=operation
            )
        except Exception as exc:
            logger.debug("bounded operand preparation failed: %s", exc)
            return _unsupported_result(started_at)
        if native_mop is None:
            return _unsupported_result(started_at)
        cache_allowed = self._cache_is_context_free(
            mop,
            blk=blk,
            ins=ins,
            solver=solver,
        )
        try:
            identity = structural_mop_hash(native_mop, 0)
        except Exception:
            identity = (
                native_mop.dstr()
                if hasattr(native_mop, "dstr")
                else repr(native_mop)
            )
        cache_key = (self._policy, int(native_mop.t), int(native_mop.size), identity)
        cache = self._always_nonzero_cache if nonzero else self._always_zero_cache
        if cache_allowed:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        try:
            prepared = self._prepare_single_ast(
                native_mop,
                blk=blk,
                ins=ins,
                operation=operation,
            )
        except Z3NodeLimitExceeded as exc:
            # The builder raises with the consumed count.  Recreate the receipt
            # without exposing its mutable budget implementation to callers.
            return Z3ProofResult(
                status=Z3ProofStatus.ABSTAINED,
                reason=Z3ProofAbstentionReason.NODE_LIMIT,
                observed_expression_nodes=exc.observed_nodes,
                elapsed_ms=(time.perf_counter() - started_at) * 1000.0,
            )
        except Exception as exc:
            logger.debug("bounded AST preparation failed: %s", exc)
            return _unsupported_result(started_at)
        if prepared is None:
            return _unsupported_result(started_at)
        native_mop, ast, budget, visitor_needs_budget = prepared
        try:
            create_z3_vars(ast.get_leaf_list())
            visitor = (
                AstNodeZ3Visitor(node_budget=budget)
                if visitor_needs_budget
                else AstNodeZ3Visitor()
            )
            z3_expr = visitor.visit(ast)
        except Z3NodeLimitExceeded:
            assert budget is not None
            return _node_limit_result(started_at, budget)
        except Exception as exc:
            logger.debug("bounded zero translation failed: %s", exc)
            observed = budget.observed_nodes if budget is not None else None
            return _unsupported_result(started_at, observed)
        observed = budget.observed_nodes if budget is not None else None
        if z3_expr is None:
            return _unsupported_result(started_at, observed)
        try:
            query_solver = _new_query_solver(self._policy, solver)
            query_solver.push()
            try:
                zero = z3.BitVecVal(0, z3_expr.size())
                query_solver.add(z3_expr == zero if nonzero else z3_expr != zero)
                check_result = query_solver.check()
            finally:
                query_solver.pop()
        except Exception as exc:
            logger.debug("bounded zero solver query failed: %s", exc)
            result = Z3ProofResult(
                status=Z3ProofStatus.ABSTAINED,
                reason=Z3ProofAbstentionReason.SOLVER_UNKNOWN,
                observed_expression_nodes=observed,
                elapsed_ms=(time.perf_counter() - started_at) * 1000.0,
            )
        else:
            result = _classify_solver_result(
                check_result,
                query_solver,
                self._policy,
                started_at,
                observed,
            )
        if cache_allowed and result.status in {
            Z3ProofStatus.PROVED,
            Z3ProofStatus.DISPROVED,
        }:
            cache[cache_key] = result
        return result

    @requires_z3_installed
    def prove_always_zero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> Z3ProofResult:
        blk, ins = self._resolve_context(blk, ins)
        return self._prove_always_zero_or_nonzero(
            mop, nonzero=False, blk=blk, ins=ins, solver=solver
        )

    @requires_z3_installed
    def is_always_zero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
    ) -> bool:
        """Compatibility wrapper returning ``True`` only for ``PROVED``."""

        return self.prove_always_zero(mop, blk=blk, ins=ins).status is Z3ProofStatus.PROVED

    @requires_z3_installed
    def prove_always_nonzero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        solver: z3.Solver | None = None,
    ) -> Z3ProofResult:
        blk, ins = self._resolve_context(blk, ins)
        return self._prove_always_zero_or_nonzero(
            mop, nonzero=True, blk=blk, ins=ins, solver=solver
        )

    @requires_z3_installed
    def is_always_nonzero(
        self,
        mop: ida_hexrays.mop_t | None,
        *,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
    ) -> bool:
        """Compatibility wrapper returning ``True`` only for ``PROVED``."""

        return (
            self.prove_always_nonzero(mop, blk=blk, ins=ins).status
            is Z3ProofStatus.PROVED
        )

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
        self._comparison_cache.clear()
        self._always_zero_cache.clear()
        self._always_nonzero_cache.clear()


def d810_backend_probe() -> str | None:
    """Backend plugin protocol hook: ``None`` if usable, else why not.

    This module imports cleanly whether or not z3 is installed -- it only
    sets Z3_INSTALLED -- so import success is not evidence the backend works.
    Z3_INSTALLED stays authoritative; this just exposes it uniformly.
    """
    return (
        None
        if Z3_INSTALLED
        else ("z3 not installed or failed to import (pip install z3-solver)")
    )
