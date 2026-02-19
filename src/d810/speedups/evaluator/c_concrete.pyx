# distutils: language = c++
# cython: language_level=3, embedsignature=True
# cython: cdivision=True
# distutils: define_macros=__EA64__=1
"""Cython fast path for the concrete microcode AST evaluator.

This module mirrors :class:`d810.evaluator.concrete.ConcreteEvaluator` and
exposes :class:`CythonConcreteEvaluator`, which implements the same interface
but with Cython-optimised dispatch.

It replaces ``d810.speedups.expr.c_ast_evaluate.AstEvaluator`` following
the ``d810.speedups.<pkgname>`` convention established by the evaluator
package refactor (Phase 5).

See ``docs/plans/2026-02-18-evaluator-package-refactor.md``, section 4.6.

Key differences from the deprecated ``c_ast_evaluate.pyx``:
- Accepts plain Python ``AstBase`` objects from ``d810.expr.p_ast``
  (not the Cython types from ``d810.speedups.expr.c_ast``).
- Helper lookup goes through :func:`d810.evaluator.helpers.get_registry`
  instead of ``getattr(d810.core.bits, helper_name, None)``.
"""
from __future__ import annotations

import ida_hexrays

from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.core.bits import (
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    signed_to_unsigned,
    unsigned_to_signed,
)
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.evaluator.helpers import get_registry as _get_registry

logger = getLogger(__name__)

# Lazy-loaded Python AST types from d810.expr.p_ast.
# Using plain Python types (not Cython c_ast types) so that
# CythonConcreteEvaluator can be used with any AstBase instance,
# including mock objects in unit tests.
cdef object _AstNode = None
cdef object _AstLeaf = None
cdef object _AstConstant = None
cdef object _AstProxy = None


cdef inline void _ensure_types_loaded():
    global _AstNode, _AstLeaf, _AstConstant, _AstProxy
    if _AstNode is None:
        from d810.expr.ast import AstNode, AstLeaf, AstConstant, AstProxy
        _AstNode = AstNode
        _AstLeaf = AstLeaf
        _AstConstant = AstConstant
        _AstProxy = AstProxy


cdef object _BINARY_OPCODES = frozenset((
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
    ida_hexrays.m_cfadd,
    ida_hexrays.m_ofadd,
    ida_hexrays.m_seto,
    ida_hexrays.m_setnz,
    ida_hexrays.m_setz,
    ida_hexrays.m_setae,
    ida_hexrays.m_setb,
    ida_hexrays.m_seta,
    ida_hexrays.m_setbe,
    ida_hexrays.m_setg,
    ida_hexrays.m_setge,
    ida_hexrays.m_setl,
    ida_hexrays.m_setle,
    ida_hexrays.m_setp,
))


cdef class CythonConcreteEvaluator:
    """Cython fast path for the concrete microcode AST evaluator.

    Implements the same interface as
    :class:`d810.evaluator.concrete.ConcreteEvaluator` and can be used as
    a drop-in replacement.  The module-level singleton in
    :mod:`d810.evaluator.concrete` swaps to this class when the extension
    is available.

    Accepts plain Python ``AstBase`` instances from ``d810.expr.p_ast``;
    no dependency on the Cython AST types in ``d810.speedups.expr.c_ast``.
    """

    cpdef object evaluate_with_leaf_info(
        self,
        object node,
        object leafs_info,
        object leafs_value,
    ):
        """Evaluate *node* using per-leaf info objects and a value list.

        Convenience wrapper used by ``Z3ConstantOptimization`` and the
        ``AstNode.evaluate_with_leaf_info`` shim.

        Args:
            node: Root of the AST to evaluate.
            leafs_info: List of ``AstInfo``-like objects whose ``.ast``
                attribute exposes an ``ast_index`` integer.
            leafs_value: Parallel list of concrete integer values.

        Returns:
            Concrete integer result.
        """
        cdef dict dict_index_to_value = {}
        for leaf_info, leaf_value in zip(leafs_info, leafs_value):
            if leaf_info.ast.ast_index is not None:
                dict_index_to_value[leaf_info.ast.ast_index] = leaf_value
        return self.evaluate(node, dict_index_to_value)

    cpdef object evaluate(self, object node, dict dict_index_to_value):
        """Evaluate *node* given concrete leaf bindings.

        Dispatches to :meth:`_eval_node` or :meth:`_eval_leaf` depending
        on the node type.  Follows ``AstProxy`` transparently.

        Args:
            node: Root of the AST to evaluate (``AstBase`` instance).
            dict_index_to_value: Mapping from ``ast_index`` to concrete
                integer value for each variable leaf.

        Returns:
            Concrete integer result, masked to ``node.dest_size`` bits.

        Raises:
            AstEvaluationException: For unsupported node types or opcodes.
        """
        _ensure_types_loaded()
        if isinstance(node, _AstNode):
            return self._eval_node(node, dict_index_to_value)
        if isinstance(node, _AstLeaf):
            return self._eval_leaf(node, dict_index_to_value)
        if isinstance(node, _AstProxy):
            return self.evaluate(node._target, dict_index_to_value)
        raise AstEvaluationException(
            f"Unsupported AST node type: {type(node).__name__}"
        )

    cdef inline object _eval_leaf(self, object leaf, dict dict_index_to_value):
        """Evaluate a leaf node (``AstLeaf`` / ``AstConstant``).

        Returns the constant value stored in the mop for ``AstConstant``
        nodes, or looks up the variable's value from *dict_index_to_value*
        for ``AstLeaf`` nodes.
        """
        # AstConstant: prefer concrete mop value, otherwise fall back to expected_value
        if isinstance(leaf, _AstConstant):
            if leaf.mop is not None and leaf.mop.t == ida_hexrays.mop_n:
                return leaf.mop.nnn.value
            return leaf.expected_value

        if leaf.is_constant() and leaf.mop is not None:
            return leaf.mop.nnn.value
        assert leaf.ast_index is not None
        val = dict_index_to_value.get(leaf.ast_index)
        if val is None:
            raise AstEvaluationException(
                f"Variable leaf ast_index={leaf.ast_index} not found in env"
            )
        return val

    cdef inline object _eval_node(self, object node, dict dict_index_to_value):
        """Evaluate an interior ``AstNode``.

        Full opcode dispatch chain.  Helper lookup goes through
        :func:`d810.evaluator.helpers.get_registry` so all registered
        helpers (rotate, future bswap, etc.) are available without
        touching this file.
        """
        if node.ast_index in dict_index_to_value:
            return dict_index_to_value[node.ast_index]
        if node.dest_size is None:
            raise ValueError("dest_size is None")

        res_mask = AND_TABLE[node.dest_size]

        if node.left is None:
            raise ValueError(f"left is None for opcode: {node.opcode}")

        if node.opcode in _BINARY_OPCODES and node.right is None:
            raise ValueError("right is None for binary opcode: {0}".format(node.opcode))

        if node.opcode == ida_hexrays.m_mov:
            return (self.evaluate(node.left, dict_index_to_value)) & res_mask
        elif node.opcode == ida_hexrays.m_neg:
            return (-self.evaluate(node.left, dict_index_to_value)) & res_mask
        elif node.opcode == ida_hexrays.m_lnot:
            return self.evaluate(node.left, dict_index_to_value) != 0
        elif node.opcode == ida_hexrays.m_bnot:
            return (self.evaluate(node.left, dict_index_to_value) ^ res_mask) & res_mask
        elif node.opcode == ida_hexrays.m_xds:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            return signed_to_unsigned(left_value_signed, node.dest_size) & res_mask
        elif node.opcode == ida_hexrays.m_xdu:
            return (self.evaluate(node.left, dict_index_to_value)) & res_mask
        elif node.opcode == ida_hexrays.m_low:
            return (self.evaluate(node.left, dict_index_to_value)) & res_mask
        elif node.opcode == ida_hexrays.m_high:
            if node.left.dest_size is None:
                raise ValueError("left.dest_size is None for m_high")
            shift_bits = node.dest_size * 8 if node.dest_size is not None else 0
            return (
                self.evaluate(node.left, dict_index_to_value) >> shift_bits
            ) & res_mask
        elif node.opcode == ida_hexrays.m_add and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                + self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_sub and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                - self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_mul and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                * self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_udiv and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                // self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_sdiv and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                // self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_umod and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                % self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_smod and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                % self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_or and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                | self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_and and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                & self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_xor and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                ^ self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_shl and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                << self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_shr and node.right is not None:
            return (
                self.evaluate(node.left, dict_index_to_value)
                >> self.evaluate(node.right, dict_index_to_value)
            ) & res_mask
        elif node.opcode == ida_hexrays.m_sar and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            res_signed = left_value_signed >> self.evaluate(
                node.right, dict_index_to_value
            )
            return signed_to_unsigned(res_signed, node.dest_size) & res_mask
        elif node.opcode == ida_hexrays.m_cfadd and node.right is not None:
            tmp = get_add_cf(
                self.evaluate(node.left, dict_index_to_value),
                self.evaluate(node.right, dict_index_to_value),
                node.left.dest_size,
            )
            return tmp & res_mask
        elif node.opcode == ida_hexrays.m_ofadd and node.right is not None:
            tmp = get_add_of(
                self.evaluate(node.left, dict_index_to_value),
                self.evaluate(node.right, dict_index_to_value),
                node.left.dest_size,
            )
            return tmp & res_mask
        elif node.opcode == ida_hexrays.m_sets:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            res = 1 if left_value_signed < 0 else 0
            return res & res_mask
        elif node.opcode == ida_hexrays.m_seto and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.evaluate(node.right, dict_index_to_value), node.right.dest_size
            )
            sub_overflow = get_sub_of(
                left_value_signed, right_value_signed, node.left.dest_size
            )
            return sub_overflow & res_mask
        elif node.opcode == ida_hexrays.m_setnz and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                != self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setz and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                == self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setae and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                >= self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setb and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                < self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_seta and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                > self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setbe and node.right is not None:
            res = (
                1
                if self.evaluate(node.left, dict_index_to_value)
                <= self.evaluate(node.right, dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setg and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.evaluate(node.right, dict_index_to_value), node.right.dest_size
            )
            res = 1 if left_value_signed > right_value_signed else 0
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setge and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.evaluate(node.right, dict_index_to_value), node.right.dest_size
            )
            res = 1 if left_value_signed >= right_value_signed else 0
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setl and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.evaluate(node.right, dict_index_to_value), node.right.dest_size
            )
            res = 1 if left_value_signed < right_value_signed else 0
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setle and node.right is not None:
            left_value_signed = unsigned_to_signed(
                self.evaluate(node.left, dict_index_to_value), node.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.evaluate(node.right, dict_index_to_value), node.right.dest_size
            )
            res = 1 if left_value_signed <= right_value_signed else 0
            return res & res_mask
        elif node.opcode == ida_hexrays.m_setp and node.right is not None:
            res = get_parity_flag(
                self.evaluate(node.left, dict_index_to_value),
                self.evaluate(node.right, dict_index_to_value),
                node.left.dest_size,
            )
            return res & res_mask
        elif node.opcode == ida_hexrays.m_call:
            if logger.debug_on:
                logger.debug(
                    "evaluate m_call: ast_index=%s, dest_size=%s, callee=%s, args=%s",
                    node.ast_index,
                    node.dest_size,
                    node.left,
                    node.right,
                )
            # Attempt to evaluate rotate helper calls (__ROL*/__ROR*).
            # func_name is populated by mop_to_ast_internal when building
            # AST nodes for rotate helper calls.
            helper_name = (getattr(node, "func_name", "") or "").lstrip("!")
            if (
                helper_name
                and (helper_name.startswith("__ROL") or helper_name.startswith("__ROR"))
                and node.left is not None
                and node.right is not None
            ):
                # Use HelperRegistry instead of getattr(d810.core.bits, ...)
                helper_func = _get_registry().lookup(helper_name)
                if helper_func is not None:
                    val = self.evaluate(node.left, dict_index_to_value)
                    rot = self.evaluate(node.right, dict_index_to_value)
                    result = helper_func(val, rot)
                    return result & res_mask
            # Unknown runtime value - treat as 0 to let constant evaluation proceed.
            return 0 & res_mask
        else:
            raise AstEvaluationException(
                "Can't evaluate opcode: {0}".format(node.opcode)
            )
