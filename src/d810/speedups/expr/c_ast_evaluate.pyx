# distutils: language = c++
# cython: language_level=3, embedsignature=True
# cython: cdivision=True
# distutils: define_macros=__EA64__=1
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

logger = getLogger(__name__)

# Lazy import to avoid circular dependency with c_ast.pyx
# These get populated on first use
cdef object _AstNode = None
cdef object _AstLeaf = None
cdef object _AstConstant = None
cdef object _AstProxy = None

cdef inline void _ensure_types_loaded():
    global _AstNode, _AstLeaf, _AstConstant, _AstProxy
    if _AstNode is None:
        from d810.speedups.expr.c_ast import AstNode, AstLeaf, AstConstant, AstProxy
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


cdef class AstEvaluator:
    """
    Pure-Python evaluator for AST nodes. Extracted from AstNode/AstLeaf methods
    to centralize evaluation logic.
    """

    cpdef object evaluate_with_leaf_info(self, object node, object leafs_info, object leafs_value):
        dict_index_to_value = {}
        for leaf_info, leaf_value in zip(leafs_info, leafs_value):
            if leaf_info.ast.ast_index is not None:
                dict_index_to_value[leaf_info.ast.ast_index] = leaf_value
        return self.evaluate(node, dict_index_to_value)

    cpdef object evaluate(self, object node, dict dict_index_to_value):
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
        # AstConstant: prefer concrete mop value, otherwise fall back to expected_value
        if isinstance(leaf, _AstConstant):
            if leaf.mop is not None and leaf.mop.t == ida_hexrays.mop_n:
                return leaf.mop.nnn.value
            return leaf.expected_value

        if leaf.is_constant() and leaf.mop is not None:
            return leaf.mop.nnn.value
        assert leaf.ast_index is not None
        return dict_index_to_value.get(leaf.ast_index)

    cdef inline object _eval_node(self, object node, dict dict_index_to_value):
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
            return 0 & res_mask
        else:
            raise AstEvaluationException(
                "Can't evaluate opcode: {0}".format(node.opcode)
            )
