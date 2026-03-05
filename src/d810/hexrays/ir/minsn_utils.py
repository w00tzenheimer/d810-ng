"""Instruction-level AST builder utilities.

Converts IDA IR types (minsn_t) to AST types (AstNode, AstLeaf).
Split from hexrays.expr.p_ast as part of the IR/AST layer separation.
"""

from __future__ import annotations

import ida_hexrays

import d810.core.typing as typing
from d810.core import getLogger
from d810.hexrays.ir.mop_utils import mop_to_ast
from d810.hexrays.utils.hexrays_formatters import format_minsn_t, opcode_to_string
from d810.hexrays.utils.hexrays_helpers import (
    MBA_RELATED_OPCODES,
    MINSN_TO_AST_FORBIDDEN_OPCODES,
    get_mop_index,
    is_rotate_helper_call,
)

logger = getLogger(__name__)


def _py_slow_minsn_to_ast(instruction: ida_hexrays.minsn_t) -> typing.Any | None:
    try:
        # Early filter: forbidden opcodes
        if instruction.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for forbidden opcode: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
            return None

        # Early filter: unsupported opcodes (not in MBA_RELATED_OPCODES)
        # Allow rotate helper calls ("__ROL*" / "__ROR*") even though m_call
        # is normally filtered out - they can be constant-folded later.
        if instruction.opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(
            instruction
        ):
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for unsupported opcode: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
            return None

        # Constant-returning helper calls are folded to m_ldc by the peephole
        # pass ConstantCallResultFoldRule.  No need for AST special case.

        # Transparent-call shortcut: no args, computation stored in destination mop_d
        if (
            instruction.opcode == ida_hexrays.m_call
            and (instruction.r is None or instruction.r.t == ida_hexrays.mop_z)
            and instruction.d is not None
            and instruction.d.t == ida_hexrays.mop_d
        ):
            if logger.debug_on:
                logger.debug(
                    "[minsn_to_ast] Unwrapping call with empty args; using destination expression for AST",
                )
            dest_ast = mop_to_ast(instruction.d)
            if dest_ast is not None:
                return dest_ast

        ins_mop = ida_hexrays.mop_t()
        ins_mop.create_from_insn(instruction)

        tmp = mop_to_ast(ins_mop)
        if tmp is None:
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for unsupported or nop instruction: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
        else:
            tmp.dst_mop = instruction.d
        return tmp
    except RuntimeError as e:
        logger.error(
            "Error while transforming instruction %s: %s",
            format_minsn_t(instruction),
            e,
        )


def minsn_to_ast(ins: ida_hexrays.minsn_t) -> typing.Any | None:
    """Convert a microcode instruction to an AST tree.

    Public, unified entrypoint that callers can use instead of reaching into
    the Cython module directly.
    """
    return _py_slow_minsn_to_ast(ins)


def _rename_leafs(leaf_list: list) -> list[str]:
    """Assign Z3-style variable names to AST leaf operands.

    Returns a list of ``BitVec`` declaration strings suitable for inclusion
    in a Z3 proof script.

    This is a pure formatting helper -- no Z3 import required.
    """
    known_leaf_list: list = []
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


def build_z3_equivalence_proof(
    original_ins: ida_hexrays.minsn_t,
    new_ins: ida_hexrays.minsn_t,
) -> str | None:
    """Return a Z3 proof script comparing *original_ins* with *new_ins*.

    Returns None when either instruction cannot be converted to an AST.
    The caller is responsible for writing the returned string to a logger.
    """
    orig_mba_tree = minsn_to_ast(original_ins)
    new_mba_tree = minsn_to_ast(new_ins)
    if orig_mba_tree is None or new_mba_tree is None:
        return None
    orig_leaf_list = orig_mba_tree.get_leaf_list()
    new_leaf_list = new_mba_tree.get_leaf_list()

    var_def_list = _rename_leafs(orig_leaf_list + new_leaf_list)

    lines: list[str] = []
    lines.append(
        "print('Testing: {0} == {1}')".format(
            format_minsn_t(original_ins), format_minsn_t(new_ins)
        )
    )
    for var_def in var_def_list:
        lines.append("{0}".format(var_def))

    removed_xdu = "{0}".format(orig_mba_tree).replace("xdu", "")
    lines.append("original_expr = {0}".format(removed_xdu))
    removed_xdu = "{0}".format(new_mba_tree).replace("xdu", "")
    lines.append("new_expr = {0}".format(removed_xdu))
    lines.append("prove(original_expr == new_expr)\n")

    return "\n".join(lines)


__all__ = [
    "minsn_to_ast",
]
