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


__all__ = [
    "minsn_to_ast",
]
