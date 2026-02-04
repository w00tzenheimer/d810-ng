import typing

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.expr.ast import AstConstant, AstNode, minsn_to_ast
from d810.expr.z3_utils import z3_check_mop_equality
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule

logger = getLogger(__name__)


class Z3ConstantOptimization(Z3Rule):
    DESCRIPTION = "Detect and replace obfuscated constants"

    def __init__(self):
        super().__init__()
        self.min_nb_opcode = 3
        self.min_nb_constant = 3

    @property
    def PATTERN(self) -> AstNode | None:
        """Return the pattern to match."""
        return

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("c_res"))

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_opcode" in kwargs.keys():
            self.min_nb_opcode = kwargs["min_nb_opcode"]
        if "min_nb_constant" in kwargs.keys():
            self.min_nb_constant = kwargs["min_nb_constant"]

    @typing.override
    def check_and_replace(self, blk: ida_hexrays.mblock_t, instruction: ida_hexrays.minsn_t) -> ida_hexrays.minsn_t | None:
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return None
        leaf_info_list, cst_leaf_values, opcodes = tmp.get_information()
        leaf_num = len(leaf_info_list)

        if (
            leaf_num != 1
            or len(opcodes) < self.min_nb_opcode
            or len(cst_leaf_values) < self.min_nb_constant
        ):
            return None

        if logger.debug_on:
            logger.debug("Found candidate: %s", format_minsn_t(instruction))
        try:
            val_0 = tmp.evaluate_with_leaf_info(leaf_info_list, [0])  # * leaf_num)
            val_1 = tmp.evaluate_with_leaf_info(
                leaf_info_list, [0xFFFFFFFF]
            )  # * leaf_num)
            if logger.debug_on:
                logger.debug("  val_0: %s, val_1: %s", val_0, val_1)
            if val_0 != val_1 or tmp.mop is None:
                return None

            # TODO(w00tzenheimer): if we're evaluating (evaluate_with_leaf_info) and the results are equal,
            #   why do we need to run the z3 equality check?
            #   why can't this simply be:
            #   if val_0 != val_1 or tmp.mop is None:
            #       return None
            #   tmp.add_constant_leaf("c_res", val_0, tmp.mop.size)
            #   tmp.compute_sub_ast()
            #   new_instruction = self.get_replacement(typing.cast(AstNode, tmp))
            #   return new_instruction
            c_res_mop = ida_hexrays.mop_t()
            c_res_mop.make_number(val_0, tmp.mop.size or 1)
            if z3_check_mop_equality(tmp.mop, c_res_mop):
                if logger.debug_on:
                    logger.debug("  z3_check_mop_equality is equal")

                tmp.add_constant_leaf("c_res", val_0, tmp.mop.size)
                # TODO(w00tzenheimer): should we recompute caches so that leafs_by_name contains the new constant leaf?
                # tmp.compute_sub_ast()
                new_instruction = self.get_replacement(typing.cast(AstNode, tmp))
                return new_instruction
        except ZeroDivisionError:
            logger.error("ZeroDivisionError while evaluating %s", tmp, exc_info=True)
        except AstEvaluationException as e:
            logger.error("Error while evaluating %s: %s", tmp, e, exc_info=True)

    @typing.override
    def check_candidate(self, candidate: AstNode) -> bool:
        """Return True if the candidate matches the rule, otherwise False."""
        return True
