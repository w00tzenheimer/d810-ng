import logging
import typing

from ida_hexrays import *

from d810 import _compat
from d810.conf.loggers import LevelFlag
from d810.errors import AstEvaluationException
from d810.expr.ast import AstConstant, AstNode, minsn_to_ast
from d810.expr.z3_utils import z3_check_mop_equality
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule

optimizer_logger = logging.getLogger("D810.optimizer")
debug_on = LevelFlag(optimizer_logger.name, logging.DEBUG)


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
        return AstNode(m_mov, AstConstant("c_res"))

    @_compat.override
    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_opcode" in kwargs.keys():
            self.min_nb_opcode = kwargs["min_nb_opcode"]
        if "min_nb_constant" in kwargs.keys():
            self.min_nb_constant = kwargs["min_nb_constant"]

    @_compat.override
    def check_and_replace(self, blk: mblock_t, instruction: minsn_t) -> minsn_t | None:
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

        if debug_on:
            optimizer_logger.debug("Found candidate: %s", format_minsn_t(instruction))
        try:
            val_0 = tmp.evaluate_with_leaf_info(leaf_info_list, [0])  # * leaf_num)
            val_1 = tmp.evaluate_with_leaf_info(
                leaf_info_list, [0xFFFFFFFF]
            )  # * leaf_num)
            if debug_on:
                optimizer_logger.debug("  val_0: %s, val_1: %s", val_0, val_1)
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
            c_res_mop = mop_t()
            c_res_mop.make_number(val_0, tmp.mop.size)
            if z3_check_mop_equality(tmp.mop, c_res_mop):
                if debug_on:
                    optimizer_logger.debug("  z3_check_mop_equality is equal")

                tmp.add_constant_leaf("c_res", val_0, tmp.mop.size)
                # TODO(w00tzenheimer): should we recompute caches so that leafs_by_name contains the new constant leaf?
                # tmp.compute_sub_ast()
                new_instruction = self.get_replacement(typing.cast(AstNode, tmp))
                return new_instruction
        except ZeroDivisionError:
            optimizer_logger.error(
                "ZeroDivisionError while evaluating %s", tmp, exc_info=True
            )
        except AstEvaluationException as e:
            optimizer_logger.error(
                "Error while evaluating %s: %s", tmp, e, exc_info=True
            )

    @_compat.override
    def check_candidate(self, candidate: AstNode) -> bool:
        """Return True if the candidate matches the rule, otherwise False."""
        return True
