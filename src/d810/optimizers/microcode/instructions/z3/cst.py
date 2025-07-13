from d810.errors import AstEvaluationException
from d810.expr.ast import AstConstant, AstNode, minsn_to_ast
from d810.expr.z3_utils import z3_check_mop_equality
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule

from ida_hexrays import *


class Z3ConstantOptimization(Z3Rule):
    DESCRIPTION = "Detect and replace obfuscated constants"
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("c_res"))

    def __init__(self):
        super().__init__()
        self.min_nb_opcode = 3
        self.min_nb_constant = 3

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_opcode" in kwargs.keys():
            self.min_nb_opcode = kwargs["min_nb_opcode"]
        if "min_nb_constant" in kwargs.keys():
            self.min_nb_constant = kwargs["min_nb_constant"]

    def check_and_replace(self, blk, instruction):
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return None
        leaf_info_list, cst_leaf_values, opcodes = tmp.get_information()
        if (
            len(leaf_info_list) == 1
            and len(opcodes) >= self.min_nb_opcode
            and (len(cst_leaf_values) >= self.min_nb_constant)
        ):
            try:
                val_0 = tmp.evaluate_with_leaf_info(leaf_info_list, [0])
                val_1 = tmp.evaluate_with_leaf_info(leaf_info_list, [0xFFFFFFFF])

                if val_0 == val_1:
                    c_res_mop = mop_t()
                    c_res_mop.make_number(val_0, tmp.mop.size)
                    is_ok = z3_check_mop_equality(tmp.mop, c_res_mop)
                    if is_ok:
                        tmp.add_leaf("c_res", c_res_mop)
                        new_instruction = self.get_replacement(tmp)
                        return new_instruction
                    return None
            except ZeroDivisionError:
                pass
            except AstEvaluationException as e:
                print("Error while evaluating {0}: {1}".format(tmp, e))
                pass
        return None
