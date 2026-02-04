from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import equal_bnot_mop, equal_mops_bypass_xdu
from d810.optimizers.microcode.flow.jumps.handler import JumpOptimizationRule

import ida_hexrays


class CompareConstantRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jge]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_and,
        AstNode(ida_hexrays.m_or, AstLeaf("xdu_x_0"), AstConstant("c_2")),
        AstNode(
            ida_hexrays.m_or,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(ida_hexrays.m_bnot, AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstConstant("c_1"))),
        ),
    )
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = ida_hexrays.m_jl
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if not equal_mops_bypass_xdu(
            left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop
        ):
            return False
        if not equal_bnot_mop(left_candidate["c_2"].mop, left_candidate["c_1"].mop):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule2(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jge]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_or,
        AstNode(
            ida_hexrays.m_xdu, AstNode(ida_hexrays.m_and, AstNode(ida_hexrays.m_bnot, AstLeaf("x_0")), AstConstant("c_1"))
        ),
        AstNode(
            ida_hexrays.m_and,
            AstNode(ida_hexrays.m_sub, AstLeaf("xdu_x_0"), AstConstant("xdu_c_1")),
            AstNode(
                ida_hexrays.m_bnot,
                AstNode(
                    ida_hexrays.m_xdu, AstNode(ida_hexrays.m_xor, AstLeaf("xdu1_x_0"), AstConstant("xdu_c_1"))
                ),
            ),
        ),
    )
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = ida_hexrays.m_jge
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if not equal_mops_bypass_xdu(
            left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop
        ):
            return False
        if not equal_mops_bypass_xdu(
            left_candidate["xdu1_x_0"].mop, left_candidate["x_0"].mop
        ):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule3(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jge]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_and,
        AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstConstant("c_1")),
        AstNode(ida_hexrays.m_bnot, AstLeaf("x_0")),
    )
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = ida_hexrays.m_jg
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule4(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jl, ida_hexrays.m_jge]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_and,
        AstNode(
            ida_hexrays.m_or,
            AstNode(ida_hexrays.m_bnot, AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstConstant("c_1"))),
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstConstant("c_1")),
        ),
        AstNode(ida_hexrays.m_or, AstLeaf("xdu_x_0"), AstConstant("bnot_c_1")),
    )

    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = ida_hexrays.m_jge
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        print("dflighdrth")
        if not equal_mops_bypass_xdu(
            left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop
        ):
            return False
        if not equal_bnot_mop(
            left_candidate["c_1"].mop, left_candidate["bnot_c_1"].mop
        ):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True
