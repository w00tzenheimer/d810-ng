import ida_hexrays

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.expr.z3_utils import z3_check_mop_equality, z3_check_mop_inequality
from d810.optimizers.microcode.flow.jumps.handler import JumpOptimizationRule


class JnzRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_neg, AstNode(ida_hexrays.m_and, AstNode(ida_hexrays.m_bnot, AstLeaf("x_0")), AstConstant("1", 1))
    )
    RIGHT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule2(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(ida_hexrays.m_or, AstNode(ida_hexrays.m_bnot, AstLeaf("x_0")), AstConstant("1", 1))
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule3(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_xor,
        AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstConstant("c_1")),
        AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("c_2")),
    )
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & left_candidate["c_2"].value
        if tmp == 0:
            return False
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule4(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(ida_hexrays.m_sub, AstConstant("3", 3), AstLeaf("x_0"))
    RIGHT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule5(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_xor, AstNode(ida_hexrays.m_sub, AstConstant("3", 3), AstLeaf("x_0")), AstLeaf("x_0")
    )
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule6(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_xor,
        AstNode(ida_hexrays.m_bnot, AstNode(ida_hexrays.m_sub, AstConstant("3", 3), AstLeaf("x_0"))),
        AstNode(ida_hexrays.m_bnot, AstLeaf("x_0")),
    )
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule7(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & right_candidate["c_2"].value
        if tmp == right_candidate["c_2"].value:
            return False
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JnzRule8(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        tmp = left_candidate["c_1"].value & right_candidate["c_2"].value
        if tmp == left_candidate["c_1"].value:
            return False

        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        else:
            self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JbRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jb]
    LEFT_PATTERN = AstNode(ida_hexrays.m_xdu, AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("1", 1)))
    RIGHT_PATTERN = AstConstant("2", 2)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class JaeRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jae]
    LEFT_PATTERN = AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("c_1"))
    RIGHT_PATTERN = AstConstant("c_2")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if left_candidate["c_1"].value >= right_candidate["c_2"].value:
            return False
        self.jump_replacement_block_serial = self.direct_block_serial
        return True


class JmpRuleZ3Const(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstLeaf("x_0")
    RIGHT_PATTERN = AstLeaf("x_1")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        # print(mop_to_ast(left_candidate.mop))
        # print(repr(left_candidate.mop))
        # print(dir(left_candidate.mop))
        if z3_check_mop_equality(left_candidate.mop, right_candidate.mop):
            self.jump_replacement_block_serial = (
                self.direct_block_serial
                if opcode == ida_hexrays.m_jnz
                else self.jump_original_block_serial
            )
            return True
        if z3_check_mop_inequality(left_candidate.mop, right_candidate.mop):
            self.jump_replacement_block_serial = (
                self.direct_block_serial
                if opcode != ida_hexrays.m_jnz
                else self.jump_original_block_serial
            )
            return True
        return False
