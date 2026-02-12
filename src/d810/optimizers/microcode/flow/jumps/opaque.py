import ida_hexrays

from d810.core.bits import unsigned_to_signed
from d810.expr.ast import AstConstant, AstLeaf, AstNode, mop_to_ast
from d810.expr.z3_utils import z3_check_mop_equality, z3_check_mop_inequality
from d810.optimizers.microcode.flow.jumps.handler import JumpOptimizationRule


_COND_JUMP_PAIR_BASE = (
    (ida_hexrays.m_jnz, ida_hexrays.m_jz),
    (ida_hexrays.m_jb, ida_hexrays.m_jae),
    (ida_hexrays.m_ja, ida_hexrays.m_jbe),
    (ida_hexrays.m_jl, ida_hexrays.m_jge),
    (ida_hexrays.m_jg, ida_hexrays.m_jle),
)

# Enumerate both directions from pair bases, like:
#   (A, B), (B, A), ...
COND_JUMP_PAIR_ENUM = tuple(
    pair
    for left, right in _COND_JUMP_PAIR_BASE
    for pair in ((left, right), (right, left))
)


def _is_constant_ast(ast) -> bool:
    """Return True when *ast* contains only constant leaves."""
    if ast is None:
        return False
    if ast.is_leaf():
        return ast.is_constant()

    left = getattr(ast, "left", None)
    right = getattr(ast, "right", None)
    if left is None:
        return False
    if not _is_constant_ast(left):
        return False
    if right is not None and not _is_constant_ast(right):
        return False
    return True


def _eval_constant_mop(mop) -> int | None:
    """Evaluate *mop* when it is a constant-only expression tree."""
    try:
        ast = mop_to_ast(mop)
    except Exception:
        return None
    if ast is None or not _is_constant_ast(ast):
        return None
    try:
        return int(ast.evaluate({}))
    except Exception:
        return None


def _constant_relation(left_mop, right_mop) -> bool | None:
    """Return constant equality relation for mops, or None if non-constant."""
    left_val = _eval_constant_mop(left_mop)
    if left_val is None:
        return None
    right_val = _eval_constant_mop(right_mop)
    if right_val is None:
        return None
    return left_val == right_val


def _target_for_relation(
    opcode: int, is_equal: bool, jump_target: int, fallthrough_target: int
) -> int:
    """Return replacement target serial for jz/jnz given relation truth."""
    if is_equal:
        # jz takes jump target when equal; jnz takes fall-through.
        return jump_target if opcode == ida_hexrays.m_jz else fallthrough_target
    # not equal
    return jump_target if opcode == ida_hexrays.m_jnz else fallthrough_target


def _constant_jump_taken(opcode: int, left_mop, right_mop) -> bool | None:
    """Return jump-taken decision for constant-only conditional jumps."""
    left_val = _eval_constant_mop(left_mop)
    if left_val is None:
        return None
    right_val = _eval_constant_mop(right_mop)
    if right_val is None:
        return None

    size = max(getattr(left_mop, "size", 0), getattr(right_mop, "size", 0))
    if size <= 0:
        size = 8
    mask = (1 << (size * 8)) - 1
    left_u = left_val & mask
    right_u = right_val & mask

    if opcode == ida_hexrays.m_jnz:
        return left_u != right_u
    if opcode == ida_hexrays.m_jz:
        return left_u == right_u
    if opcode == ida_hexrays.m_jb:
        return left_u < right_u
    if opcode == ida_hexrays.m_jae:
        return left_u >= right_u
    if opcode == ida_hexrays.m_ja:
        return left_u > right_u
    if opcode == ida_hexrays.m_jbe:
        return left_u <= right_u

    left_s = unsigned_to_signed(left_u, size)
    right_s = unsigned_to_signed(right_u, size)
    if opcode == ida_hexrays.m_jl:
        return left_s < right_s
    if opcode == ida_hexrays.m_jge:
        return left_s >= right_s
    if opcode == ida_hexrays.m_jg:
        return left_s > right_s
    if opcode == ida_hexrays.m_jle:
        return left_s <= right_s

    return None


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
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jcnd] + list(
        dict.fromkeys(op for pair in COND_JUMP_PAIR_ENUM for op in pair)
    )
    LEFT_PATTERN = AstLeaf("x_0")
    RIGHT_PATTERN = AstLeaf("x_1")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def _make_goto_ins(self, instruction, target_serial: int):
        new_ins = ida_hexrays.minsn_t(instruction)
        new_ins.opcode = ida_hexrays.m_goto
        new_ins.l.erase()
        new_ins.r.erase()
        new_ins.d = ida_hexrays.mop_t()
        new_ins.d.make_blkref(target_serial)
        return new_ins

    def check_pattern_and_replace(self, blk, instruction, left_ast, right_ast):
        # m_jcnd has a single condition operand; bypass binary pattern matching
        # and fold when the condition is a constant-only expression.
        if instruction.opcode == ida_hexrays.m_jcnd:
            if instruction.d is None or instruction.d.t != ida_hexrays.mop_b:
                return None
            if blk.nextb is None:
                return None
            cond_val = _eval_constant_mop(instruction.l)
            if cond_val is None:
                return None
            target_serial = instruction.d.b if cond_val != 0 else blk.nextb.serial
            return self._make_goto_ins(instruction, target_serial)
        return super().check_pattern_and_replace(blk, instruction, left_ast, right_ast)

    def check_candidate(self, opcode, left_candidate, right_candidate):
        # print(mop_to_ast(left_candidate.mop))
        # print(repr(left_candidate.mop))
        # print(dir(left_candidate.mop))
        if opcode in (ida_hexrays.m_jnz, ida_hexrays.m_jz) and z3_check_mop_equality(
            left_candidate.mop, right_candidate.mop
        ):
            self.jump_replacement_block_serial = _target_for_relation(
                opcode,
                is_equal=True,
                jump_target=self.jump_original_block_serial,
                fallthrough_target=self.direct_block_serial,
            )
            return True
        if opcode in (ida_hexrays.m_jnz, ida_hexrays.m_jz) and z3_check_mop_inequality(
            left_candidate.mop, right_candidate.mop
        ):
            self.jump_replacement_block_serial = _target_for_relation(
                opcode,
                is_equal=False,
                jump_target=self.jump_original_block_serial,
                fallthrough_target=self.direct_block_serial,
            )
            return True
        # Fallback: if both sides are concretely evaluable constants, fold
        # opaque predicates for all supported paired conditional jumps.
        jump_taken = _constant_jump_taken(opcode, left_candidate.mop, right_candidate.mop)
        if jump_taken is not None:
            self.jump_replacement_block_serial = (
                self.jump_original_block_serial if jump_taken else self.direct_block_serial
            )
            return True
        return False
