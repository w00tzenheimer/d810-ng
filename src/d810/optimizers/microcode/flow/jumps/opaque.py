import ida_hexrays

from d810.evaluator.evaluators import evaluate_concrete
from d810.core.bits import unsigned_to_signed
from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.ir.mop_utils import mop_to_ast
from d810.backends.ast.z3 import Z3MopProver
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
        result = evaluate_concrete(ast, {})
    except Exception:
        result = None

    # Compatibility path for non-d810 test stubs that only provide an
    # evaluate(dict) method. Real ASTs should be handled by evaluate_concrete.
    if result is None and hasattr(ast, "evaluate"):
        try:
            result = ast.evaluate({})
        except Exception:
            return None

    return int(result) if result is not None else None


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
    return _constant_jump_taken_values(opcode, left_val, right_val, size)


def _constant_jump_taken_values(
    opcode: int,
    left_val: int,
    right_val: int,
    size: int,
) -> bool | None:
    """Return jump-taken decision for already-resolved constant operands."""
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


def _mop_number_value(mop) -> int | None:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_n:
        return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None) if nnn is not None else None
    return None if value is None else int(value)


def _mop_value_key(mop) -> tuple[str, int, int] | None:
    if mop is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    t = getattr(mop, "t", None)
    if t == ida_hexrays.mop_r:
        value = getattr(mop, "r", None)
        return None if value is None else ("r", int(value), size)
    if t == ida_hexrays.mop_l:
        lref = getattr(mop, "l", None)
        idx = getattr(lref, "idx", None) if lref is not None else None
        return None if idx is None else ("l", int(idx), size)
    if t == ida_hexrays.mop_S:
        sref = getattr(mop, "s", None)
        off = (
            getattr(sref, "off", None)
            if sref is not None
            else getattr(mop, "stkoff", None)
        )
        return None if off is None else ("S", int(off), size)
    return None


def _clear_value_key_aliases(
    env: dict[tuple[str, int, int], int],
    key: tuple[str, int, int],
) -> None:
    kind, value, _size = key
    for candidate in tuple(env):
        if candidate[0] == kind and candidate[1] == value:
            env.pop(candidate, None)


def _iter_pre_tail_insns(blk, stop_insn=None):
    insn = getattr(blk, "head", None)
    seen = 0
    while insn is not None and seen < 512:
        if stop_insn is not None and insn is stop_insn:
            break
        yield insn
        seen += 1
        insn = getattr(insn, "next", None)


def _block_successors(blk) -> tuple[int, ...]:
    try:
        return tuple(int(blk.succ(idx)) for idx in range(int(blk.nsucc())))
    except Exception:
        return tuple(int(value) for value in getattr(blk, "succs", ()) or ())


def _block_predecessors(blk) -> tuple[int, ...]:
    try:
        return tuple(int(blk.pred(idx)) for idx in range(int(blk.npred())))
    except Exception:
        return tuple(int(value) for value in getattr(blk, "preds", ()) or ())


def _resolve_entry_constant(
    blk,
    key: tuple[str, int, int],
    *,
    depth: int,
    max_depth: int,
    seen: frozenset[int],
) -> int | None:
    if depth >= max_depth:
        return None
    preds = _block_predecessors(blk)
    if len(preds) != 1:
        return None
    pred_serial = preds[0]
    if pred_serial in seen:
        return None
    mba = getattr(blk, "mba", None)
    if mba is None:
        return None
    pred_blk = mba.get_mblock(pred_serial)
    if pred_blk is None:
        return None
    if int(getattr(blk, "serial", -1)) not in _block_successors(pred_blk):
        return None
    if len(_block_successors(pred_blk)) != 1:
        return None
    return _resolve_reaching_constant_for_key(
        pred_blk,
        key,
        stop_insn=None,
        depth=depth + 1,
        max_depth=max_depth,
        seen=seen | {int(getattr(blk, "serial", -1))},
    )


def _resolve_source_constant(
    blk,
    env: dict[tuple[str, int, int], int],
    mop,
    *,
    depth: int,
    max_depth: int,
    seen: frozenset[int],
) -> int | None:
    number = _mop_number_value(mop)
    if number is not None:
        return number
    key = _mop_value_key(mop)
    if key is None:
        return None
    if key in env:
        return env[key]
    return _resolve_entry_constant(
        blk,
        key,
        depth=depth,
        max_depth=max_depth,
        seen=seen,
    )


def _resolve_reaching_constant_for_key(
    blk,
    key: tuple[str, int, int],
    *,
    stop_insn=None,
    depth: int = 0,
    max_depth: int = 4,
    seen: frozenset[int] = frozenset(),
) -> int | None:
    env: dict[tuple[str, int, int], int] = {}
    for insn in _iter_pre_tail_insns(blk, stop_insn):
        dest_key = _mop_value_key(getattr(insn, "d", None))
        if dest_key is None:
            continue
        opcode = getattr(insn, "opcode", None)
        if opcode not in (ida_hexrays.m_mov, ida_hexrays.m_xdu):
            _clear_value_key_aliases(env, dest_key)
            continue
        value = _resolve_source_constant(
            blk,
            env,
            getattr(insn, "l", None),
            depth=depth,
            max_depth=max_depth,
            seen=seen,
        )
        if value is None:
            _clear_value_key_aliases(env, dest_key)
            continue
        size = dest_key[2]
        if size > 0:
            value &= (1 << (size * 8)) - 1
        _clear_value_key_aliases(env, dest_key)
        env[dest_key] = int(value)

    if key in env:
        return env[key]
    return _resolve_entry_constant(
        blk,
        key,
        depth=depth,
        max_depth=max_depth,
        seen=seen,
    )


def _resolve_reaching_constant_for_mop(blk, mop, *, stop_insn=None) -> int | None:
    number = _mop_number_value(mop)
    if number is not None:
        return number
    key = _mop_value_key(mop)
    if key is None:
        return None
    return _resolve_reaching_constant_for_key(
        blk,
        key,
        stop_insn=stop_insn,
        seen=frozenset({int(getattr(blk, "serial", -1))}),
    )


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


class _JnzModuloEvenIdentityRule(JumpOptimizationRule):
    """Base for adjacent-product modulo predicates that are always equal to 0."""

    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        # x*(x+1) % 2 == 0 and x*(x-1) % 2 == 0 are always true because one
        # adjacent factor is even. The matched condition is therefore equality
        # against zero.
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.direct_block_serial
        else:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class JnzRuleModIdentity(_JnzModuloEvenIdentityRule):
    """Opaque predicate for x*(x+1)%2 == 0 (always true).

    This mathematical identity holds because either x or (x+1) is even,
    so their product is always divisible by 2. The modulo 2 always yields 0.
    This rule handles the signed-mod x+1 variant.
    """
    # Pattern: smod(mul(X, add(X, 1)), 2) == 0
    # AstChoice was removed from the AST API; this keeps the opaque identity
    # optimization active without relying on a non-existent node type.
    LEFT_PATTERN = AstNode(
        ida_hexrays.m_smod,
        AstNode(
            ida_hexrays.m_mul,
            AstLeaf("x_0"),
            AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstConstant("1", 1))
        ),
        AstConstant("2", 2)
    )


class JnzRuleSmodSubIdentity(_JnzModuloEvenIdentityRule):
    """Opaque predicate for x*(x-1)%2 == 0 using signed modulo."""

    LEFT_PATTERN = AstNode(
        ida_hexrays.m_smod,
        AstNode(
            ida_hexrays.m_mul,
            AstLeaf("x_0"),
            AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstConstant("1", 1))
        ),
        AstConstant("2", 2)
    )


class JnzRuleUmodAddIdentity(_JnzModuloEvenIdentityRule):
    """Opaque predicate for x*(x+1)%2 == 0 using unsigned modulo."""

    LEFT_PATTERN = AstNode(
        ida_hexrays.m_umod,
        AstNode(
            ida_hexrays.m_mul,
            AstLeaf("x_0"),
            AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstConstant("1", 1))
        ),
        AstConstant("2", 2)
    )


class JnzRuleUmodSubIdentity(_JnzModuloEvenIdentityRule):
    """Opaque predicate for x*(x-1)%2 == 0 using unsigned modulo."""

    LEFT_PATTERN = AstNode(
        ida_hexrays.m_umod,
        AstNode(
            ida_hexrays.m_mul,
            AstLeaf("x_0"),
            AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstConstant("1", 1))
        ),
        AstConstant("2", 2)
    )


class JmpRuleReachingConst(JumpOptimizationRule):
    """Fold conditional jumps whose operands are constants on the incoming path."""

    ORIGINAL_JUMP_OPCODES = list(
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
        if instruction.opcode not in self.ORIGINAL_JUMP_OPCODES:
            return None
        if instruction.d is None or instruction.d.t != ida_hexrays.mop_b:
            return None
        if blk.nextb is None:
            return None

        left_val = _resolve_reaching_constant_for_mop(
            blk,
            instruction.l,
            stop_insn=instruction,
        )
        if left_val is None:
            return None
        right_val = _resolve_reaching_constant_for_mop(
            blk,
            instruction.r,
            stop_insn=instruction,
        )
        if right_val is None:
            return None

        size = max(
            int(getattr(instruction.l, "size", 0) or 0),
            int(getattr(instruction.r, "size", 0) or 0),
            1,
        )
        jump_taken = _constant_jump_taken_values(
            instruction.opcode,
            left_val,
            right_val,
            size,
        )
        if jump_taken is None:
            return None

        target_serial = int(instruction.d.b) if jump_taken else int(blk.nextb.serial)
        return self._make_goto_ins(instruction, target_serial)


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
        if opcode in (ida_hexrays.m_jnz, ida_hexrays.m_jz) and Z3MopProver().are_equal(
            left_candidate.mop, right_candidate.mop
        ):
            self.jump_replacement_block_serial = _target_for_relation(
                opcode,
                is_equal=True,
                jump_target=self.jump_original_block_serial,
                fallthrough_target=self.direct_block_serial,
            )
            return True
        if opcode in (ida_hexrays.m_jnz, ida_hexrays.m_jz) and Z3MopProver().are_unequal(
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
