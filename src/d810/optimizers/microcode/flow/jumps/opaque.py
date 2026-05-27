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


class JnzRuleModIdentity(JumpOptimizationRule):
    """Opaque predicate for x*(x+1)%2 == 0 (always true).

    This mathematical identity holds because either x or (x+1) is even,
    so their product is always divisible by 2. The modulo 2 always yields 0.
    Pattern currently matches the signed-mod variant (smod).
    The umod form can be added as a sibling rule if it appears in samples.
    """
    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
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
    RIGHT_PATTERN = AstConstant("0", 0)
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        # x*(x+1) % 2 == 0 is ALWAYS true (left operand always equals right operand 0).
        # Condition: left == right is TRUE
        # - m_jnz (jump if NOT equal): condition FALSE → jump NOT taken → fallthrough (direct_block_serial)
        # - m_jz (jump if equal): condition TRUE → jump taken → go to jump_original_block_serial
        if opcode == ida_hexrays.m_jnz:
            self.jump_replacement_block_serial = self.direct_block_serial
        else:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


def _parse_opaque_ea_whitelist() -> set[int]:
    """Read D810_Z3_OPAQUE_EAS env var (comma-separated hex EAs) into a set.

    When set and non-empty, JmpRuleZ3Const only runs Z3 against jumps whose
    instruction EA is in this set. Cuts Z3 cost from ~200 jcnd-per-function
    to the handful of known opaque predicates. Without this, Z3 fans out
    over every conditional jump and dies on bitvector solves.
    """
    import os as _os
    raw = _os.environ.get("D810_Z3_OPAQUE_EAS", "").strip()
    if not raw:
        return set()
    out: set[int] = set()
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.add(int(tok, 16) if tok.lower().startswith("0x") else int(tok, 16))
        except Exception:
            continue
    return out


_OPAQUE_EA_WHITELIST: set[int] = _parse_opaque_ea_whitelist()


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
        # PATCH 2026-05-26: per-EA whitelist (D810_Z3_OPAQUE_EAS).
        # When set, skip this rule for any jcnd whose EA isn't in the list.
        # Lets the user run Z3 only on known opaque predicates instead of
        # every conditional jump in the function.
        if _OPAQUE_EA_WHITELIST and instruction.ea not in _OPAQUE_EA_WHITELIST:
            return None
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


# ---------------------------------------------------------------------------
# Affine opaque predicate (fast, Z3-free).
#
# Pattern shape: both sides of jz/jnz/jcnd reduce to the SAME affine combination
# of opaque terms but DIFFERENT additive constants. The comparison is then a
# compile-time constant. Examples in the wild (iOS arm64 OLLVM/RASP output):
#   604LL * a2 == 604LL * a2 - 768                  -> 0 == -768  (false)
#   630LL * a4 + 630 == 630LL * a4 - 218            -> 630 == -218 (false)
#   -674LL * vars0 == -512 - 674LL * vars0          -> 0 == -512  (false)
#   -524LL * ~vars0 == 524LL * vars0 + 524          -> equal (true)
# The last one uses ~x = -x - 1 (two's complement), which we normalise.
# ---------------------------------------------------------------------------

_AFFINE_RECURSION_LIMIT = 24

# Hex-Rays' dstr() embeds SSA version tags like `x22.8{3992}` and
# `(... ){4002}` into the rendered text. The SAME semantic operand can carry
# different SSA tags on each side of a comparison (e.g. `c*x22` materialised
# from two distinct microcode definitions), which would make our term-map
# keys diverge. Strip every `{<digits>}` to canonicalise on the SSA-free shape.
import re as _re
_SSA_TAG_RE = _re.compile(r"\{\d+\}")


def _serialize_mop_key(mop) -> str:
    """Stable canonical key for an opaque mop sub-expression.

    Uses Hex-Rays' own pretty-printer when available with SSA tags stripped.
    """
    try:
        s = mop.dstr()
    except Exception:
        s = None
    if s:
        return _SSA_TAG_RE.sub("", s)
    return f"@{id(mop):x}"


def _affine_extract(mop, size: int, depth: int = 0):
    """Decompose mop into (term_map, const) over Z / 2^(size*8).

    term_map: {opaque_key: coefficient}, coefficient stored unsigned mod 2^N.
    Pure constants give ({}, value). Returns None if shape exceeds the
    recursion limit, but never None for ordinary leaves (those become an
    opaque term with coefficient 1).
    """
    if mop is None or depth > _AFFINE_RECURSION_LIMIT:
        return None
    mask = (1 << (size * 8)) - 1
    if mop.t == ida_hexrays.mop_n:
        try:
            return ({}, mop.nnn.value & mask)
        except Exception:
            return None
    if mop.t != ida_hexrays.mop_d or mop.d is None:
        return ({_serialize_mop_key(mop): 1}, 0)

    insn = mop.d
    op = insn.opcode

    def _combine(a, b, sign):
        out_map = dict(a[0])
        for k, v in b[0].items():
            nv = (out_map.get(k, 0) + sign * v) & mask
            if nv == 0:
                out_map.pop(k, None)
            else:
                out_map[k] = nv
        out_const = (a[1] + sign * b[1]) & mask
        return (out_map, out_const)

    def _scale(a, factor):
        factor &= mask
        if factor == 0:
            return ({}, 0)
        out_map = {}
        for k, v in a[0].items():
            nv = (v * factor) & mask
            if nv != 0:
                out_map[k] = nv
        return (out_map, (a[1] * factor) & mask)

    if op in (ida_hexrays.m_add,):
        l = _affine_extract(insn.l, size, depth + 1)
        r = _affine_extract(insn.r, size, depth + 1)
        if l is None or r is None:
            return None
        return _combine(l, r, 1)
    if op in (ida_hexrays.m_sub,):
        l = _affine_extract(insn.l, size, depth + 1)
        r = _affine_extract(insn.r, size, depth + 1)
        if l is None or r is None:
            return None
        return _combine(l, r, -1)
    if op in (ida_hexrays.m_neg,):
        l = _affine_extract(insn.l, size, depth + 1)
        if l is None:
            return None
        return _scale(l, -1)
    if op in (ida_hexrays.m_bnot,):
        # ~x = -x - 1
        l = _affine_extract(insn.l, size, depth + 1)
        if l is None:
            return None
        neg_l = _scale(l, -1)
        return (neg_l[0], (neg_l[1] - 1) & mask)
    if op in (ida_hexrays.m_mul,):
        l = _affine_extract(insn.l, size, depth + 1)
        r = _affine_extract(insn.r, size, depth + 1)
        if l is None or r is None:
            return None
        if not l[0]:
            return _scale(r, l[1])
        if not r[0]:
            return _scale(l, r[1])
        # Non-linear product: treat whole node as an opaque term.
        return ({_serialize_mop_key(mop): 1}, 0)
    # m_xdu / m_xds / m_low / m_high / arbitrary unary or other ops:
    # treat the whole expression as a single opaque term so we still match
    # `OP(x) + K1 == OP(x) + K2`.
    return ({_serialize_mop_key(mop): 1}, 0)


def _affine_decide_equality(opcode: int, lhs_mop, rhs_mop) -> bool | None:
    """For jz/jnz return jump-taken decision when both sides have the same
    affine term map but possibly different constants. Returns None when the
    rule does not apply (different terms or extraction failure).
    """
    size = max(getattr(lhs_mop, "size", 0), getattr(rhs_mop, "size", 0))
    if size <= 0:
        size = 8
    lhs = _affine_extract(lhs_mop, size)
    rhs = _affine_extract(rhs_mop, size)
    if lhs is None or rhs is None:
        return None
    if lhs[0] != rhs[0]:
        return None
    mask = (1 << (size * 8)) - 1
    is_equal = (lhs[1] & mask) == (rhs[1] & mask)
    if opcode == ida_hexrays.m_jz:
        return is_equal
    if opcode == ida_hexrays.m_jnz:
        return not is_equal
    return None


class JmpRuleAffineEq(JumpOptimizationRule):
    """Fold opaque jz/jnz where both sides reduce to identical affine form.

    Examples covered:
      ``c*x + K1 == c*x + K2``       -> equal iff K1 == K2 (mod 2^N)
      ``c*~x  ==  -c*x - c``         -> always equal (~x = -x - 1)
      ``-674*x == -512 - 674*x``     -> never equal (constants differ)

    Strictly faster than Z3 and runs without a whitelist. Catches the
    "affine fan-out" opaque predicates commonly emitted by OLLVM around
    RASP probe sites in iOS arm64 binaries.
    """

    ORIGINAL_JUMP_OPCODES = [ida_hexrays.m_jnz, ida_hexrays.m_jz]
    LEFT_PATTERN = AstLeaf("x_0")
    RIGHT_PATTERN = AstLeaf("x_1")
    REPLACEMENT_OPCODE = ida_hexrays.m_goto

    def check_candidate(self, opcode, left_candidate, right_candidate):
        taken = _affine_decide_equality(opcode, left_candidate.mop, right_candidate.mop)
        if taken is None:
            return False
        self.jump_replacement_block_serial = (
            self.jump_original_block_serial if taken else self.direct_block_serial
        )
        return True
