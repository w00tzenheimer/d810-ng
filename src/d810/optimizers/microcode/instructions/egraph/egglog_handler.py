"""Bounded, proof-gated Egglog MBA instruction rule.

This is intentionally *not* a second global instruction optimizer.  Egglog is
an opt-in peephole rule, so the normal project configuration and execution
scope decide when it may run.  Each candidate gets a fresh e-graph; no facts
or expressions leak between instructions or decompilations.
"""

from __future__ import annotations

import ida_hexrays

from d810.backends.mba.egglog_backend import (
    EGGLOG_AVAILABLE,
    AstToBitExprConverter,
    BitExpr,
    egglog,
)
from d810.core import getLogger
from d810.hexrays.expr.ast import AstNode
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)

_SUPPORTED_ROOT_OPCODES = frozenset(
    {
        ida_hexrays.m_add,
        ida_hexrays.m_sub,
        ida_hexrays.m_mul,
        ida_hexrays.m_and,
        ida_hexrays.m_or,
        ida_hexrays.m_xor,
    }
)
_BOOL_OPCODES = frozenset(
    {ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_xor, ida_hexrays.m_bnot}
)
_ARITH_OPCODES = frozenset(
    {ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_mul, ida_hexrays.m_neg}
)
_VALID_SIZES = frozenset({1, 2, 4, 8})


class EgglogOptimizer(PeepholeSimplificationRule):
    """Extract one strictly smaller, proof-gated MBA rewrite with Egglog.

    The initial rule set is deliberately one directional Hacker's Delight
    identity.  It is enough to prove that Egglog 13.2 extraction can drive a
    live D810 rewrite, without hiding cost in generic AC rules or saturation.
    """

    DESCRIPTION = "Bounded Egglog MBA extraction (proof-gated)"
    CATEGORY = "MBA Solving"

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_GLBOPT2]
        self.max_leaves = 2
        self.rounds = 3
        self.require_proof = True

    def configure(self, kwargs) -> None:
        config = dict(kwargs or {})
        maturity_names = config.pop("maturities", None)
        super().configure(config)
        if maturity_names is not None:
            try:
                self.maturities = [
                    ir_maturity_to_ida(IRMaturity[str(name)])
                    for name in maturity_names
                ]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("EgglogOptimizer maturities must be IRMaturity names") from exc
        self.max_leaves = int(self.config.get("max_leaves", 2))
        self.rounds = int(self.config.get("rounds", 3))
        self.require_proof = bool(self.config.get("require_proof", True))
        if self.max_leaves < 1 or self.max_leaves > 8:
            raise ValueError("EgglogOptimizer max_leaves must be between 1 and 8")
        if self.rounds < 1 or self.rounds > 6:
            raise ValueError("EgglogOptimizer rounds must be between 1 and 6")

    def check_and_replace(self, blk, ins):
        """Return a replacement only after extraction, shrink, and proof."""
        del blk
        if not EGGLOG_AVAILABLE or ins.opcode not in _SUPPORTED_ROOT_OPCODES:
            return None
        try:
            return self._check_and_replace(ins)
        except Exception:  # Never leak an exception through Hex-Rays' callback.
            logger.exception("egglog MBA extraction failed at %#x", getattr(ins, "ea", 0))
            return None

    def _check_and_replace(self, ins):
        ast = minsn_to_ast(ins)
        if ast is None or not self._is_candidate(ast, ins):
            return None

        converter = AstToBitExprConverter()
        original = converter.convert(ast)
        leaf_mapping = converter.get_leaf_mapping()
        if original is None or len(leaf_mapping) != 2:
            return None

        names = tuple(sorted(leaf_mapping))
        target = BitExpr.var(names[0]) ^ BitExpr.var(names[1])
        extracted = self._extract_xor(original, target)
        if extracted is None:
            return None

        replacement = AstNode(
            ida_hexrays.m_xor,
            leaf_mapping[names[0]].clone(),
            leaf_mapping[names[1]].clone(),
        )
        if self._node_count(replacement) >= self._node_count(ast):
            return None
        if self.require_proof and not self._prove_xor_identity(ins.d.size):
            return None
        return self._create_instruction(replacement, ins)

    def _is_candidate(self, ast, ins) -> bool:
        if ins.d is None or int(ins.d.size) not in _VALID_SIZES:
            return False
        leaves = ast.get_leaf_list()
        variable_leaves = [leaf for leaf in leaves if not leaf.is_constant()]
        unique_variable_leaves = {
            self._leaf_identity(leaf): leaf for leaf in variable_leaves
        }
        if not unique_variable_leaves or len(unique_variable_leaves) > self.max_leaves:
            return False
        if any(
            int(getattr(leaf.mop, "size", 0)) != int(ins.d.size)
            for leaf in unique_variable_leaves.values()
        ):
            return False
        opcodes = self._opcodes(ast)
        return bool(opcodes & _BOOL_OPCODES) and bool(opcodes & _ARITH_OPCODES)

    @staticmethod
    def _opcodes(node) -> set[int]:
        if node is None or node.is_leaf():
            return set()
        return (
            {int(node.opcode)}
            | EgglogOptimizer._opcodes(node.left)
            | EgglogOptimizer._opcodes(node.right)
        )

    @staticmethod
    def _leaf_identity(leaf) -> int:
        ast_index = getattr(leaf, "ast_index", None)
        return id(leaf) if ast_index is None else int(ast_index)

    def _extract_xor(self, original: BitExpr, target: BitExpr) -> BitExpr | None:
        """Run the single bounded directional rule and require extraction to it."""
        egraph = egglog.EGraph()
        x, y = egglog.vars_("x y", BitExpr)
        egraph.register(
            egglog.rewrite((x + y) - BitExpr(2) * (x & y)).to(x ^ y),
        )
        egraph.register(original)
        egraph.run(self.rounds)
        extracted = egraph.extract(original)
        try:
            egraph.check(egglog.eq(extracted).to(target))
        except Exception:
            return None
        if str(extracted) != str(target):
            return None
        return extracted

    @staticmethod
    def _node_count(node) -> int:
        if node is None:
            return 0
        if node.is_leaf():
            return 1
        return 1 + EgglogOptimizer._node_count(node.left) + EgglogOptimizer._node_count(node.right)

    @staticmethod
    def _prove_xor_identity(dest_size: int) -> bool:
        """Prove the exact rule at the native destination bit width."""
        try:
            import z3

            width = int(dest_size) * 8
            x, y = z3.BitVecs("egglog_x egglog_y", width)
            solver = z3.Solver()
            solver.set(timeout=50)
            solver.add((x + y) - z3.BitVecVal(2, width) * (x & y) != (x ^ y))
            return solver.check() == z3.unsat
        except Exception:
            return False

    @staticmethod
    def _create_instruction(replacement: AstNode, original_ins):
        new_mop = replacement.create_mop(original_ins.ea)
        if new_mop is None:
            return None
        new_ins = ida_hexrays.minsn_t(original_ins.ea)
        new_ins.opcode = ida_hexrays.m_mov
        new_ins.l = new_mop
        new_ins.d = original_ins.d
        return new_ins
