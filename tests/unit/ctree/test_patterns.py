"""Unit tests for d810.ctree pattern DSL with mocks (no IDA needed).

Tests BasePat, AnyPat, OrPat, AndPat, DeepExprPat, AbstractBinaryOpPat,
NumPat, CallPat, IfPat, BlockPat, InstructionPat, and the base_check decorator.
"""
from __future__ import annotations

import pytest

from d810.ctree.match_context import MatchContext
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.patterns.abstracts import AnyPat, OrPat, AndPat, DeepExprPat
from d810.ctree.patterns.expressions import (
    ExpressionPat,
    NumPat,
    CallPat,
    AbstractBinaryOpPat,
    AbstractUnaryOpPat,
)
from d810.ctree.patterns.instructions import InstructionPat, BlockPat, IfPat


# ---------------------------------------------------------------------------
# Register mock ops for iteration (needed for DeepExprPat tests)
# ---------------------------------------------------------------------------
_MOCK_LEAF_OP = 9990
_MOCK_UNARY_OP = 9991
_MOCK_BINARY_OP = 9992
_MOCK_BLOCK_OP = 9993

def _register_mock_ops():
    from d810.ctree import ast_iteration
    if _MOCK_UNARY_OP not in ast_iteration.op2func:
        ast_iteration.op2func[_MOCK_UNARY_OP] = lambda x: tuple(x._children)
    if _MOCK_BINARY_OP not in ast_iteration.op2func:
        ast_iteration.op2func[_MOCK_BINARY_OP] = lambda x: tuple(x._children)
    if _MOCK_BLOCK_OP not in ast_iteration.op2func:
        ast_iteration.op2func[_MOCK_BLOCK_OP] = lambda x: tuple(x._children)

_register_mock_ops()


class MockItem:
    """Minimal mock for a ctree item."""

    def __init__(self, op: int = 0, ea: int = 0x1000, label_num: int = -1):
        self.op = op
        self.ea = ea
        self.label_num = label_num
        self.opname = f"mock_op_{op}"
        self._children: list = []

    def equal_effect(self, other: "MockItem") -> bool:
        return self.op == other.op


class MockPat:
    """Minimal stand-in for pattern field in MatchContext."""
    pass


def make_ctx() -> MatchContext:
    return MatchContext(ast_ctx=None, pattern=MockPat())


# -------------------------------------------------------------------------
# BasePat tests
# -------------------------------------------------------------------------
class TestBasePat:
    def test_abstract_check_raises(self):
        pat = BasePat()
        with pytest.raises(NotImplementedError):
            pat.check(MockItem(), make_ctx())

    def test_abstract_children_raises(self):
        pat = BasePat()
        with pytest.raises(NotImplementedError):
            _ = pat.children

    def test_get_opname_returns_none_for_base(self):
        # BasePat.op is None, so get_opname should return None
        assert BasePat.get_opname() is None


class SimplePat(BasePat):
    """Concrete pattern for testing base_check decorator."""

    def __init__(self, should_match: bool = True, **kwargs):
        super().__init__(**kwargs)
        self._should_match = should_match

    @BasePat.base_check
    def check(self, item, ctx):
        return self._should_match

    @property
    def children(self):
        return ()


class TestBaseCheck:
    def test_returns_false_for_none_item(self):
        pat = SimplePat()
        assert pat.check(None, make_ctx()) is False

    def test_check_op_mismatch(self):
        pat = SimplePat(check_op=99)
        item = MockItem(op=1)
        assert pat.check(item, make_ctx()) is False

    def test_check_op_match(self):
        pat = SimplePat(check_op=42)
        item = MockItem(op=42)
        assert pat.check(item, make_ctx()) is True

    def test_bind_name_stores_item(self):
        pat = SimplePat(bind_name="myvar")
        item = MockItem(op=5)
        ctx = make_ctx()
        assert pat.check(item, ctx) is True
        assert ctx.get_item("myvar") is item

    def test_bind_name_conflict_returns_false(self):
        """If bind_name already has a different item, check returns False."""
        pat = SimplePat(bind_name="x")
        ctx = make_ctx()
        item1 = MockItem(op=1)
        item2 = MockItem(op=99)  # different op -> not equal_effect
        pat.check(item1, ctx)  # binds "x" to item1
        assert pat.check(item2, ctx) is False

    def test_should_not_match(self):
        pat = SimplePat(should_match=False)
        item = MockItem(op=0)
        assert pat.check(item, make_ctx()) is False


# -------------------------------------------------------------------------
# AnyPat tests
# -------------------------------------------------------------------------
class TestAnyPat:
    def test_matches_any_item(self):
        pat = AnyPat()
        assert pat.check(MockItem(), make_ctx()) is True

    def test_matches_none_when_may_be_none(self):
        pat = AnyPat(may_be_none=True)
        assert pat.check(None, make_ctx()) is True

    def test_rejects_none_when_not_may_be_none(self):
        pat = AnyPat(may_be_none=False)
        assert pat.check(None, make_ctx()) is False

    def test_bind_name_works(self):
        pat = AnyPat(bind_name="captured")
        item = MockItem(op=7)
        ctx = make_ctx()
        assert pat.check(item, ctx) is True
        assert ctx.get_item("captured") is item

    def test_children_is_empty(self):
        assert AnyPat().children == ()


# -------------------------------------------------------------------------
# OrPat tests
# -------------------------------------------------------------------------
class TestOrPat:
    def test_matches_if_any_subpattern_matches(self):
        p1 = SimplePat(should_match=False)
        p2 = SimplePat(should_match=True)
        pat = OrPat(p1, p2)
        assert pat.check(MockItem(), make_ctx()) is True

    def test_fails_if_none_match(self):
        p1 = SimplePat(should_match=False)
        p2 = SimplePat(should_match=False)
        pat = OrPat(p1, p2)
        assert pat.check(MockItem(), make_ctx()) is False

    def test_children_returns_subpatterns(self):
        p1 = SimplePat()
        p2 = SimplePat()
        pat = OrPat(p1, p2)
        assert pat.children == (p1, p2)


# -------------------------------------------------------------------------
# AndPat tests
# -------------------------------------------------------------------------
class TestAndPat:
    def test_matches_if_all_match(self):
        p1 = SimplePat(should_match=True)
        p2 = SimplePat(should_match=True)
        pat = AndPat(p1, p2)
        assert pat.check(MockItem(), make_ctx()) is True

    def test_fails_if_any_fails(self):
        p1 = SimplePat(should_match=True)
        p2 = SimplePat(should_match=False)
        pat = AndPat(p1, p2)
        assert pat.check(MockItem(), make_ctx()) is False

    def test_children_returns_subpatterns(self):
        p1 = SimplePat()
        p2 = SimplePat()
        pat = AndPat(p1, p2)
        assert pat.children == (p1, p2)


# -------------------------------------------------------------------------
# CtreeOptimizerManager tests (without IDA)
# -------------------------------------------------------------------------
class TestCtreeOptimizerManager:
    def test_manager_creation(self):
        from d810.core.stats import OptimizationStatistics
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        assert mgr.ctree_rules == []
        assert mgr.stats is stats

    def test_on_maturity_skips_non_final(self):
        from d810.core.stats import OptimizationStatistics
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        # When ida_hexrays is None, CMAT_FINAL comparison is skipped
        # and all rules are evaluated. With no rules, result is 0.
        assert mgr.on_maturity(None, 3) == 0


# -------------------------------------------------------------------------
# CtreeOptimizationRule registration tests
# -------------------------------------------------------------------------
class TestCtreeOptimizationRuleRegistration:
    def test_noop_counter_is_registered(self):
        """NoopCtreeCounter should auto-register when imported."""
        from d810.hexrays.ctree_hooks import CtreeOptimizationRule
        # Force import to trigger registration
        from d810.optimizers.ctree.noop_counter import NoopCtreeCounter  # noqa: F401

        # Registry uses normalize_key(keyof(cls)) which is cls.__name__.lower()
        key = CtreeOptimizationRule.normalize_key(
            CtreeOptimizationRule.keyof(NoopCtreeCounter)
        )
        assert key in CtreeOptimizationRule.registry
        assert CtreeOptimizationRule.registry[key] is NoopCtreeCounter

    def test_noop_counter_returns_zero(self):
        from d810.optimizers.ctree.noop_counter import NoopCtreeCounter

        rule = NoopCtreeCounter()
        assert rule.name == "noop_ctree_counter"
        # With None cfunc, should still return 0
        assert rule.optimize_ctree(None) == 0


# -------------------------------------------------------------------------
# DeepExprPat tests (Issue D6)
# -------------------------------------------------------------------------

class MockTreeNode:
    """Mock AST node with children for DeepExprPat iteration."""

    def __init__(self, name: str, op: int, children: list | None = None):
        self.name = name
        self.op = op
        self.ea = 0x1000
        self.opname = name
        self._children = children or []

    def equal_effect(self, other):
        return self.op == other.op


class TestDeepExprPat:
    def test_finds_match_in_nested_tree(self):
        """DeepExprPat should find a matching node deep in the tree."""
        # Build: root(child(target_leaf))
        target = MockTreeNode("target", _MOCK_LEAF_OP)
        child = MockTreeNode("child", _MOCK_UNARY_OP, [target])
        root = MockTreeNode("root", _MOCK_UNARY_OP, [child])

        # Pattern that matches only the target node
        class TargetPat(BasePat):
            @BasePat.base_check
            def check(self, item, ctx):
                return getattr(item, "name", None) == "target"

            @property
            def children(self):
                return ()

        pat = DeepExprPat(TargetPat())
        ctx = make_ctx()
        assert pat.check(root, ctx) is True

    def test_binds_the_matching_subitem(self):
        """DeepExprPat with bind_name on inner pat should bind the subitem."""
        target = MockTreeNode("target", _MOCK_LEAF_OP)
        child = MockTreeNode("child", _MOCK_UNARY_OP, [target])
        root = MockTreeNode("root", _MOCK_UNARY_OP, [child])

        class TargetPat(BasePat):
            @BasePat.base_check
            def check(self, item, ctx):
                return getattr(item, "name", None) == "target"

            @property
            def children(self):
                return ()

        inner_pat = TargetPat(bind_name="found")
        pat = DeepExprPat(inner_pat)
        ctx = make_ctx()
        assert pat.check(root, ctx) is True
        bound = ctx.get_item("found")
        assert bound is not None
        assert bound.name == "target"

    def test_returns_false_when_no_match(self):
        """DeepExprPat returns False when no subitem matches."""
        leaf = MockTreeNode("leaf", _MOCK_LEAF_OP)
        root = MockTreeNode("root", _MOCK_UNARY_OP, [leaf])

        class NeverPat(BasePat):
            @BasePat.base_check
            def check(self, item, ctx):
                return False

            @property
            def children(self):
                return ()

        pat = DeepExprPat(NeverPat())
        assert pat.check(root, make_ctx()) is False

    def test_matches_root_itself(self):
        """DeepExprPat should match the root node if it satisfies the inner pat."""
        root = MockTreeNode("root", _MOCK_LEAF_OP)

        class AlwaysPat(BasePat):
            @BasePat.base_check
            def check(self, item, ctx):
                return True

            @property
            def children(self):
                return ()

        pat = DeepExprPat(AlwaysPat())
        assert pat.check(root, make_ctx()) is True


# -------------------------------------------------------------------------
# AbstractBinaryOpPat.symmetric tests (Issue D7)
# -------------------------------------------------------------------------

class MockBinaryExpr:
    """Mock binary expression with x and y operands."""

    def __init__(self, x_op: int, y_op: int, op: int = 100):
        self.op = op
        self.ea = 0x1000
        self.opname = "mock_binop"
        self.x = MockItem(op=x_op)
        self.y = MockItem(op=y_op)

    def equal_effect(self, other):
        return self.op == other.op


class ConcreteBinaryPat(AbstractBinaryOpPat):
    """Concrete binary op pattern for testing with a specific op."""

    op = 100  # matches MockBinaryExpr default op


class TestAbstractBinaryOpPatSymmetric:
    def test_symmetric_true_matches_either_order(self):
        """With symmetric=True, (A, B) should match expr(A, B) or expr(B, A)."""
        pat_a = SimplePat(check_op=10)
        pat_b = SimplePat(check_op=20)
        pat = ConcreteBinaryPat(pat_a, pat_b, symmetric=True)

        # Normal order: x=10, y=20
        expr_normal = MockBinaryExpr(x_op=10, y_op=20)
        assert pat.check(expr_normal, make_ctx()) is True

        # Swapped order: x=20, y=10
        expr_swapped = MockBinaryExpr(x_op=20, y_op=10)
        assert pat.check(expr_swapped, make_ctx()) is True

    def test_symmetric_false_only_matches_given_order(self):
        """With symmetric=False, only the given order should match."""
        pat_a = SimplePat(check_op=10)
        pat_b = SimplePat(check_op=20)
        pat = ConcreteBinaryPat(pat_a, pat_b, symmetric=False)

        # Normal order: x=10, y=20
        expr_normal = MockBinaryExpr(x_op=10, y_op=20)
        assert pat.check(expr_normal, make_ctx()) is True

        # Swapped order: x=20, y=10
        expr_swapped = MockBinaryExpr(x_op=20, y_op=10)
        assert pat.check(expr_swapped, make_ctx()) is False

    def test_symmetric_false_is_default(self):
        """symmetric should default to False."""
        pat_a = SimplePat(check_op=10)
        pat_b = SimplePat(check_op=20)
        pat = ConcreteBinaryPat(pat_a, pat_b)
        assert pat.symmetric is False

    def test_children_returns_operands(self):
        pat_a = SimplePat()
        pat_b = SimplePat()
        pat = ConcreteBinaryPat(pat_a, pat_b)
        assert pat.children == (pat_a, pat_b)


# -------------------------------------------------------------------------
# NumPat tests (Expression pattern coverage)
# -------------------------------------------------------------------------

class MockNumExpr:
    """Mock numeric expression for NumPat testing."""

    class _NumVal:
        def __init__(self, val):
            self._value = val

    def __init__(self, value: int, op: int | None = None):
        # Without IDA, NumPat.op is None, so check_op won't filter by op
        self.op = op
        self.ea = 0x1000
        self.opname = "cot_num"
        self.n = self._NumVal(value)

    def equal_effect(self, other):
        return self.op == other.op


class TestNumPat:
    def test_numpat_matches_any_number_when_no_value(self):
        """NumPat() with no num arg should match any numeric expr."""
        pat = NumPat()
        # NumPat.op is None (no IDA), so check_op is None -- no op filter
        expr = MockNumExpr(42)
        assert pat.check(expr, make_ctx()) is True

    def test_numpat_matches_specific_value(self):
        """NumPat(42) should match expr with value 42."""
        pat = NumPat(42)
        expr = MockNumExpr(42)
        assert pat.check(expr, make_ctx()) is True

    def test_numpat_rejects_wrong_value(self):
        """NumPat(42) should reject expr with value 99."""
        pat = NumPat(42)
        expr = MockNumExpr(99)
        assert pat.check(expr, make_ctx()) is False


# -------------------------------------------------------------------------
# CallPat tests (Expression pattern coverage)
# -------------------------------------------------------------------------

class MockCallExpr:
    """Mock call expression for CallPat testing."""

    def __init__(self, x_op: int, args: list | None = None, op: int | None = None):
        self.op = op
        self.ea = 0x1000
        self.opname = "cot_call"
        self.x = MockItem(op=x_op)
        self.a = args or []

    def equal_effect(self, other):
        return self.op == other.op


class TestCallPat:
    def test_callpat_matches_with_no_args(self):
        """CallPat with None calling_function and ignore_arguments should match."""
        pat = CallPat(None, ignore_arguments=True)
        expr = MockCallExpr(x_op=1)
        assert pat.check(expr, make_ctx()) is True

    def test_callpat_checks_argument_count(self):
        """CallPat checks argument count when not ignoring."""
        arg_pat = SimplePat(should_match=True)
        pat = CallPat(None, arg_pat)
        # 1 arg pattern but 0 args in expr
        expr = MockCallExpr(x_op=1, args=[])
        assert pat.check(expr, make_ctx()) is False

    def test_callpat_matches_arguments(self):
        """CallPat matches when arguments match."""
        arg1_pat = SimplePat(should_match=True)
        pat = CallPat(None, arg1_pat, ignore_arguments=False)
        expr = MockCallExpr(x_op=1, args=[MockItem(op=5)])
        assert pat.check(expr, make_ctx()) is True

    def test_callpat_children(self):
        arg1 = SimplePat()
        pat = CallPat(None, arg1)
        assert pat.calling_function is None
        assert len(pat.arguments) == 1


# -------------------------------------------------------------------------
# InstructionPat label checking tests
# -------------------------------------------------------------------------

class TestInstructionPatLabel:
    def test_skip_label_check(self):
        """SKIP_LABEL_CHECK (-3) should match any label_num."""

        class ConcreteInstrPat(InstructionPat):
            @InstructionPat.instr_check
            def check(self, item, ctx):
                return True

            @property
            def children(self):
                return ()

        pat = ConcreteInstrPat(label_num=InstructionPat.SKIP_LABEL_CHECK)
        item_labeled = MockItem(op=0, label_num=5)
        item_unlabeled = MockItem(op=0, label_num=-1)
        assert pat.check(item_labeled, make_ctx()) is True
        assert pat.check(item_unlabeled, make_ctx()) is True

    def test_has_some_label(self):
        """HAS_SOME_LABEL (-2) should match only items with a label."""

        class ConcreteInstrPat(InstructionPat):
            @InstructionPat.instr_check
            def check(self, item, ctx):
                return True

            @property
            def children(self):
                return ()

        pat = ConcreteInstrPat(label_num=InstructionPat.HAS_SOME_LABEL)
        item_labeled = MockItem(op=0, label_num=5)
        item_unlabeled = MockItem(op=0, label_num=-1)
        assert pat.check(item_labeled, make_ctx()) is True
        assert pat.check(item_unlabeled, make_ctx()) is False

    def test_has_no_label(self):
        """HAS_NO_LABEL (-1) should match only items without a label."""

        class ConcreteInstrPat(InstructionPat):
            @InstructionPat.instr_check
            def check(self, item, ctx):
                return True

            @property
            def children(self):
                return ()

        pat = ConcreteInstrPat(label_num=InstructionPat.HAS_NO_LABEL)
        item_labeled = MockItem(op=0, label_num=5)
        item_unlabeled = MockItem(op=0, label_num=-1)
        assert pat.check(item_labeled, make_ctx()) is False
        assert pat.check(item_unlabeled, make_ctx()) is True

    def test_specific_label_num(self):
        """Specific label_num should match only that label."""

        class ConcreteInstrPat(InstructionPat):
            @InstructionPat.instr_check
            def check(self, item, ctx):
                return True

            @property
            def children(self):
                return ()

        pat = ConcreteInstrPat(label_num=5)
        item_match = MockItem(op=0, label_num=5)
        item_no_match = MockItem(op=0, label_num=3)
        assert pat.check(item_match, make_ctx()) is True
        assert pat.check(item_no_match, make_ctx()) is False


# -------------------------------------------------------------------------
# IfPat tests (Instruction pattern coverage)
# -------------------------------------------------------------------------

class MockIfItem:
    """Mock for an if instruction item."""

    class _CIf:
        def __init__(self, expr, ithen, ielse=None):
            self.expr = expr
            self.ithen = ithen
            self.ielse = ielse

    def __init__(self, expr, ithen, ielse=None, op=None, label_num=-1):
        self.op = op
        self.ea = 0x1000
        self.opname = "cit_if"
        self.label_num = label_num
        self.cif = self._CIf(expr, ithen, ielse)

    def equal_effect(self, other):
        return self.op == other.op


class TestIfPat:
    def test_ifpat_matches_condition(self):
        """IfPat with condition pattern should check the condition."""
        cond = MockItem(op=42)
        then_branch = MockItem(op=1)
        # IfPat.op is None (no IDA), so no check_op filter
        pat = IfPat(
            condition=SimplePat(check_op=42),
            then_branch=AnyPat(),
            else_branch=AnyPat(),
        )
        item = MockIfItem(cond, then_branch)
        assert pat.check(item, make_ctx()) is True

    def test_ifpat_no_else_rejects_with_else(self):
        """IfPat with no_else=True should reject items with else branch."""
        cond = MockItem(op=42)
        then_branch = MockItem(op=1)
        else_branch = MockItem(op=2)
        pat = IfPat(
            condition=AnyPat(),
            no_else=True,
        )
        item = MockIfItem(cond, then_branch, ielse=else_branch)
        assert pat.check(item, make_ctx()) is False

    def test_ifpat_no_else_accepts_without_else(self):
        """IfPat with no_else=True should accept items without else branch."""
        cond = MockItem(op=42)
        then_branch = MockItem(op=1)
        pat = IfPat(
            condition=AnyPat(),
            no_else=True,
        )
        item = MockIfItem(cond, then_branch, ielse=None)
        assert pat.check(item, make_ctx()) is True

    def test_ifpat_children(self):
        pat = IfPat()
        assert len(pat.children) == 3


# -------------------------------------------------------------------------
# BlockPat tests (Instruction pattern coverage)
# -------------------------------------------------------------------------

class MockBlockItem:
    """Mock for a block instruction item."""

    def __init__(self, block_items: list, op=None, label_num=-1):
        self.op = op
        self.ea = 0x1000
        self.opname = "cit_block"
        self.label_num = label_num
        self.cblock = block_items

    def equal_effect(self, other):
        return self.op == other.op


class TestBlockPat:
    def test_blockpat_matches_sequence(self):
        """BlockPat should match when all sub-patterns match in order."""
        pat = BlockPat(
            SimplePat(check_op=1),
            SimplePat(check_op=2),
        )
        block = MockBlockItem([MockItem(op=1), MockItem(op=2)])
        assert pat.check(block, make_ctx()) is True

    def test_blockpat_rejects_wrong_length(self):
        """BlockPat should reject if block length differs from pattern count."""
        pat = BlockPat(SimplePat(check_op=1))
        block = MockBlockItem([MockItem(op=1), MockItem(op=2)])
        assert pat.check(block, make_ctx()) is False

    def test_blockpat_rejects_mismatch(self):
        """BlockPat should reject when a sub-pattern doesn't match."""
        pat = BlockPat(
            SimplePat(check_op=1),
            SimplePat(check_op=99),
        )
        block = MockBlockItem([MockItem(op=1), MockItem(op=2)])
        assert pat.check(block, make_ctx()) is False


# -------------------------------------------------------------------------
# CtreeOptimizerManager rule execution tests (MEDIUM issue)
# -------------------------------------------------------------------------

class TestCtreeOptimizerManagerRuleExecution:
    def test_rules_fire_and_stats_recorded(self):
        """Rules should fire and statistics should be recorded."""
        from d810.core.stats import OptimizationStatistics
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager, CtreeOptimizationRule

        class FakeRule(CtreeOptimizationRule):
            NAME = "fake_rule"
            def optimize_ctree(self, cfunc):
                return 3  # 3 patches

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        rule = FakeRule()
        mgr.add_rule(rule)

        # Without IDA, on_maturity skips CMAT_FINAL check, evaluates all rules
        total = mgr.on_maturity(None, 8)
        assert total == 3
        # Stats should have recorded the patches
        assert stats.get_cfg_rule_patch_counts("fake_rule") == [3]

    def test_exception_handling_in_rules(self):
        """Exceptions in rules should be caught and not propagate."""
        from d810.core.stats import OptimizationStatistics
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager, CtreeOptimizationRule

        class FailingRule(CtreeOptimizationRule):
            NAME = "failing_rule"
            def optimize_ctree(self, cfunc):
                raise RuntimeError("boom")

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(FailingRule())

        # Should not raise
        total = mgr.on_maturity(None, 8)
        assert total == 0

    def test_multiple_rules_accumulate(self):
        """Multiple rules should accumulate their patch counts."""
        from d810.core.stats import OptimizationStatistics
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager, CtreeOptimizationRule

        class Rule1(CtreeOptimizationRule):
            NAME = "rule_one"
            def optimize_ctree(self, cfunc):
                return 2

        class Rule2(CtreeOptimizationRule):
            NAME = "rule_two"
            def optimize_ctree(self, cfunc):
                return 5

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(Rule1())
        mgr.add_rule(Rule2())

        total = mgr.on_maturity(None, 8)
        assert total == 7
