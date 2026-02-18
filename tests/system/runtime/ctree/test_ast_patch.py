"""Unit tests for d810.ctree.ast_patch (no IDA needed).

Tests ASTPatch class, remove_instr, replace_instr, replace_expr
using lightweight mocks that simulate ctree structures.
"""
from __future__ import annotations

import pytest

from d810.ctree.ast_patch import ASTPatch, remove_instr, replace_instr, replace_expr


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockItem:
    """Mock for a ctree item (cinsn_t / cexpr_t)."""

    def __init__(self, op: int = 0, ea: int = 0x1000, label_num: int = -1,
                 opname: str = "mock_instr", is_expr_val: bool = False):
        self.op = op
        self.ea = ea
        self.label_num = label_num
        self.opname = opname
        self._is_expr = is_expr_val
        self._children: list["MockItem"] = []

    def is_expr(self) -> bool:
        return self._is_expr

    def equal_effect(self, other: "MockItem") -> bool:
        return self.op == other.op


class MockBlock:
    """Mock for a parent block returned by ctx.get_parent_block()."""

    def __init__(self, cinsn: "MockItem | None" = None):
        self.cinsn = cinsn


class MockCfunc:
    """Mock for cfunc_t with remove_unused_labels."""

    def __init__(self):
        self.removed_labels = False

    def remove_unused_labels(self):
        self.removed_labels = True


class MockASTContext:
    """Mock for ASTContext used in remove_instr/replace_instr."""

    def __init__(
        self,
        parent_block: MockBlock | None = None,
        label2gotos: dict | None = None,
    ):
        self._parent_block = parent_block
        self.label2gotos: dict = label2gotos or {}
        self.cfunc = MockCfunc()
        self.is_modified: bool = False

    def get_parent_block(self, item):
        return self._parent_block


# ---------------------------------------------------------------------------
# ASTPatch class tests
# ---------------------------------------------------------------------------

class TestASTPatch:
    def test_scheme_modified_patch_type(self):
        patch = ASTPatch.scheme_modified()
        assert patch.ptype == ASTPatch.PatchType.SCHEME_MODIFIED
        assert patch.item is None
        assert patch.new_item is None

    def test_remove_instr_patch_creation(self):
        item = MockItem(is_expr_val=False)
        patch = ASTPatch.remove_instr(item)
        assert patch.ptype == ASTPatch.PatchType.REMOVE_INSTR
        assert patch.item is item
        assert patch.new_item is None

    def test_remove_instr_asserts_on_expr(self):
        item = MockItem(is_expr_val=True)
        with pytest.raises(AssertionError):
            ASTPatch.remove_instr(item)

    def test_replace_instr_patch_creation(self):
        item = MockItem(is_expr_val=False)
        new_item = MockItem(is_expr_val=False, op=99)
        patch = ASTPatch.replace_instr(item, new_item)
        assert patch.ptype == ASTPatch.PatchType.REPLACE_INSTR
        assert patch.item is item
        assert patch.new_item is new_item

    def test_replace_instr_asserts_on_expr(self):
        item = MockItem(is_expr_val=True)
        new_item = MockItem(is_expr_val=False)
        with pytest.raises(AssertionError):
            ASTPatch.replace_instr(item, new_item)

    def test_replace_expr_patch_creation(self):
        item = MockItem(is_expr_val=True)
        new_item = MockItem(is_expr_val=True, op=99)
        patch = ASTPatch.replace_expr(item, new_item)
        assert patch.ptype == ASTPatch.PatchType.REPLACE_EXPR
        assert patch.item is item
        assert patch.new_item is new_item

    def test_replace_expr_asserts_on_instr(self):
        item = MockItem(is_expr_val=False)
        new_item = MockItem(is_expr_val=True)
        with pytest.raises(AssertionError):
            ASTPatch.replace_expr(item, new_item)

    def test_do_patch_scheme_modified_returns_false(self):
        patch = ASTPatch.scheme_modified()
        ctx = MockASTContext()
        assert patch.do_patch(ctx) is False

    def test_do_patch_invalid_type_raises(self):
        patch = ASTPatch(patch_type=999)
        ctx = MockASTContext()
        with pytest.raises(TypeError, match="not implemented"):
            patch.do_patch(ctx)


# ---------------------------------------------------------------------------
# remove_instr tests (without IDA -- limited, tests label/parent logic)
# ---------------------------------------------------------------------------

class TestRemoveInstr:
    def test_remove_instr_no_parent_returns_false(self):
        """When no parent block is found, remove_instr should return False."""
        item = MockItem(opname="test_instr")
        ctx = MockASTContext(parent_block=None)
        result = remove_instr(item, ctx)
        assert result is False

    def test_remove_instr_sets_modified(self):
        """Even though idaapi is None (so remove_instruction_from_ast returns
        False), ctx.is_modified is set to True when the function reaches
        the end without returning early."""
        parent_cinsn = MockItem()
        block = MockBlock(cinsn=parent_cinsn)
        item = MockItem(label_num=-1, opname="nop")
        ctx = MockASTContext(parent_block=block)
        # Without IDA, remove_instruction_from_ast returns False.
        # The function still sets ctx.is_modified = True at the end.
        result = remove_instr(item, ctx)
        # Without IDA, collect_gotos and collect_labels return empty,
        # remove_instruction_from_ast returns False, rv stays False.
        # But ctx.is_modified is set unconditionally before return.
        assert ctx.is_modified is True


# ---------------------------------------------------------------------------
# replace_instr tests (without IDA)
# ---------------------------------------------------------------------------

class TestReplaceInstr:
    def test_replace_preserves_label(self):
        """When replacing an item with a label, the label should transfer
        to the new item."""
        item = MockItem(label_num=5, opname="old_instr")
        new_item = MockItem(label_num=-1, opname="new_instr")
        ctx = MockASTContext()
        # replace_instr calls _replace_instr at the end, which returns False
        # without IDA. But the label transfer logic runs before that.
        replace_instr(item, new_item, ctx)
        # Check that label was transferred
        assert new_item.label_num == 5

    def test_replace_conflicting_label_returns_false(self):
        """If new_item already has a different label, replace should fail."""
        item = MockItem(label_num=5, opname="old_instr")
        new_item = MockItem(label_num=10, opname="new_instr")
        ctx = MockASTContext()
        result = replace_instr(item, new_item, ctx)
        assert result is False


# ---------------------------------------------------------------------------
# replace_expr tests (without IDA)
# ---------------------------------------------------------------------------

class TestReplaceExpr:
    def test_replace_expr_returns_false_without_ida(self):
        """Without IDA, replace_expr returns False immediately."""
        expr = MockItem(is_expr_val=True)
        new_expr = MockItem(is_expr_val=True, op=99)
        ctx = MockASTContext()
        result = replace_expr(expr, new_expr, ctx)
        assert result is False
