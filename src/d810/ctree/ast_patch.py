"""Safe ctree modification primitives.

Provides ``remove_instr()``, ``replace_instr()``, ``replace_expr()``,
and the ``ASTPatch`` class which encapsulates deferred patching.

Ported from herast (herast/tree/ast_patch.py).
"""
from __future__ import annotations

from d810.core import typing
from enum import Enum
from collections import defaultdict

from d810.core import getLogger
from d810.ctree.ast_iteration import collect_gotos, collect_labels
from d810.ctree.ast_context import ASTContext

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


def _replace_instr(item: typing.Any, new_item: typing.Any) -> bool:
    """Low-level instruction swap."""
    if idaapi is None:
        return False
    new_item = idaapi.cinsn_t(new_item)
    try:
        idaapi.qswap(item, new_item)
        return True
    except Exception as e:
        logger.error("Got an exception during ctree instr replacing: %s", e)
        return False


def remove_instr(item: typing.Any, ctx: ASTContext) -> bool:
    """Remove an instruction from the ctree, handling labels safely."""
    parent = ctx.get_parent_block(item)
    if parent is None:
        logger.warning(
            "Failed to remove item from tree, because no parent is found: %s",
            item.opname,
        )
        return False

    removed_gotos = collect_gotos(item)
    count: dict[int, int] = defaultdict(int)
    for g in removed_gotos:
        count[g.label_num] += 1

    unused_labels: list[int] = []
    for lnum, c in count.items():
        if len(ctx.label2gotos.get(lnum, [])) == c:
            unused_labels.append(lnum)

    removed_labels = collect_labels(item)
    for u in unused_labels:
        try:
            removed_labels.remove(u)
        except ValueError:
            pass

    rv = False
    if len(removed_labels) > 0:
        from d810.ctree.utils import move_label_to_next_insn

        if (
            len(removed_labels) == 1
            and item.label_num != -1
            and move_label_to_next_insn(parent.cinsn, item, ctx)
        ):
            rv = True
            ctx.is_modified = True
        else:
            logger.error("failed to remove item %s with labels in it", item.opname)
            return False

    from d810.ctree.utils import remove_instruction_from_ast

    if remove_instruction_from_ast(item, parent.cinsn):
        rv = True

    if not rv:
        logger.warning(
            "failed to remove item %s from tree at %s", item.opname, hex(item.ea)
        )

    if len(unused_labels) != 0 and rv:
        ctx.cfunc.remove_unused_labels()

    ctx.is_modified = True
    return rv


def replace_instr(item: typing.Any, new_item: typing.Any, ctx: ASTContext) -> bool:
    """Replace an instruction in the ctree, handling labels safely."""
    removed_gotos = collect_gotos(item)
    count: dict[int, int] = defaultdict(int)
    for g in removed_gotos:
        count[g.label_num] += 1

    unused_labels: list[int] = []
    for lnum, c in count.items():
        if len(ctx.label2gotos.get(lnum, [])) == c:
            unused_labels.append(lnum)

    removed_labels = collect_labels(item)
    for u in unused_labels:
        try:
            removed_labels.remove(u)
        except ValueError:
            pass

    if idaapi is not None:
        if new_item.ea == idaapi.BADADDR and item.ea != idaapi.BADADDR:
            new_item.ea = item.ea

    if new_item.label_num == -1 and item.label_num != -1:
        new_item.label_num = item.label_num
        try:
            removed_labels.remove(item.label_num)
        except ValueError:
            pass

    if new_item.label_num not in (-1, item.label_num):
        logger.error("failed to replace item %s with new label", item.opname)
        return False

    if len(removed_labels) > 1:
        logger.error("failed to replace item %s with labels in it", item.opname)
        return False

    if (
        len(removed_labels) == 1
        and removed_labels[0] != item
        and new_item.label_num not in (item.label_num, -1)
    ):
        logger.error("failed to replace item %s with labels in it", item.opname)
        return False

    rv = _replace_instr(item, new_item)

    if idaapi is not None:
        if rv and new_item.op == idaapi.cit_goto:
            ctx.is_modified = True
    if rv and new_item.label_num != -1:
        ctx.is_modified = True
    if rv and len(unused_labels) != 0:
        ctx.is_modified = True
        ctx.cfunc.remove_unused_labels()
    return rv


def replace_expr(
    expr: typing.Any, new_expr: typing.Any, ctx: ASTContext
) -> bool:
    """Replace an expression in the ctree."""
    if idaapi is None:
        return False
    new_expr = idaapi.cexpr_t(new_expr)
    expr.replace_by(new_expr)
    return True


class ASTPatch:
    """Encapsulates a deferred ctree patch."""

    class PatchType(Enum):
        SCHEME_MODIFIED = 0
        REMOVE_INSTR = 1
        REPLACE_INSTR = 2
        REPLACE_EXPR = 3

    def __init__(
        self,
        patch_type: "ASTPatch.PatchType",
        item: typing.Any = None,
        new_item: typing.Any = None,
    ) -> None:
        self.ptype = patch_type
        self.item = item
        self.new_item = new_item

    @classmethod
    def remove_instr(cls, item: typing.Any) -> "ASTPatch":
        """Create a patch that removes an instruction."""
        assert not item.is_expr()
        return cls(cls.PatchType.REMOVE_INSTR, item)

    @classmethod
    def replace_instr(cls, item: typing.Any, new_item: typing.Any) -> "ASTPatch":
        """Create a patch that replaces an instruction."""
        assert not item.is_expr()
        assert not new_item.is_expr()
        return cls(cls.PatchType.REPLACE_INSTR, item, new_item)

    @classmethod
    def replace_expr(cls, expr: typing.Any, new_expr: typing.Any) -> "ASTPatch":
        """Create a patch that replaces an expression."""
        assert expr.is_expr()
        assert new_expr.is_expr()
        return cls(cls.PatchType.REPLACE_EXPR, expr, new_expr)

    @classmethod
    def scheme_modified(cls) -> "ASTPatch":
        """Create a patch indicating the scheme modified the tree directly."""
        return cls(cls.PatchType.SCHEME_MODIFIED)

    def do_patch(self, ast_ctx: ASTContext) -> bool:
        """Apply the patch to the AST."""
        if self.ptype == self.PatchType.REMOVE_INSTR:
            return remove_instr(self.item, ast_ctx)
        elif self.ptype == self.PatchType.REPLACE_INSTR:
            return replace_instr(self.item, self.new_item, ast_ctx)
        elif self.ptype == self.PatchType.REPLACE_EXPR:
            return replace_expr(self.item, self.new_item, ast_ctx)
        elif self.ptype == self.PatchType.SCHEME_MODIFIED:
            return False
        else:
            raise TypeError("This patch type is not implemented")
