"""AST processor for ctree traversal with modification support.

Walks the ctree left-to-right, children-first. Supports restart-on-
modification: if a patch modifies the tree, the processor re-walks
from the root.

Ported from herast (herast/tree/ast_processor.py).
"""
from __future__ import annotations

from d810.core import typing
from enum import Enum

from d810.core import getLogger
from d810.ctree.ast_iteration import get_children
from d810.ctree.ast_patch import ASTPatch
from d810.ctree.ast_context import ASTContext

logger = getLogger("D810.ctree")


def build_path(ast: typing.Any) -> list[tuple[typing.Any, int]]:
    """Build a left-most path from *ast* down to a leaf."""
    path: list[tuple[typing.Any, int]] = []
    while len(children := get_children(ast)) != 0:
        path.append((ast, 0))
        ast = children[0]
    path.append((ast, -1))
    return path


class RelativePosition(Enum):
    PARENT = 0
    BEHIND = 1
    AHEAD = 2
    CURRENT = 3


class ASTProcessor:
    """Iterates the ctree left-to-right and children first.

    Example 1: A->B->C tree yields C, B, A.
    Example 2: A<-B->C tree yields A, C, B.
    """

    def __init__(self, root: typing.Any) -> None:
        self.root = root
        self.path: list[tuple[typing.Any, int]] = []
        self.restart_iteration()

    def get_item_path(self, item: typing.Any) -> list[tuple[typing.Any, int]]:
        """Get the path from root to *item*."""
        parent = self.root.find_parent_of(item)
        if parent is None:
            return [(item, -1)]

        parent = parent.to_specific_type
        parent_children = get_children(parent)
        child_idx = 0
        for child_idx, c in enumerate(parent_children):
            if c == item:
                break
        else:
            raise ValueError()

        path = self.get_item_path(parent)
        if len(path) != 0:
            path[-1] = (path[-1][0], child_idx)
        path.append((item, -1))
        return path

    def restart_iteration(self) -> None:
        """Restart iteration from the root."""
        self.path = build_path(self.root)

    def is_iteration_ended(self) -> bool:
        """Return True if the iteration is finished."""
        return len(self.path) == 0

    def is_iteration_started(self) -> bool:
        """Return True if the iterator is at the very beginning."""
        if len(self.path) == 0:
            return False
        # check that AST path is all left-sided
        if any(child_idx != 0 for (_, child_idx) in self.path[:-1]):
            return False
        # check that the last node is a leaf
        last_item, child_idx = self.path[-1]
        if len(get_children(last_item)) != 0 or child_idx > 0:
            return False
        return True

    def get_current(self) -> typing.Any | None:
        """Return the current item, or None if iteration ended."""
        if len(self.path) == 0:
            return None
        return self.path[-1][0]

    def pop_current(self) -> typing.Any | None:
        """Advance the iterator and return the next item."""
        if len(self.path) == 0:
            return None

        current_item, child_idx = self.path.pop()
        # -1 means no need to iterate children
        if child_idx == -1:
            return current_item

        children = get_children(current_item)
        # iteration is finished for all children
        if len(children) == child_idx + 1:
            return current_item

        self.path.append((current_item, child_idx + 1))
        child = children[child_idx + 1]
        self.path += build_path(child)
        return self.get_current()

    def get_relative_position(
        self, item_path: list[tuple[typing.Any, int]], ast_ctx: ASTContext
    ) -> RelativePosition:
        """Determine the relative position of *item_path* to the current item."""
        item = item_path[-1][0]
        if item == self.get_current():
            return RelativePosition.CURRENT

        relpos = RelativePosition.CURRENT
        for (_, pidx), (_, fidx) in zip(self.path, item_path):
            if pidx < fidx:
                relpos = RelativePosition.BEHIND
                break
            elif pidx > fidx:
                relpos = RelativePosition.AHEAD
                break
        else:
            if len(item_path) == len(self.path):
                relpos = RelativePosition.CURRENT
            elif len(item_path) < len(self.path):
                relpos = RelativePosition.PARENT
            else:
                relpos = RelativePosition.BEHIND
        return relpos

    def apply_patch(self, ast_patch: ASTPatch, ast_ctx: ASTContext) -> bool:
        """Apply a patch and update the iteration state accordingly."""
        # restart from root if user modified AST in scheme callback
        if ast_patch.ptype is ast_patch.PatchType.SCHEME_MODIFIED:
            self.restart_iteration()
            return True

        # sanity check
        assert ast_patch.item is not None

        # if iteration ended, just do the patch
        if len(self.path) == 0:
            logger.warning("patching AST that already finished iteration")
            return ast_patch.do_patch(ast_ctx)

        item_path = self.get_item_path(ast_patch.item)
        if len(item_path) == 0:
            logger.warning("patching AST with items that don't match")
            rv = ast_patch.do_patch(ast_ctx)
            self.restart_iteration()
            return rv

        if not ast_patch.do_patch(ast_ctx):
            return False

        # if context is changed, reiterate from scratch
        if ast_ctx.is_modified:
            ast_ctx.rebuild()
            ast_ctx.is_modified = False
            self.restart_iteration()
            return True

        relpos = self.get_relative_position(item_path, ast_ctx)
        # if item is yet to be iterated, nothing needs to change
        if relpos is RelativePosition.AHEAD:
            return True

        # otherwise reiteration is needed
        if ast_patch.new_item is None:
            # popping deleted instruction
            item_path.pop()
            parent_block, child_idx = item_path[-1]
            children = get_children(parent_block)
            if len(children) != child_idx:
                child = children[child_idx]
                item_path += build_path(child)
            else:
                item_path[-1] = (parent_block, -1)
            self.path = item_path
        elif ast_patch.new_item is not None:
            item_path.pop()
            self.path = item_path + build_path(ast_patch.new_item)

        return True
