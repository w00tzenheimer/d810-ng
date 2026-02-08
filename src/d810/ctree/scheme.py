"""Scheme: pairs a pattern with a handler callback.

When the pattern matches a ctree node, the handler is invoked with
the match context and returns an ``ASTPatch`` (or ``None``).

Ported from herast (herast/tree/scheme.py).
"""
from __future__ import annotations

import typing
from enum import Enum

from d810.core import getLogger
from d810.ctree.match_context import MatchContext
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.ast_patch import ASTPatch

logger = getLogger("D810.ctree")


class Scheme:
    """Pairs patterns with a handler for ctree matching."""

    class SchemeType(Enum):
        GENERIC = 0
        READONLY = 1
        SINGULAR = 2

    def __init__(
        self,
        *patterns: BasePat,
        scheme_type: "Scheme.SchemeType" = SchemeType.GENERIC,
    ) -> None:
        """
        :param patterns: AST patterns to match.
        :param scheme_type:
            ``GENERIC`` -- items are independent,
            ``READONLY`` -- no AST patching,
            ``SINGULAR`` -- interdependency between matched items.
        """
        self.patterns: tuple[BasePat, ...] = patterns
        self.stype: Scheme.SchemeType = scheme_type

    def on_matched_item(
        self, item: typing.Any, ctx: MatchContext
    ) -> ASTPatch | None:
        """Callback for successful match.

        Override in subclasses to implement AST modification or
        information collection.

        :param item: matched AST item.
        :param ctx: matching context with variable bindings.
        :return: how to patch the AST, or ``None``.
        """
        return None

    def on_tree_iteration_start(self) -> None:
        """Called at the start of AST iteration.

        Override to initialize state.
        """
        return

    def on_tree_iteration_end(self) -> None:
        """Called at the end of AST iteration.

        Override to process collected information.
        """
        return
