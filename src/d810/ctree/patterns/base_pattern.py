"""Base pattern class for ctree pattern matching.

All ctree patterns inherit from :class:`BasePat`.  The ``check()`` method
is the main entry point; subclasses override it via the ``@base_check``
decorator which handles ``check_op`` validation, ``bind_name`` storage,
and debug output.

Ported from herast (herast/tree/patterns/base_pattern.py).
"""
from __future__ import annotations

import traceback
from d810.core import typing
from d810.core import getLogger
from d810.ctree.match_context import MatchContext

logger = getLogger("D810.ctree")


class BasePat:
    """Base class for all ctree patterns."""

    op: int | None = None

    def __init__(
        self,
        bind_name: str | None = None,
        debug: bool = False,
        debug_msg: str | None = None,
        debug_trace_depth: int = 0,
        check_op: int | None = None,
    ) -> None:
        """
        :param bind_name: should successfully matched item be remembered
        :param debug: should provide debug information during matching
        :param debug_msg: additional message to print on debug
        :param debug_trace_depth: additional trace information on debug
        :param check_op: what item type to check. skips this check if None
        """
        self.bind_name = bind_name
        self.check_op = check_op
        self.debug = debug
        self.debug_msg = debug_msg
        self.debug_trace_depth = debug_trace_depth

    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        """Base matching operation.

        :param item: AST item (citem_t)
        :param ctx: matching context
        """
        raise NotImplementedError("This is an abstract class")

    @classmethod
    def get_opname(cls) -> str | None:
        """Return the human-readable name of this pattern's op code."""
        from d810.ctree import consts as consts_mod
        return consts_mod.op2str.get(cls.op, None)

    @staticmethod
    def base_check(func: typing.Callable) -> typing.Callable:
        """Decorator for child classes instead of inheritance, since
        before and after calls are needed.
        """

        def __perform_base_check(self: BasePat, item: typing.Any, ctx: MatchContext) -> bool:
            if item is None:
                return False

            if self.check_op is not None and item.op != self.check_op:
                return False

            rv: bool = func(self, item, ctx)

            if rv and self.bind_name is not None:
                rv = ctx.bind_item(self.bind_name, item)

            if self.debug:
                if self.debug_msg:
                    logger.debug("Debug: value = %s, %s", rv, self.debug_msg)
                else:
                    logger.debug("Debug: value = %s", rv)

                if self.debug_trace_depth != 0:
                    logger.debug(
                        "Debug calltrace, address of item: %#x (%s)",
                        item.ea,
                        item.opname,
                    )
                    logger.debug("---------------------------------")
                    for line in traceback.format_stack()[: self.debug_trace_depth]:
                        logger.debug(line.rstrip())
                    logger.debug("---------------------------------")
            return rv

        return __perform_base_check

    @property
    def children(self) -> tuple:
        """Return child patterns. Must be overridden by subclasses."""
        raise NotImplementedError("An abstract class doesn't have any children")
