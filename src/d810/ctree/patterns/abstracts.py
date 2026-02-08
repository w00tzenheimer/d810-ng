"""Abstract combinator patterns for ctree matching.

Provides ``AnyPat``, ``OrPat``, ``AndPat``, and ``DeepExprPat`` which
combine or recursively search sub-patterns.

Ported from herast (herast/tree/patterns/abstracts.py).
"""
from __future__ import annotations

import typing

from d810.core import getLogger
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.match_context import MatchContext

logger = getLogger("D810.ctree")


class AnyPat(BasePat):
    """Pattern that always successfully matches."""

    def __init__(self, may_be_none: bool = True, **kwargs: typing.Any) -> None:
        """
        :param may_be_none: whether item is allowed to be None
        """
        super().__init__(**kwargs)
        self.may_be_none = may_be_none

    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        rv = item is not None or self.may_be_none
        if rv and item is not None and self.bind_name is not None:
            rv = ctx.bind_item(self.bind_name, item)
        return rv

    @property
    def children(self) -> tuple:
        return ()


class OrPat(BasePat):
    """Logical-or pattern: matches if any sub-pattern matches."""

    def __init__(self, *pats: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        if len(pats) <= 1:
            logger.warning("OrPat expects at least two patterns")
        self.pats: tuple[BasePat, ...] = tuple(pats)

    @BasePat.base_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        for p in self.pats:
            if p.check(item, ctx):
                return True
        return False

    @property
    def children(self) -> tuple[BasePat, ...]:
        return self.pats


class AndPat(BasePat):
    """Logical-and pattern: matches only if all sub-patterns match."""

    def __init__(self, *pats: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        if len(pats) <= 1:
            logger.warning("one or less patterns to AndPat is useless")
        self.pats: tuple[BasePat, ...] = tuple(pats)

    @BasePat.base_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        for p in self.pats:
            if not p.check(item, ctx):
                return False
        return True

    @property
    def children(self) -> tuple[BasePat, ...]:
        return self.pats


class DeepExprPat(BasePat):
    """Find pattern somewhere inside an item and save it in context if
    ``bind_name`` is provided.

    Recursively descends into all sub-items of the given item.
    """

    def __init__(self, pat: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.pat = pat

    @BasePat.base_check
    def check(self, expr: typing.Any, ctx: MatchContext) -> bool:
        from d810.ctree.ast_iteration import iterate_all_subitems

        for item in iterate_all_subitems(expr):
            if not self.pat.check(item, ctx):
                continue
            return True
        return False
