"""Match context for ctree pattern matching.

Stores named variable bindings during pattern matching. When a pattern
with a ``bind_name`` matches, the matched ``citem_t`` is stored under
that key for later retrieval.

Ported from herast (herast/tree/match_context.py).
"""
from __future__ import annotations

from d810.core import typing
from d810.core import getLogger

if typing.TYPE_CHECKING:
    from d810.ctree.patterns.base_pattern import BasePat

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional so the module can be tested without IDA.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


class MatchContext:
    """Dict-like storage for named variable bindings during pattern matching."""

    def __init__(self, ast_ctx: typing.Any, pattern: "BasePat") -> None:
        self.ast_ctx = ast_ctx
        self.pattern = pattern
        self.binded_items: dict[str, typing.Any] = {}

    def get_item(self, name: str) -> typing.Any | None:
        """Return the item bound to *name*, or ``None``."""
        return self.binded_items.get(name, None)

    def bind_item(self, name: str, item: typing.Any) -> bool:
        """Bind *item* to *name*.

        If *name* is already bound, the new item must be equivalent to the
        existing one (same variable index for ``cot_var``, or
        ``equal_effect`` for everything else).
        """
        current_item = self.get_item(name)
        if current_item is None:
            self.binded_items[name] = item
            return True

        if idaapi is not None:
            if current_item.op == idaapi.cot_var:
                if item.op != idaapi.cot_var:
                    return False
                return current_item.v.idx == item.v.idx

        return item.equal_effect(current_item)

    def has_item(self, name: str) -> bool:
        """Return ``True`` if *name* is bound."""
        return self.binded_items.get(name, None) is not None
