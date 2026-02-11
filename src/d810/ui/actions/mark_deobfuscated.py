"""Mark as deobfuscated action.

Mark the current function as deobfuscated (stub).
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_hexrays
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


class MarkDeobfuscated(D810ActionHandler):
    """Mark the current function as deobfuscated (stub)."""

    ACTION_ID = "d810ng:mark_deobfuscated"
    ACTION_TEXT = "Mark as deobfuscated"
    ACTION_TOOLTIP = "Mark this function as successfully deobfuscated (coming soon)"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 50

    def execute(self, ctx: typing.Any) -> int:
        """Execute the mark as deobfuscated action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if ida_kernwin is None:
            return 0

        ida_kernwin.info("Not yet implemented: Mark as deobfuscated")
        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        if ida_hexrays is None:
            return False

        return ida_hexrays.get_widget_vdui(ctx.widget) is not None
