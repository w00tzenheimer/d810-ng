"""Function rules action.

Show / edit the rules that apply to the current function (stub).
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

class FunctionRules(D810ActionHandler):
    """Show / edit the rules that apply to the current function (stub)."""

    ACTION_ID = "d810ng:function_rules"
    ACTION_TEXT = "Function rules..."
    ACTION_TOOLTIP = "View or edit rules for this function (coming soon)"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 30

    def execute(self, ctx: typing.Any) -> int:
        """Execute the function rules action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        if ida_kernwin_mod is None:
            return 0

        ida_kernwin_mod.info("Not yet implemented: Function rules editor")
        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        ida_hexrays_mod = self.ida_module("ida_hexrays")
        if ida_hexrays_mod is None:
            return False

        return ida_hexrays_mod.get_widget_vdui(ctx.widget) is not None
