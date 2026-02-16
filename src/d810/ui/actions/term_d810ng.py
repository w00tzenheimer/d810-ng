"""Term D810ng action.

Provides a Settings submenu anchor for engine lifecycle actions.
"""

from __future__ import annotations

from d810.core import typing
from d810.ui.actions.base import D810ActionHandler


class TermD810ng(D810ActionHandler):
    """Anchor action for Term D810 submenu."""

    ACTION_ID = "d810ng:term"
    ACTION_TEXT = "Term D810"
    ACTION_TOOLTIP = "D810 engine lifecycle actions"
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 195
    REQUIRES_STARTED = False
    SUBMENU = "Settings"

    def execute(self, ctx: typing.Any) -> int:
        return 1
