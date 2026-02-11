"""D810ng action framework.

This package provides auto-discovery of context menu actions via the
Registrant metaclass. Actions are automatically registered when their
modules are imported.

The framework uses a 3-tier architecture:
    1. Logic layer (pure Python, no IDA imports)
    2. Handler layer (D810ActionHandler subclasses)
    3. Registration layer (D810ContextMenu auto-discovers handlers)

Example:
    To create a new action, subclass D810ActionHandler and implement execute():

    >>> from d810.ui.actions import D810ActionHandler
    >>> class MyAction(D810ActionHandler):
    ...     ACTION_ID = "d810ng:my_action"
    ...     ACTION_TEXT = "My Action"
    ...     ACTION_TOOLTIP = "Does something useful"
    ...     SUPPORTED_VIEWS = frozenset({"pseudocode"})
    ...
    ...     def execute(self, ctx) -> int:
    ...         # Implement action logic
    ...         return 1

    The action is automatically registered in D810ActionHandler.registry
    when the class is defined.
"""
from __future__ import annotations

from d810.ui.actions.base import D810ActionHandler

# Import all action modules to trigger registration
from d810.ui.actions import (
    decompile_function,
    deobfuscate_this,
    deobfuscation_stats,
    export_disasm,
    export_microcode,
    export_to_c,
    function_rules,
    mark_deobfuscated,
    reload_d810ng,
    start_d810ng,
    stop_d810ng,
)

# Export public API
__all__ = ["D810ActionHandler"]
