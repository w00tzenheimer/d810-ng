"""D810ng action framework.

This package provides action base classes and optional action-module loading.

The framework uses a 3-tier architecture:
    1. Logic layer (pure Python, no IDA imports)
    2. Handler layer (D810ActionHandler subclasses)
    3. Registration layer (D810ContextMenu discovers/instantiates handlers)

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

    The action class is registered in D810ActionHandler.registry when defined.
"""
from __future__ import annotations

import importlib

from d810.ui.actions.base import D810ActionHandler

_BUILTIN_ACTION_MODULES = (
    "decompile_function",
    "deobfuscate_this",
    "deobfuscation_stats",
    "export_disasm",
    "export_microcode",
    "export_to_c",
    "function_rules",
    "mark_deobfuscated",
    "reload_d810ng",
    "start_d810ng",
    "stop_d810ng",
)


def load_builtin_actions() -> None:
    """Import built-in action modules to populate D810ActionHandler.registry."""
    for module_name in _BUILTIN_ACTION_MODULES:
        importlib.import_module(f"{__name__}.{module_name}")

# Export public API
__all__ = ["D810ActionHandler", "load_builtin_actions"]
