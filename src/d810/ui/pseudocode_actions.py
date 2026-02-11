"""Pseudocode context-menu action handlers for D810ng.

DEPRECATED: This module is maintained for backward compatibility only.
New code should import directly from d810.ui.actions.

The action classes have been migrated to individual modules in d810.ui.actions/.
This file now re-exports them for backward compatibility.
"""
from __future__ import annotations

import typing
import warnings

from d810.core.logging import getLogger

# Re-export new action classes for backward compatibility
from d810.ui.actions.decompile_function import DecompileFunction
from d810.ui.actions.deobfuscate_this import DeobfuscateThisFunction
from d810.ui.actions.deobfuscation_stats import DeobfuscationStats
from d810.ui.actions.function_rules import FunctionRules
from d810.ui.actions.mark_deobfuscated import MarkDeobfuscated

# Deprecated: Use d810.ui.actions_logic directly
from d810.ui.actions_logic import (
    check_plugin_state,
    format_stats_for_display,
    get_deobfuscation_stats,
)

logger = getLogger("D810.ui")

# Emit deprecation warning when this module is imported
warnings.warn(
    "d810.ui.pseudocode_actions is deprecated. "
    "Import action classes from d810.ui.actions.* instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Backward compatibility: Legacy action lists
# These are maintained for any code that still references them
ALL_ACTIONS: list[typing.Any] = [
    DeobfuscateThisFunction,
    DeobfuscationStats,
    FunctionRules,
    MarkDeobfuscated,
]

DISASM_ACTIONS: list[typing.Any] = [
    DecompileFunction,
]

__all__ = [
    "DecompileFunction",
    "DeobfuscateThisFunction",
    "DeobfuscationStats",
    "FunctionRules",
    "MarkDeobfuscated",
    "check_plugin_state",
    "format_stats_for_display",
    "get_deobfuscation_stats",
    "ALL_ACTIONS",
    "DISASM_ACTIONS",
    "_D810Action",
]

# Legacy _D810Action class (for compatibility)
# This is now just a stub, as all actions inherit from D810ActionHandler
if typing.TYPE_CHECKING:
    from d810.manager import D810State


class _D810Action:
    """Legacy base class - use D810ActionHandler from d810.ui.actions instead.

    DEPRECATED: This class is maintained for backward compatibility only.
    """

    ACTION_ID: str = ""
    ACTION_TEXT: str = ""
    ACTION_TOOLTIP: str = ""
    REQUIRES_STARTED: bool = False

    def __init__(self, state: "D810State") -> None:
        """Initialize action with state reference.

        Args:
            state: The D810State instance to use for accessing plugin state.
        """
        self._state = state
