"""View type predicates for filtering actions by context.

This module provides helpers to determine widget types so the context menu
can show only relevant actions.
"""
from __future__ import annotations

import typing

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_hexrays
    import idaapi

    IDA_AVAILABLE = True
except ImportError:
    ida_hexrays = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


def is_pseudocode_widget(widget: typing.Any) -> bool:
    """Check if a widget is a pseudocode (Hex-Rays decompiler) view.

    Args:
        widget: IDA widget handle (TWidget *)

    Returns:
        True if widget is a pseudocode view, False otherwise
    """
    if not IDA_AVAILABLE or ida_hexrays is None:
        return False

    # Check if we can get a vdui_t from this widget
    vdui = ida_hexrays.get_widget_vdui(widget)
    return vdui is not None


def is_disassembly_widget(widget: typing.Any) -> bool:
    """Check if a widget is a disassembly view.

    Args:
        widget: IDA widget handle (TWidget *)

    Returns:
        True if widget is a disassembly view, False otherwise
    """
    if not IDA_AVAILABLE or idaapi is None:
        return False

    # Check widget type
    widget_type = idaapi.get_widget_type(widget)
    return widget_type == idaapi.BWN_DISASM
