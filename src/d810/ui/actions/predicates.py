"""View type predicates for filtering actions by context.

This module provides helpers to determine widget types so the context menu
can show only relevant actions.
"""
from __future__ import annotations

from d810.core import typing


def is_pseudocode_widget(
    widget: typing.Any,
    ida_hexrays_module: typing.Any | None = None,
) -> bool:
    """Check if a widget is a pseudocode (Hex-Rays decompiler) view.

    Args:
        widget: IDA widget handle (TWidget *)

    Returns:
        True if widget is a pseudocode view, False otherwise
    """
    if ida_hexrays_module is None:
        return False

    # Check if we can get a vdui_t from this widget
    vdui = ida_hexrays_module.get_widget_vdui(widget)
    return vdui is not None


def is_disassembly_widget(
    widget: typing.Any,
    idaapi_module: typing.Any | None = None,
) -> bool:
    """Check if a widget is a disassembly view.

    Args:
        widget: IDA widget handle (TWidget *)

    Returns:
        True if widget is a disassembly view, False otherwise
    """
    if idaapi_module is None:
        return False

    # Check widget type
    widget_type = idaapi_module.get_widget_type(widget)
    return widget_type == idaapi_module.BWN_DISASM
