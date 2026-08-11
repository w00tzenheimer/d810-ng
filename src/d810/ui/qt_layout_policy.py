"""Small cross-binding layout policies shared by native D810 panels."""

from __future__ import annotations

from d810.core.typing import Any
from d810.qt_shim import QtCore, QtWidgets


_LEFT_ALIGNED_BUTTON_STYLESHEET = (
    "QPushButton { text-align: left; padding-left: 8px; }"
)


def _left_top_alignment() -> tuple[Any, Any] | None:
    alignment = getattr(QtCore.Qt, "AlignmentFlag", None)
    if alignment is not None:
        left = getattr(alignment, "AlignLeft", None)
        top = getattr(alignment, "AlignTop", None)
    else:
        left = getattr(QtCore.Qt, "AlignLeft", None)
        top = getattr(QtCore.Qt, "AlignTop", None)
    if left is None or top is None:
        return None
    return left, left | top


def _all_non_fixed_fields_grow() -> Any:
    try:
        return QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
    except AttributeError:
        return QtWidgets.QFormLayout.AllNonFixedFieldsGrow


def configure_left_aligned_form(layout: Any) -> None:
    """Anchor a compact information form left and let value fields expand."""
    alignment = _left_top_alignment()
    if alignment is None:
        return
    left, left_top = alignment
    layout.setFormAlignment(left_top)
    layout.setLabelAlignment(left)
    layout.setFieldGrowthPolicy(_all_non_fixed_fields_grow())


def configure_left_aligned_button(button: Any) -> None:
    """Left-align one push-button caption without affecting host-wide styling."""
    button.setMinimumHeight(32)
    button.setStyleSheet(_LEFT_ALIGNED_BUTTON_STYLESHEET)


def configure_overflow_menu_button(button: Any) -> None:
    """Keep a compact overflow menu easy to target without fixing its size."""
    button.setMinimumWidth(72)


__all__ = [
    "configure_left_aligned_button",
    "configure_left_aligned_form",
    "configure_overflow_menu_button",
]
