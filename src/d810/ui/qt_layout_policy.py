"""Small cross-binding layout policies shared by native D810 panels."""

from __future__ import annotations

from d810.core.typing import Any
from d810.qt_shim import QtCore, QtWidgets


_LEFT_ALIGNED_BUTTON_STYLESHEET = (
    "QPushButton { text-align: left; padding-left: 8px; }"
)


def _left_top_alignment() -> tuple[Any, Any]:
    try:
        alignment = QtCore.Qt.AlignmentFlag
        left = alignment.AlignLeft
        top = alignment.AlignTop
    except AttributeError:
        left = QtCore.Qt.AlignLeft
        top = QtCore.Qt.AlignTop
    return left, left | top


def _all_non_fixed_fields_grow() -> Any:
    try:
        return QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
    except AttributeError:
        return QtWidgets.QFormLayout.AllNonFixedFieldsGrow


def configure_left_aligned_form(layout: Any) -> None:
    """Anchor a compact information form left and let value fields expand."""
    left, left_top = _left_top_alignment()
    layout.setFormAlignment(left_top)
    layout.setLabelAlignment(left)
    layout.setFieldGrowthPolicy(_all_non_fixed_fields_grow())


def configure_left_aligned_button(button: Any) -> None:
    """Left-align one push-button caption without affecting host-wide styling."""
    button.setStyleSheet(_LEFT_ALIGNED_BUTTON_STYLESHEET)


__all__ = [
    "configure_left_aligned_button",
    "configure_left_aligned_form",
]
