"""Portable icon loading for Qt bindings with incomplete SVG support."""
from __future__ import annotations

import pathlib

from d810.qt_shim import QtCore, QtGui


_ICON_DIR = pathlib.Path(__file__).with_name("icons")
_ICON_SIZE = 24


def bundled_icon(name: str) -> QtGui.QIcon:
    """Load a packaged SVG, drawing a compact fallback when Qt cannot rasterize it."""

    icon = QtGui.QIcon(str(_ICON_DIR / f"{name}.svg"))
    if not icon.pixmap(QtCore.QSize(_ICON_SIZE, _ICON_SIZE)).isNull():
        return icon
    pixmap = _fallback_pixmap(name)
    return QtGui.QIcon(pixmap)


def _fallback_pixmap(name: str) -> QtGui.QPixmap:
    pixmap = QtGui.QPixmap(_ICON_SIZE, _ICON_SIZE)
    global_color = getattr(QtCore.Qt, "GlobalColor", QtCore.Qt)
    pixmap.fill(global_color.transparent)

    painter = QtGui.QPainter(pixmap)
    try:
        painter.setRenderHint(_antialiasing_hint())
        _paint_fallback_icon(painter, name)
    finally:
        painter.end()
    return pixmap


def _antialiasing_hint():
    try:
        return QtGui.QPainter.RenderHint.Antialiasing
    except AttributeError:
        return QtGui.QPainter.Antialiasing


def _paint_fallback_icon(painter: QtGui.QPainter, name: str) -> None:
    if name == "status-running":
        _paint_dot(painter, "#4CAF50", "#2E7D32", 8)
    elif name == "status-stopped":
        _paint_dot(painter, "#D32F2F", "#9A0007", 8)
    elif name == "rule-enabled":
        _paint_dot(painter, "#4CAF50", None, 5)
    elif name == "rule-disabled":
        _paint_dot(painter, "#9E9E9E", None, 5)
    elif name == "rule-configurable":
        _paint_sliders(painter)
    elif name == "new":
        _paint_new_document(painter)
    elif name == "duplicate":
        _paint_duplicate_documents(painter)
    elif name == "edit":
        _paint_edit(painter)
    elif name == "delete":
        _paint_delete(painter)


def _paint_dot(
    painter: QtGui.QPainter, fill: str, outline: str | None, radius: int
) -> None:
    if outline is None:
        painter.setPen(QtCore.Qt.NoPen)
    else:
        painter.setPen(_pen(outline, 1.5))
    painter.setBrush(QtGui.QBrush(QtGui.QColor(fill)))
    painter.drawEllipse(QtCore.QPointF(12, 12), radius, radius)


def _paint_sliders(painter: QtGui.QPainter) -> None:
    painter.setPen(_pen("#455A64", 1.5))
    painter.setBrush(QtGui.QBrush(QtGui.QColor("#455A64")))
    for y, x in ((6, 9), (12, 14), (18, 7)):
        painter.drawLine(4, y, 20, y)
        painter.drawEllipse(QtCore.QPointF(x, y), 1.75, 1.75)


def _paint_new_document(painter: QtGui.QPainter) -> None:
    painter.setPen(_pen("#303030", 1.8))
    painter.setBrush(QtCore.Qt.NoBrush)
    painter.drawRect(5, 3, 14, 18)
    painter.drawLine(12, 10, 12, 18)
    painter.drawLine(8, 14, 16, 14)


def _paint_duplicate_documents(painter: QtGui.QPainter) -> None:
    painter.setPen(_pen("#303030", 1.7))
    painter.setBrush(QtCore.Qt.NoBrush)
    painter.drawRect(4, 6, 12, 14)
    painter.drawRect(8, 3, 12, 14)


def _paint_edit(painter: QtGui.QPainter) -> None:
    painter.setPen(_pen("#303030", 3.0))
    painter.drawLine(7, 17, 17, 7)
    painter.setPen(_pen("#303030", 1.4))
    painter.drawLine(6, 19, 10, 18)


def _paint_delete(painter: QtGui.QPainter) -> None:
    painter.setPen(_pen("#303030", 1.8))
    painter.setBrush(QtCore.Qt.NoBrush)
    painter.drawRect(7, 8, 10, 12)
    painter.drawLine(5, 6, 19, 6)
    painter.drawLine(10, 4, 14, 4)


def _pen(color: str, width: float) -> QtGui.QPen:
    pen = QtGui.QPen(QtGui.QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(QtCore.Qt.RoundCap)
    pen.setJoinStyle(QtCore.Qt.RoundJoin)
    return pen
