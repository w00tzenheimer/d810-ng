"""Read-only Qt graphics primitives for the D810 Maturity Canvas.

The navigation, grid, card, and Bezier presentation are informed by
NodeDataFlowEditor (Copyright (c) 2025 Joseph Al Hajjar; MIT notice in
``d810/_vendor/nodedatafloweditor.LICENSE``).  D810 deliberately excludes
the upstream graph-authoring model: this module renders a projection and
never owns recipe, evidence, or persistence state.
"""

from __future__ import annotations

import math

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtGui, QtWidgets
from d810.ui.workbench_canvas_graphics_logic import (
    BezierControlPoints,
    clamp_canvas_scale,
    edge_presentation,
    node_card_lines,
    node_presentation,
)
from d810.ui.workbench_canvas_models import CanvasEdge, CanvasNode


_GRID_MINOR = 20.0
_GRID_MAJOR = 100.0
_ZOOM_IN_FACTOR = 1.15
_PORT_COLORS = {
    "analysis": "#4c78a8",
    "capability": "#72b7b2",
    "evidence": "#f58518",
    "fact": "#54a24b",
    "pipeline": "#9d755d",
}
_NODE_FILLS = {
    "blocked": "#5b3030",
    "carried": "#303f5b",
    "disabled": "#3b3b3b",
    "evidence_produced": "#6b5423",
}


def _enum(owner: typing.Any, scoped_name: str, legacy_name: str) -> typing.Any:
    """Return one Qt5/Qt6 enum spelling without exposing a binding choice."""

    scoped = getattr(owner, scoped_name, None)
    return getattr(scoped, legacy_name, None) if scoped is not None else getattr(owner, legacy_name)


if QT_GRAPHICS_AVAILABLE:

    def _keep_aspect_ratio() -> typing.Any:
        return _enum(QtCore.Qt, "AspectRatioMode", "KeepAspectRatio")


    def _anchor_under_mouse() -> typing.Any:
        return _enum(QtWidgets.QGraphicsView, "ViewportAnchor", "AnchorUnderMouse")


    def _rubber_band_drag() -> typing.Any:
        return _enum(QtWidgets.QGraphicsView, "DragMode", "RubberBandDrag")


    def _scroll_hand_drag() -> typing.Any:
        return _enum(QtWidgets.QGraphicsView, "DragMode", "ScrollHandDrag")


    def _full_viewport_update() -> typing.Any:
        return _enum(
            QtWidgets.QGraphicsView,
            "ViewportUpdateMode",
            "FullViewportUpdate",
        )


    def _middle_button() -> typing.Any:
        return _enum(QtCore.Qt, "MouseButton", "MidButton")


    def _space_key() -> typing.Any:
        return _enum(QtCore.Qt, "Key", "Key_Space")


    def _antialiasing() -> typing.Any:
        return _enum(QtGui.QPainter, "RenderHint", "Antialiasing")


    def _item_is_selectable() -> typing.Any:
        return _enum(QtWidgets.QGraphicsItem, "GraphicsItemFlag", "ItemIsSelectable")


    def _elide_right() -> typing.Any:
        return _enum(QtCore.Qt, "TextElideMode", "ElideRight")


    def _pen_style(name: str) -> typing.Any:
        return _enum(QtCore.Qt, "PenStyle", name)


    def _palette_role(name: str) -> typing.Any:
        return _enum(QtGui.QPalette, "ColorRole", name)


    def active_theme_color(role: str) -> typing.Any:
        """Read host colours at paint time instead of installing a canvas theme."""

        application = QtWidgets.QApplication.instance()
        palette = application.palette() if application is not None else QtGui.QPalette()
        return palette.color(_palette_role(role))


    def _event_xy(event: typing.Any) -> tuple[int, int]:
        position = getattr(event, "position", None)
        point = position() if callable(position) else event.pos()
        x = getattr(point, "x")
        y = getattr(point, "y")
        return int(x()), int(y())


    class ReadOnlyDataflowScene(QtWidgets.QGraphicsScene):
        """A theme-native dataflow scene with a stable navigation grid."""

        def drawBackground(self, painter: typing.Any, rect: typing.Any) -> None:
            painter.fillRect(rect, active_theme_color("Base"))
            left = math.floor(float(rect.left()) / _GRID_MINOR) * _GRID_MINOR
            top = math.floor(float(rect.top()) / _GRID_MINOR) * _GRID_MINOR
            right = float(rect.right())
            bottom = float(rect.bottom())
            minor_pen = QtGui.QPen(active_theme_color("Midlight"))
            major_pen = QtGui.QPen(active_theme_color("Mid"))
            x = left
            while x <= right:
                painter.setPen(
                    major_pen if int(round(x)) % int(_GRID_MAJOR) == 0 else minor_pen
                )
                painter.drawLine(x, top, x, bottom)
                x += _GRID_MINOR
            y = top
            while y <= bottom:
                painter.setPen(
                    major_pen if int(round(y)) % int(_GRID_MAJOR) == 0 else minor_pen
                )
                painter.drawLine(left, y, right, y)
                y += _GRID_MINOR


    class ReadOnlyDataflowView(QtWidgets.QGraphicsView):
        """Navigation surface for a projection-derived, non-authoring scene."""

        def __init__(self, scene: typing.Any) -> None:
            super().__init__(scene)
            self._panning = False
            self._space_pan = False
            self._pan_button: typing.Any | None = None
            self._pan_origin = (0, 0)
            self.setRenderHint(_antialiasing(), True)
            self.setTransformationAnchor(_anchor_under_mouse())
            self.setResizeAnchor(_anchor_under_mouse())
            self.setViewportUpdateMode(_full_viewport_update())
            self.setDragMode(_rubber_band_drag())

        def fit_workspace(self) -> None:
            rect = self.scene().sceneRect()
            if not rect.isNull() and rect.isValid():
                self.fitInView(rect, _keep_aspect_ratio())

        def reset_zoom(self) -> None:
            self.resetTransform()

        def reset_to_workspace(self) -> None:
            self.resetTransform()
            self.fit_workspace()

        def wheelEvent(self, event: typing.Any) -> None:
            delta = int(event.angleDelta().y())
            if delta == 0:
                super().wheelEvent(event)
                return
            factor = _ZOOM_IN_FACTOR if delta > 0 else 1.0 / _ZOOM_IN_FACTOR
            current = float(self.transform().m11())
            target = clamp_canvas_scale(current, factor)
            if target != current:
                self.scale(target / current, target / current)
            event.accept()

        def mousePressEvent(self, event: typing.Any) -> None:
            if event.button() == _middle_button() or self._space_pan:
                self._panning = True
                self._pan_button = event.button()
                self._pan_origin = _event_xy(event)
                self.setDragMode(_scroll_hand_drag())
                event.accept()
                return
            super().mousePressEvent(event)

        def mouseMoveEvent(self, event: typing.Any) -> None:
            if self._panning:
                x, y = _event_xy(event)
                origin_x, origin_y = self._pan_origin
                self.horizontalScrollBar().setValue(
                    self.horizontalScrollBar().value() - (x - origin_x)
                )
                self.verticalScrollBar().setValue(
                    self.verticalScrollBar().value() - (y - origin_y)
                )
                self._pan_origin = (x, y)
                event.accept()
                return
            super().mouseMoveEvent(event)

        def mouseReleaseEvent(self, event: typing.Any) -> None:
            if self._panning and event.button() == self._pan_button:
                self._panning = False
                self._pan_button = None
                self.setDragMode(_scroll_hand_drag() if self._space_pan else _rubber_band_drag())
                event.accept()
                return
            super().mouseReleaseEvent(event)

        def keyPressEvent(self, event: typing.Any) -> None:
            if event.key() == _space_key():
                self._space_pan = True
                self.setDragMode(_scroll_hand_drag())
                event.accept()
                return
            super().keyPressEvent(event)

        def keyReleaseEvent(self, event: typing.Any) -> None:
            if event.key() == _space_key():
                self._space_pan = False
                if not self._panning:
                    self.setDragMode(_rubber_band_drag())
                event.accept()
                return
            super().keyReleaseEvent(event)


    class ReadOnlyCanvasNodeItem(QtWidgets.QGraphicsObject):
        """A selectable, self-painting card for one immutable canvas node."""

        def __init__(self, node: CanvasNode, width: float, height: float) -> None:
            super().__init__()
            self._node = node
            self._presentation = node_presentation(node.provenance)
            self._rect = QtCore.QRectF(0.0, 0.0, width, height)
            self.setData(0, node.node_id)
            self.setFlag(_item_is_selectable(), True)
            self.setToolTip(node.detail)

        def boundingRect(self) -> typing.Any:
            return self._rect

        def _text_rect(self, top: float) -> typing.Any:
            return QtCore.QRectF(10.0, top, self._rect.width() - 20.0, 15.0)

        def _elide(self, painter: typing.Any, text: str) -> str:
            return painter.fontMetrics().elidedText(
                str(text),
                _elide_right(),
                int(self._text_rect(0.0).width()),
            )

        def _state_brush(self) -> typing.Any:
            return QtGui.QBrush(active_theme_color("Base"))

        def _badge_brush(self) -> typing.Any:
            color = _NODE_FILLS.get(self._node.state, "#294f3b")
            if self._presentation.read_only:
                color = "#53606d" if self._node.provenance == "system" else "#6b5423"
            return QtGui.QBrush(QtGui.QColor(color))

        def _outline_pen(self) -> typing.Any:
            color = active_theme_color("Highlight" if self.isSelected() else "Mid")
            pen = QtGui.QPen(color)
            pen.setWidthF(2.0 if self.isSelected() else 1.0)
            if self._presentation.read_only:
                pen.setStyle(_pen_style("DashLine"))
            return pen

        def _paint_ports(self, painter: typing.Any) -> None:
            for direction, ports, x in (
                ("input", self._node.inputs, 0.0),
                ("output", self._node.outputs, self._rect.width()),
            ):
                del direction
                for index, port in enumerate(ports):
                    y = 78.0 + index * 12.0
                    painter.setPen(QtGui.QPen(active_theme_color("Text")))
                    painter.setBrush(
                        QtGui.QBrush(
                            QtGui.QColor(_PORT_COLORS.get(port.artifact_type, "#bab0ac"))
                        )
                    )
                    painter.drawEllipse(QtCore.QPointF(x, y), 4.0, 4.0)

        def paint(
            self,
            painter: typing.Any,
            option: typing.Any,
            widget: typing.Any = None,
        ) -> None:
            del option, widget
            painter.setPen(self._outline_pen())
            painter.setBrush(self._state_brush())
            painter.drawRoundedRect(self._rect, 5.0, 5.0)
            painter.setPen(QtGui.QPen(active_theme_color("Text")))
            for top, line in zip((8.0, 25.0, 43.0, 61.0), node_card_lines(self._node)):
                painter.drawText(self._text_rect(top), self._elide(painter, line))
            badge_rect = QtCore.QRectF(self._rect.width() - 72.0, 7.0, 64.0, 15.0)
            painter.setPen(QtGui.QPen(active_theme_color("Base")))
            painter.setBrush(self._badge_brush())
            painter.drawRoundedRect(badge_rect, 3.0, 3.0)
            painter.setPen(QtGui.QPen(active_theme_color("BrightText")))
            painter.drawText(badge_rect, self._presentation.badge)
            self._paint_ports(painter)


    class ReadOnlyCanvasConnectionItem(QtWidgets.QGraphicsPathItem):
        """A selectable visual path for one immutable contract edge."""

        def __init__(self, edge: CanvasEdge, curve: BezierControlPoints) -> None:
            path = QtGui.QPainterPath(QtCore.QPointF(*curve.start))
            path.cubicTo(
                QtCore.QPointF(*curve.control_1),
                QtCore.QPointF(*curve.control_2),
                QtCore.QPointF(*curve.end),
            )
            super().__init__(path)
            self._presentation = edge_presentation(edge.relation)
            self._color = _PORT_COLORS.get(edge.kind, "#bab0ac")
            self.setData(0, edge)
            self.setToolTip(self._presentation.label)
            self.setFlag(_item_is_selectable(), True)
            self.setZValue(0.0)

        def paint(
            self,
            painter: typing.Any,
            option: typing.Any,
            widget: typing.Any = None,
        ) -> None:
            del option, widget
            color = (
                QtGui.QColor(self._color)
                if self._presentation.uses_ports
                else active_theme_color("Mid")
            )
            pen = QtGui.QPen(color)
            pen.setWidthF(4.0 if self.isSelected() else 2.0)
            if self._presentation.dashed:
                pen.setStyle(_pen_style("DashLine"))
            painter.setPen(pen)
            painter.setBrush(QtGui.QBrush())
            painter.drawPath(self.path())

        def shape(self) -> typing.Any:
            stroker = QtGui.QPainterPathStroker()
            stroker.setWidth(12.0)
            return stroker.createStroke(self.path())


else:

    def active_theme_color(role: str) -> typing.Any:
        """Import-safe placeholder when no Qt graphics runtime is available."""

        del role
        raise RuntimeError("Qt graphics support is unavailable")

    class ReadOnlyDataflowScene:
        """Import-safe placeholder when no Qt graphics runtime is available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


    class ReadOnlyDataflowView:
        """Import-safe placeholder when no Qt graphics runtime is available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


    class ReadOnlyCanvasNodeItem:
        """Import-safe placeholder when no Qt graphics runtime is available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


    class ReadOnlyCanvasConnectionItem:
        """Import-safe placeholder when no Qt graphics runtime is available."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


__all__ = [
    "active_theme_color",
    "ReadOnlyCanvasConnectionItem",
    "ReadOnlyCanvasNodeItem",
    "ReadOnlyDataflowScene",
    "ReadOnlyDataflowView",
]
