"""Deterministic Qt rendering for immutable Workbench maturity projections."""

from __future__ import annotations

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtGui, QtWidgets
from d810.ui.workbench_canvas_models import MaturityCanvasProjection


_PORT_COLORS = {
    "analysis": "#4c78a8",
    "capability": "#72b7b2",
    "evidence": "#f58518",
    "fact": "#54a24b",
    "pipeline": "#9d755d",
}


if QT_GRAPHICS_AVAILABLE:

    class MaturityCanvasRenderer:
        """Paint one compact, stage-ordered workspace from a projection."""

        _STAGE_WIDTH = 980.0
        _NODE_WIDTH = 210.0
        _NODE_GAP = 18.0
        _STAGE_GAP = 14.0

        def __init__(self, scene: typing.Any | None = None) -> None:
            self.scene = scene if scene is not None else QtWidgets.QGraphicsScene()
            self._collapsed_stages: frozenset[str] = frozenset()
            self._select_node: typing.Callable[[str | None], None] | None = None
            self._add_pass: typing.Callable[[str, str], None] | None = None
            self._edit_options: (
                typing.Callable[[str, dict[str, object]], None] | None
            ) = None
            self._save_recipe: typing.Callable[[], None] | None = None
            self._projection: MaturityCanvasProjection | None = None
            self.scene.selectionChanged.connect(self._selection_changed)

        def bind_actions(
            self,
            select_node: typing.Callable[[str | None], None],
            add_pass: typing.Callable[[str, str], None],
            edit_options: typing.Callable[[str, dict[str, object]], None],
            save_recipe: typing.Callable[[], None],
        ) -> None:
            """Bind presentation events to recipe intents owned by the panel."""
            self._select_node = select_node
            self._add_pass = add_pass
            self._edit_options = edit_options
            self._save_recipe = save_recipe

        def set_collapsed_stages(self, stage_ids: typing.Iterable[str]) -> None:
            self._collapsed_stages = frozenset(str(value) for value in stage_ids)

        def request_add_pass(self, stage_id: str, pass_id: str) -> None:
            if self._add_pass is not None:
                self._add_pass(str(stage_id), str(pass_id))

        def request_edit_options(
            self,
            node_id: str,
            options: dict[str, object],
        ) -> None:
            if self._edit_options is not None:
                self._edit_options(str(node_id), dict(options))

        def request_save_recipe(self) -> None:
            if self._save_recipe is not None:
                self._save_recipe()

        @staticmethod
        def _selectable_flag() -> typing.Any:
            try:
                return QtWidgets.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
            except AttributeError:
                return QtWidgets.QGraphicsItem.ItemIsSelectable

        @staticmethod
        def _port_brush(artifact_type: str) -> typing.Any:
            color = _PORT_COLORS.get(artifact_type, "#bab0ac")
            return QtGui.QBrush(QtGui.QColor(color))

        def render(self, projection: MaturityCanvasProjection) -> None:
            """Replace scene items using only the supplied immutable projection."""
            self._projection = projection
            self.scene.clear()
            nodes_by_stage: dict[str, list[typing.Any]] = {
                stage.stage_id: [] for stage in projection.maturities
            }
            for node in projection.nodes:
                nodes_by_stage.setdefault(node.maturity.stage_id, []).append(node)

            port_positions: dict[tuple[str, str], tuple[float, float]] = {}
            stage_y = 8.0
            for stage in sorted(
                projection.maturities,
                key=lambda value: (value.ordinal, value.stage_id),
            ):
                collapsed = stage.stage_id in self._collapsed_stages
                header = self.scene.addText(("+ " if collapsed else "- ") + stage.label)
                header.setPos(12.0, stage_y)
                header.setDefaultTextColor(QtGui.QColor("#e5e9f0"))
                stage_nodes = nodes_by_stage.get(stage.stage_id, ())
                node_height = (
                    max(
                        (58.0 + 12.0 * max(len(node.inputs), len(node.outputs)))
                        for node in stage_nodes
                    )
                    if stage_nodes
                    else 58.0
                )
                body_height = 18.0 if collapsed else node_height + 16.0
                stage_box = self.scene.addRect(
                    4.0,
                    stage_y,
                    self._STAGE_WIDTH,
                    26.0 + body_height,
                    QtGui.QPen(QtGui.QColor("#7f8c8d")),
                    QtGui.QBrush(QtGui.QColor("#20252b")),
                )
                stage_box.setZValue(-2.0)
                if not collapsed:
                    for column, node in enumerate(stage_nodes):
                        node_x = 18.0 + column * (self._NODE_WIDTH + self._NODE_GAP)
                        node_y = stage_y + 34.0
                        fill = {
                            "blocked": "#5b3030",
                            "carried": "#303f5b",
                            "disabled": "#3b3b3b",
                        }.get(node.state, "#294f3b")
                        item = self.scene.addRect(
                            node_x,
                            node_y,
                            self._NODE_WIDTH,
                            node_height,
                            QtGui.QPen(QtGui.QColor("#b8c2cc")),
                            QtGui.QBrush(QtGui.QColor(fill)),
                        )
                        item.setData(0, node.node_id)
                        item.setFlag(self._selectable_flag(), True)
                        item.setToolTip(node.detail)
                        label = self.scene.addText(node.label)
                        label.setParentItem(item)
                        label.setPos(10.0, 5.0)
                        label.setDefaultTextColor(QtGui.QColor("#eceff4"))
                        for index, port in enumerate(node.inputs):
                            port_y = node_y + 34.0 + index * 12.0
                            dot = self.scene.addEllipse(
                                node_x - 4.0,
                                port_y - 4.0,
                                8.0,
                                8.0,
                                QtGui.QPen(QtGui.QColor("#d8dee9")),
                                self._port_brush(port.artifact_type),
                            )
                            dot.setToolTip(f"input {port.artifact_type}: {port.label}")
                            port_positions[(node.node_id, port.port_id)] = (
                                node_x,
                                port_y,
                            )
                        for index, port in enumerate(node.outputs):
                            port_y = node_y + 34.0 + index * 12.0
                            dot = self.scene.addEllipse(
                                node_x + self._NODE_WIDTH - 4.0,
                                port_y - 4.0,
                                8.0,
                                8.0,
                                QtGui.QPen(QtGui.QColor("#d8dee9")),
                                self._port_brush(port.artifact_type),
                            )
                            dot.setToolTip(f"output {port.artifact_type}: {port.label}")
                            port_positions[(node.node_id, port.port_id)] = (
                                node_x + self._NODE_WIDTH,
                                port_y,
                            )
                stage_y += 26.0 + body_height + self._STAGE_GAP

            for edge in projection.edges:
                source = port_positions.get((edge.source_node_id, edge.source_port_id))
                target = port_positions.get((edge.target_node_id, edge.target_port_id))
                if source is None or target is None:
                    continue
                line = self.scene.addLine(
                    source[0],
                    source[1],
                    target[0],
                    target[1],
                    QtGui.QPen(QtGui.QColor(_PORT_COLORS.get(edge.kind, "#bab0ac"))),
                )
                line.setZValue(-1.0)
                line.setToolTip(edge.kind)
            bounds = self.scene.itemsBoundingRect()
            self.scene.setSceneRect(bounds.adjusted(-8.0, -8.0, 8.0, 8.0))

        def _selection_changed(self) -> None:
            if self._select_node is None:
                return
            selected = self.scene.selectedItems()
            node_id = selected[0].data(0) if selected else None
            self._select_node(str(node_id) if node_id else None)

else:

    class MaturityCanvasRenderer:
        """Unavailable renderer placeholder for non-GUI imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


__all__ = ["MaturityCanvasRenderer"]
