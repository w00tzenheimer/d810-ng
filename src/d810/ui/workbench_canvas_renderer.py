"""Deterministic Qt rendering for immutable Workbench maturity projections."""

from __future__ import annotations

import dataclasses

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtGui, QtWidgets
from d810.ui.workbench_canvas_models import (
    CanvasEdge,
    CanvasMaturity,
    CanvasNode,
    CanvasSubgraph,
    MaturityCanvasProjection,
)


_PORT_COLORS = {
    "analysis": "#4c78a8",
    "capability": "#72b7b2",
    "evidence": "#f58518",
    "fact": "#54a24b",
    "pipeline": "#9d755d",
}
_STAGE_WIDTH = 980.0
_NODE_WIDTH = 210.0
_NODE_GAP = 18.0
_STAGE_GAP = 14.0
_SUBGRAPH_GAP = 10.0
_SUBGRAPH_HEADER_HEIGHT = 24.0


@dataclasses.dataclass(frozen=True, slots=True)
class _NodeGeometry:
    node: CanvasNode
    x: float
    y: float
    width: float
    height: float


@dataclasses.dataclass(frozen=True, slots=True)
class _SubgraphGeometry:
    subgraph: CanvasSubgraph
    x: float
    y: float
    width: float
    height: float
    nodes: tuple[_NodeGeometry, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _StageGeometry:
    stage: CanvasMaturity
    x: float
    y: float
    width: float
    height: float
    collapsed: bool
    nodes: tuple[_NodeGeometry, ...]
    subgraphs: tuple[_SubgraphGeometry, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _EdgeGeometry:
    edge: CanvasEdge
    source: tuple[float, float]
    target: tuple[float, float]


@dataclasses.dataclass(frozen=True, slots=True)
class _CanvasLayout:
    stages: tuple[_StageGeometry, ...]
    port_positions: dict[tuple[str, str, str], tuple[float, float]]
    edges: tuple[_EdgeGeometry, ...]


def _stage_subgraphs(
    projection: MaturityCanvasProjection,
    stage: CanvasMaturity,
    stage_nodes: list[CanvasNode],
) -> tuple[tuple[CanvasSubgraph, tuple[CanvasNode, ...]], ...]:
    """Return declared display groups, with a compatibility group for old fixtures."""
    by_id = {node.node_id: node for node in stage_nodes}
    declared = tuple(
        group
        for group in projection.subgraphs
        if group.maturity_id == stage.stage_id
    )
    result: list[tuple[CanvasSubgraph, tuple[CanvasNode, ...]]] = []
    grouped_node_ids: set[str] = set()
    for subgraph in declared:
        nodes = tuple(
            by_id[node_id]
            for node_id in subgraph.node_ids
            if node_id in by_id
        )
        if nodes:
            result.append((subgraph, nodes))
            grouped_node_ids.update(node.node_id for node in nodes)
    ungrouped = tuple(
        node for node in stage_nodes if node.node_id not in grouped_node_ids
    )
    if ungrouped:
        result.append(
            (
                CanvasSubgraph(
                    group_id=f"{stage.stage_id}:unassigned",
                    maturity_id=stage.stage_id,
                    strategy_stage_id="unassigned",
                    label="Unassigned workflow stage",
                    node_ids=tuple(node.node_id for node in ungrouped),
                ),
                ungrouped,
            )
        )
    return tuple(result)


def _layout_projection(
    projection: MaturityCanvasProjection,
    collapsed_stages: typing.Iterable[str],
) -> _CanvasLayout:
    """Lay out immutable nodes and direction-specific automatic edges."""
    collapsed_ids = frozenset(str(value) for value in collapsed_stages)
    nodes_by_stage: dict[str, list[CanvasNode]] = {
        stage.stage_id: [] for stage in projection.maturities
    }
    for node in projection.nodes:
        nodes_by_stage.setdefault(node.maturity.stage_id, []).append(node)

    port_positions: dict[tuple[str, str, str], tuple[float, float]] = {}
    stages: list[_StageGeometry] = []
    stage_y = 8.0
    for stage in sorted(
        projection.maturities,
        key=lambda value: (value.ordinal, value.stage_id),
    ):
        collapsed = stage.stage_id in collapsed_ids
        stage_nodes = nodes_by_stage.get(stage.stage_id, [])
        node_geometries: list[_NodeGeometry] = []
        subgraph_geometries: list[_SubgraphGeometry] = []
        stage_width = _STAGE_WIDTH
        if not collapsed:
            subgraph_y = stage_y + 32.0
            for subgraph, subgraph_nodes in _stage_subgraphs(
                projection,
                stage,
                stage_nodes,
            ):
                node_height = max(
                    58.0 + 12.0 * max(len(node.inputs), len(node.outputs))
                    for node in subgraph_nodes
                )
                subgraph_x = 14.0
                subgraph_width = max(
                    _STAGE_WIDTH - 20.0,
                    20.0
                    + len(subgraph_nodes) * _NODE_WIDTH
                    + max(0, len(subgraph_nodes) - 1) * _NODE_GAP,
                )
                subgraph_height = _SUBGRAPH_HEADER_HEIGHT + node_height + 14.0
                group_nodes: list[_NodeGeometry] = []
                for column, node in enumerate(subgraph_nodes):
                    node_x = subgraph_x + 10.0 + column * (_NODE_WIDTH + _NODE_GAP)
                    node_y = subgraph_y + _SUBGRAPH_HEADER_HEIGHT
                    node_geometry = _NodeGeometry(
                        node=node,
                        x=node_x,
                        y=node_y,
                        width=_NODE_WIDTH,
                        height=node_height,
                    )
                    group_nodes.append(node_geometry)
                    node_geometries.append(node_geometry)
                    for index, port in enumerate(node.inputs):
                        port_positions[(node.node_id, port.port_id, "input")] = (
                            node_x,
                            node_y + 34.0 + index * 12.0,
                        )
                    for index, port in enumerate(node.outputs):
                        port_positions[(node.node_id, port.port_id, "output")] = (
                            node_x + _NODE_WIDTH,
                            node_y + 34.0 + index * 12.0,
                        )
                subgraph_geometries.append(
                    _SubgraphGeometry(
                        subgraph=subgraph,
                        x=subgraph_x,
                        y=subgraph_y,
                        width=subgraph_width,
                        height=subgraph_height,
                        nodes=tuple(group_nodes),
                    )
                )
                stage_width = max(stage_width, subgraph_x + subgraph_width + 10.0)
                subgraph_y += subgraph_height + _SUBGRAPH_GAP
            body_height = subgraph_y - stage_y - _SUBGRAPH_GAP + 12.0
        else:
            body_height = 18.0
        stage_geometry = _StageGeometry(
            stage=stage,
            x=4.0,
            y=stage_y,
            width=stage_width,
            height=26.0 + body_height,
            collapsed=collapsed,
            nodes=tuple(node_geometries),
            subgraphs=tuple(subgraph_geometries),
        )
        stages.append(stage_geometry)
        stage_y += stage_geometry.height + _STAGE_GAP

    edges: list[_EdgeGeometry] = []
    for edge in projection.edges:
        source = port_positions.get(
            (edge.source_node_id, edge.source_port_id, "output")
        )
        target = port_positions.get((edge.target_node_id, edge.target_port_id, "input"))
        if source is not None and target is not None:
            edges.append(_EdgeGeometry(edge=edge, source=source, target=target))
    return _CanvasLayout(
        stages=tuple(stages),
        port_positions=port_positions,
        edges=tuple(edges),
    )


if QT_GRAPHICS_AVAILABLE:

    class MaturityCanvasRenderer:
        """Paint one compact, stage-ordered workspace from a projection."""

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
            layout = _layout_projection(projection, self._collapsed_stages)
            for stage_geometry in layout.stages:
                stage = stage_geometry.stage
                stage_y = stage_geometry.y
                collapsed = stage_geometry.collapsed
                header = self.scene.addText(("+ " if collapsed else "- ") + stage.label)
                header.setPos(12.0, stage_y)
                header.setDefaultTextColor(QtGui.QColor("#e5e9f0"))
                stage_box = self.scene.addRect(
                    stage_geometry.x,
                    stage_y,
                    stage_geometry.width,
                    stage_geometry.height,
                    QtGui.QPen(QtGui.QColor("#7f8c8d")),
                    QtGui.QBrush(QtGui.QColor("#20252b")),
                )
                stage_box.setZValue(-2.0)
                for subgraph_geometry in stage_geometry.subgraphs:
                    subgraph = subgraph_geometry.subgraph
                    subgraph_box = self.scene.addRect(
                        subgraph_geometry.x,
                        subgraph_geometry.y,
                        subgraph_geometry.width,
                        subgraph_geometry.height,
                        QtGui.QPen(QtGui.QColor("#53606d")),
                        QtGui.QBrush(QtGui.QColor("#27313d")),
                    )
                    subgraph_box.setZValue(-1.5)
                    subgraph_label = self.scene.addText(subgraph.label)
                    subgraph_label.setPos(
                        subgraph_geometry.x + 8.0,
                        subgraph_geometry.y + 3.0,
                    )
                    subgraph_label.setDefaultTextColor(QtGui.QColor("#c8d3df"))
                for node_geometry in stage_geometry.nodes:
                    node = node_geometry.node
                    fill = {
                        "blocked": "#5b3030",
                        "carried": "#303f5b",
                        "disabled": "#3b3b3b",
                    }.get(node.state, "#294f3b")
                    item = self.scene.addRect(
                        node_geometry.x,
                        node_geometry.y,
                        node_geometry.width,
                        node_geometry.height,
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
                    for port in node.inputs:
                        position = layout.port_positions[
                            (node.node_id, port.port_id, "input")
                        ]
                        dot = self.scene.addEllipse(
                            position[0] - 4.0,
                            position[1] - 4.0,
                            8.0,
                            8.0,
                            QtGui.QPen(QtGui.QColor("#d8dee9")),
                            self._port_brush(port.artifact_type),
                        )
                        dot.setToolTip(f"input {port.artifact_type}: {port.label}")
                    for port in node.outputs:
                        position = layout.port_positions[
                            (node.node_id, port.port_id, "output")
                        ]
                        dot = self.scene.addEllipse(
                            position[0] - 4.0,
                            position[1] - 4.0,
                            8.0,
                            8.0,
                            QtGui.QPen(QtGui.QColor("#d8dee9")),
                            self._port_brush(port.artifact_type),
                        )
                        dot.setToolTip(f"output {port.artifact_type}: {port.label}")

            for edge_geometry in layout.edges:
                edge = edge_geometry.edge
                line = self.scene.addLine(
                    edge_geometry.source[0],
                    edge_geometry.source[1],
                    edge_geometry.target[0],
                    edge_geometry.target[1],
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
