"""Deterministic Qt rendering for immutable Workbench maturity projections."""

from __future__ import annotations

import dataclasses

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtGui, QtWidgets
from d810.ui.workbench_canvas_graphics import (
    ReadOnlyCanvasConnectionItem,
    ReadOnlyCanvasNodeItem,
    ReadOnlyDataflowScene,
    active_theme_color,
)
from d810.ui.workbench_canvas_graphics_logic import contract_bezier, edge_presentation
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
_NODE_FILLS = {
    "blocked": "#5b3030",
    "carried": "#303f5b",
    "disabled": "#3b3b3b",
    "evidence_produced": "#6b5423",
}
_STAGE_WIDTH = 980.0
_NODE_WIDTH = 210.0
_NODE_GAP = 18.0
_NODE_ROW_GAP = 14.0
_NODES_PER_ROW = 4
_NODE_MIN_HEIGHT = 88.0
_NODE_PORT_ROW_HEIGHT = 12.0
_STAGE_GAP = 14.0
_SUBGRAPH_GAP = 10.0
_SUBGRAPH_HEADER_HEIGHT = 24.0


def _node_fill(state: str) -> str:
    """Return the compact semantic color for a projected node state."""

    return _NODE_FILLS.get(state, "#294f3b")


def _node_height(node: CanvasNode) -> float:
    """Reserve room for the fixed card header and each typed port marker."""

    port_count = max(len(node.inputs), len(node.outputs))
    return _NODE_MIN_HEIGHT + _NODE_PORT_ROW_HEIGHT * max(0, port_count - 1)


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
    node_geometries_by_id: dict[str, _NodeGeometry] = {}
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
                subgraph_x = 14.0
                subgraph_width = max(
                    _STAGE_WIDTH - 20.0,
                    20.0
                    + min(_NODES_PER_ROW, len(subgraph_nodes)) * _NODE_WIDTH
                    + max(0, min(_NODES_PER_ROW, len(subgraph_nodes)) - 1)
                    * _NODE_GAP,
                )
                group_nodes: list[_NodeGeometry] = []
                row_y = subgraph_y + _SUBGRAPH_HEADER_HEIGHT
                for row_start in range(0, len(subgraph_nodes), _NODES_PER_ROW):
                    row_nodes = subgraph_nodes[row_start : row_start + _NODES_PER_ROW]
                    row_height = max(_node_height(node) for node in row_nodes)
                    for column, node in enumerate(row_nodes):
                        node_x = subgraph_x + 10.0 + column * (_NODE_WIDTH + _NODE_GAP)
                        node_geometry = _NodeGeometry(
                            node=node,
                            x=node_x,
                            y=row_y,
                            width=_NODE_WIDTH,
                            height=row_height,
                        )
                        group_nodes.append(node_geometry)
                        node_geometries.append(node_geometry)
                        node_geometries_by_id[node.node_id] = node_geometry
                        for index, port in enumerate(node.inputs):
                            port_positions[(node.node_id, port.port_id, "input")] = (
                                node_x,
                                row_y + 78.0 + index * _NODE_PORT_ROW_HEIGHT,
                            )
                        for index, port in enumerate(node.outputs):
                            port_positions[(node.node_id, port.port_id, "output")] = (
                                node_x + _NODE_WIDTH,
                                row_y + 78.0 + index * _NODE_PORT_ROW_HEIGHT,
                            )
                    row_y += row_height + _NODE_ROW_GAP
                subgraph_height = (
                    row_y
                    - subgraph_y
                    - _NODE_ROW_GAP
                    + 14.0
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
        presentation = edge_presentation(edge.relation)
        source = port_positions.get((edge.source_node_id, edge.source_port_id, "output"))
        target = port_positions.get((edge.target_node_id, edge.target_port_id, "input"))
        if not presentation.uses_ports:
            source_node = node_geometries_by_id.get(edge.source_node_id)
            target_node = node_geometries_by_id.get(edge.target_node_id)
            if source_node is not None and target_node is not None:
                if target_node.y > source_node.y:
                    source = (
                        source_node.x + source_node.width / 2.0,
                        source_node.y + source_node.height,
                    )
                    target = (
                        target_node.x + target_node.width / 2.0,
                        target_node.y,
                    )
                else:
                    source = (
                        source_node.x + source_node.width,
                        source_node.y + source_node.height / 2.0,
                    )
                    target = (
                        target_node.x,
                        target_node.y + target_node.height / 2.0,
                    )
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
            self.scene = scene if scene is not None else ReadOnlyDataflowScene()
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
                header.setDefaultTextColor(active_theme_color("Text"))
                header.setZValue(2.0)
                stage_box = self.scene.addRect(
                    stage_geometry.x,
                    stage_y,
                    stage_geometry.width,
                    stage_geometry.height,
                    QtGui.QPen(active_theme_color("Mid")),
                    QtGui.QBrush(active_theme_color("Window")),
                )
                stage_box.setZValue(-2.0)
                for subgraph_geometry in stage_geometry.subgraphs:
                    subgraph = subgraph_geometry.subgraph
                    subgraph_box = self.scene.addRect(
                        subgraph_geometry.x,
                        subgraph_geometry.y,
                        subgraph_geometry.width,
                        subgraph_geometry.height,
                        QtGui.QPen(active_theme_color("Midlight")),
                        QtGui.QBrush(active_theme_color("AlternateBase")),
                    )
                    subgraph_box.setZValue(-1.5)
                    subgraph_label = self.scene.addText(subgraph.label)
                    subgraph_label.setPos(
                        subgraph_geometry.x + 8.0,
                        subgraph_geometry.y + 3.0,
                    )
                    subgraph_label.setDefaultTextColor(active_theme_color("Text"))
                    subgraph_label.setZValue(2.0)
                for node_geometry in stage_geometry.nodes:
                    node = node_geometry.node
                    item = ReadOnlyCanvasNodeItem(
                        node,
                        node_geometry.width,
                        node_geometry.height,
                    )
                    item.setPos(node_geometry.x, node_geometry.y)
                    item.setZValue(1.0)
                    self.scene.addItem(item)

            for edge_geometry in layout.edges:
                edge = edge_geometry.edge
                connection = ReadOnlyCanvasConnectionItem(
                    edge,
                    contract_bezier(
                        source=edge_geometry.source,
                        target=edge_geometry.target,
                    ),
                )
                self.scene.addItem(connection)
            if layout.stages:
                right = max(stage.x + stage.width for stage in layout.stages) + 24.0
                bottom = max(stage.y + stage.height for stage in layout.stages) + 24.0
                self.scene.setSceneRect(0.0, 0.0, right, bottom)
            else:
                self.scene.setSceneRect(0.0, 0.0, 1.0, 1.0)

        def _selection_changed(self) -> None:
            if self._select_node is None:
                return
            selected = self.scene.selectedItems()
            node_id = selected[0].data(0) if selected else None
            if not isinstance(node_id, str):
                node_id = None
            self._select_node(str(node_id) if node_id else None)

else:

    class MaturityCanvasRenderer:
        """Unavailable renderer placeholder for non-GUI imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Qt graphics support is unavailable")


__all__ = ["MaturityCanvasRenderer"]
