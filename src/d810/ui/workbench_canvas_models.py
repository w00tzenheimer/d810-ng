"""Immutable, Qt-free records for the Workbench maturity canvas."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasMaturity:
    stage_id: str
    label: str
    ordinal: int


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasPort:
    port_id: str
    label: str
    artifact_type: str
    direction: str


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasNode:
    node_id: str
    pass_id: str
    label: str
    maturity: CanvasMaturity
    inputs: tuple[CanvasPort, ...]
    outputs: tuple[CanvasPort, ...]
    state: str
    detail: str
    workflow_stage_id: str = ""
    workflow_stage_label: str = ""
    provenance: str = "recipe"
    recipe_item_id: str | None = None
    execution_maturity_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasEdge:
    source_node_id: str
    source_port_id: str
    target_node_id: str
    target_port_id: str
    kind: str
    relation: str = "contract"


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasSubgraph:
    """Display-only workflow grouping inside one fixed maturity stage."""

    group_id: str
    maturity_id: str
    strategy_stage_id: str
    label: str
    node_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class MaturityCanvasProjection:
    maturities: tuple[CanvasMaturity, ...]
    nodes: tuple[CanvasNode, ...]
    edges: tuple[CanvasEdge, ...]
    diagnostics: tuple[str, ...]
    subgraphs: tuple[CanvasSubgraph, ...] = ()


__all__ = [
    "CanvasEdge",
    "CanvasMaturity",
    "CanvasNode",
    "CanvasPort",
    "CanvasSubgraph",
    "MaturityCanvasProjection",
]
