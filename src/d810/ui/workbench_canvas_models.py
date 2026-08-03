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


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasEdge:
    source_node_id: str
    source_port_id: str
    target_node_id: str
    target_port_id: str
    kind: str


@dataclasses.dataclass(frozen=True, slots=True)
class MaturityCanvasProjection:
    maturities: tuple[CanvasMaturity, ...]
    nodes: tuple[CanvasNode, ...]
    edges: tuple[CanvasEdge, ...]
    diagnostics: tuple[str, ...]


__all__ = [
    "CanvasEdge",
    "CanvasMaturity",
    "CanvasNode",
    "CanvasPort",
    "MaturityCanvasProjection",
]
