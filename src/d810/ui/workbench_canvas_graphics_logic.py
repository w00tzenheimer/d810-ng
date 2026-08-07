"""Qt-free geometry and compact presentation for the Maturity Canvas."""

from __future__ import annotations

import dataclasses

from d810.ui.workbench_canvas_models import CanvasNode


_MIN_CANVAS_SCALE = 0.30
_MAX_CANVAS_SCALE = 3.20


@dataclasses.dataclass(frozen=True, slots=True)
class BezierControlPoints:
    """The four points defining one contract-edge cubic Bezier curve."""

    start: tuple[float, float]
    control_1: tuple[float, float]
    control_2: tuple[float, float]
    end: tuple[float, float]


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasNodePresentation:
    """Small semantic distinctions that remain independent of the IDA theme."""

    badge: str
    read_only: bool


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasEdgePresentation:
    """The relationship-specific visual policy for an automatic edge."""

    label: str
    dashed: bool
    uses_ports: bool


def clamp_canvas_scale(current: float, factor: float) -> float:
    """Apply an interaction scale factor without losing the workspace."""

    return min(_MAX_CANVAS_SCALE, max(_MIN_CANVAS_SCALE, current * factor))


def contract_bezier(
    *,
    source: tuple[float, float],
    target: tuple[float, float],
) -> BezierControlPoints:
    """Return a left-to-right readable contract edge between typed ports."""

    span = max(48.0, abs(target[0] - source[0]) * 0.45)
    return BezierControlPoints(
        start=source,
        control_1=(source[0] + span, source[1]),
        control_2=(target[0] - span, target[1]),
        end=target,
    )


def node_presentation(provenance: str) -> CanvasNodePresentation:
    """Describe a card without pretending all nodes are editable recipe items."""

    normalized = str(provenance).strip().lower()
    if normalized == "system":
        return CanvasNodePresentation("Observed", True)
    if normalized == "evidence":
        return CanvasNodePresentation("Evidence", True)
    return CanvasNodePresentation("Recipe", False)


def edge_presentation(relation: str) -> CanvasEdgePresentation:
    """Keep typed contract flow visually separate from recipe execution order."""

    if str(relation).strip().lower() == "sequence":
        return CanvasEdgePresentation("Recipe execution order", True, False)
    return CanvasEdgePresentation("Contract data flow", False, True)


def node_card_lines(node: CanvasNode) -> tuple[str, str, str, str]:
    """Return compact semantic card text without exposing raw contract JSON."""

    return (
        node.label,
        node.pass_id,
        f"{node.state.replace('_', ' ')} | {node.maturity.label}",
        f"in {len(node.inputs)} | out {len(node.outputs)}",
    )


__all__ = [
    "BezierControlPoints",
    "CanvasEdgePresentation",
    "CanvasNodePresentation",
    "clamp_canvas_scale",
    "contract_bezier",
    "edge_presentation",
    "node_card_lines",
    "node_presentation",
]
