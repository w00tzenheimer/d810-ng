"""Qt-free projection of a registered recipe onto maturity stages."""

from __future__ import annotations

import json
from collections.abc import Mapping

from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeValidation,
)
from d810.ui.workbench_canvas_models import (
    CanvasEdge,
    CanvasMaturity,
    CanvasNode,
    CanvasPort,
    MaturityCanvasProjection,
)


_MATURITY_ORDER = (
    "MMAT_GENERATED",
    "MMAT_PREOPTIMIZED",
    "MMAT_LOCOPT",
    "MMAT_CALLS",
    "MMAT_GLBOPT1",
    "MMAT_GLBOPT2",
    "MMAT_GLBOPT3",
    "MMAT_LVARS",
)
_MATURITY_ORDINAL = {stage_id: ordinal for ordinal, stage_id in enumerate(_MATURITY_ORDER)}


def _maturity(stage_id: str) -> CanvasMaturity:
    normalized = str(stage_id).strip()
    ordinal = _MATURITY_ORDINAL.get(normalized, len(_MATURITY_ORDER))
    label = normalized.removeprefix("MMAT_").replace("_", " ").title()
    return CanvasMaturity(normalized or "unknown", label or "Unknown", ordinal)


def _artifact_port(artifact_type: str, label: str, direction: str) -> CanvasPort:
    return CanvasPort(
        port_id=f"{artifact_type}:{label}",
        label=label,
        artifact_type=artifact_type,
        direction=direction,
    )


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str) and item)


def _contract_ports(entry: PassCatalogEntry) -> tuple[tuple[CanvasPort, ...], tuple[CanvasPort, ...]]:
    try:
        payload = json.loads(entry.contract_json)
    except (TypeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, Mapping):
        pipeline = _artifact_port("pipeline", "pipeline", "input")
        return (pipeline,), (_artifact_port("pipeline", "pipeline", "output"),)

    requires = payload.get("requires")
    outputs = payload.get("outputs")
    runtime = payload.get("runtime")
    if not isinstance(requires, Mapping) or not isinstance(outputs, Mapping):
        pipeline = _artifact_port("pipeline", "pipeline", "input")
        return (pipeline,), (_artifact_port("pipeline", "pipeline", "output"),)

    facts = requires.get("facts")
    facts_required = facts.get("required") if isinstance(facts, Mapping) else ()
    inputs = tuple(
        _artifact_port(artifact_type, name, "input")
        for artifact_type, names in (
            ("capability", requires.get("capabilities")),
            ("analysis", requires.get("analyses")),
            ("evidence", requires.get("evidence")),
            ("fact", facts_required),
        )
        for name in _strings(names)
    )
    runtime_analyses: object = ()
    if isinstance(runtime, Mapping):
        analyses = runtime.get("analyses")
        if isinstance(analyses, Mapping):
            runtime_analyses = analyses.get("provided")
    produced = tuple(
        _artifact_port(artifact_type, name, "output")
        for artifact_type, names in (
            ("analysis", runtime_analyses),
            ("evidence", outputs.get("evidence")),
            ("fact", outputs.get("facts")),
        )
        for name in _strings(names)
    )
    return inputs, produced


def _diagnostics_by_ordinal(draft: PipelineRecipeDraft, validation: RecipeValidation) -> dict[int, tuple[str, ...]]:
    if validation.draft_id != draft.draft_id or validation.revision != draft.revision:
        return {}
    grouped: dict[int, list[str]] = {}
    for diagnostic in validation.diagnostics:
        if diagnostic.ordinal is not None:
            grouped.setdefault(diagnostic.ordinal, []).append(diagnostic.message)
    return {ordinal: tuple(messages) for ordinal, messages in grouped.items()}


def project_maturity_canvas(
    draft: PipelineRecipeDraft,
    catalog: tuple[PassCatalogEntry, ...],
    validation: RecipeValidation,
    case: object | None,
) -> MaturityCanvasProjection:
    """Project recipe contracts without importing Qt, IDA, or live case state."""
    del case
    entries = {entry.pass_id: entry for entry in catalog}
    validation_messages = _diagnostics_by_ordinal(draft, validation)
    prepared: list[tuple[int, CanvasNode]] = []
    diagnostics: list[str] = []
    for ordinal, item in enumerate(draft.passes):
        entry = entries.get(item.pass_id)
        if entry is None:
            maturity = _maturity("unknown")
            inputs, outputs = (_artifact_port("pipeline", "pipeline", "input"),), ()
            label = item.pass_id
            detail = f"Pass {item.pass_id!r} is not in the current catalog."
            diagnostics.append(f"unknown pass: {item.pass_id}")
        else:
            maturity = _maturity(entry.maturity)
            inputs, outputs = _contract_ports(entry)
            label = entry.display_name
            detail = entry.contract_json
        node_messages = list(validation_messages.get(ordinal, ()))
        if maturity.stage_id not in _MATURITY_ORDINAL:
            node_messages.append(f"unknown maturity: {maturity.stage_id}")
        if node_messages:
            diagnostics.extend(node_messages)
        prepared.append(
            (
                ordinal,
                CanvasNode(
                    node_id=item.item_id,
                    pass_id=item.pass_id,
                    label=label,
                    maturity=maturity,
                    inputs=inputs,
                    outputs=outputs,
                    state="disabled" if not item.enabled else ("blocked" if node_messages else "ready"),
                    detail=detail,
                ),
            )
        )

    producers: dict[str, list[CanvasNode]] = {}
    for _, node in prepared:
        for output in node.outputs:
            producers.setdefault(output.port_id, []).append(node)
    edges: list[CanvasEdge] = []
    carried: list[CanvasNode] = []
    for _, target in prepared:
        for input_port in target.inputs:
            candidates = producers.get(input_port.port_id, ())
            if candidates:
                source = candidates[0]
                edges.append(
                    CanvasEdge(
                        source_node_id=source.node_id,
                        source_port_id=input_port.port_id,
                        target_node_id=target.node_id,
                        target_port_id=input_port.port_id,
                        kind=input_port.artifact_type,
                    )
                )
                if source.maturity.ordinal < target.maturity.ordinal:
                    carried.append(
                        CanvasNode(
                            node_id=(f"carry:{source.node_id}:{input_port.port_id}:{target.maturity.stage_id}"),
                            pass_id="carried-artifact",
                            label=f"Carry {input_port.label}",
                            maturity=target.maturity,
                            inputs=(_artifact_port(input_port.artifact_type, input_port.label, "input"),),
                            outputs=(_artifact_port(input_port.artifact_type, input_port.label, "output"),),
                            state="carried",
                            detail=f"Carried from {source.maturity.stage_id}.",
                        )
                    )
                continue
            same_label = [
                output
                for candidate in producers.values()
                for producer in candidate
                for output in producer.outputs
                if output.label == input_port.label
            ]
            if same_label:
                diagnostics.append(
                    f"incompatible artifact: {input_port.artifact_type}:{input_port.label}"
                )
            else:
                diagnostics.append(
                    f"unresolved requirement: {input_port.artifact_type}:{input_port.label}"
                )

    adjacency: dict[str, list[str]] = {node.node_id: [] for _, node in prepared}
    for edge in edges:
        if edge.source_node_id != edge.target_node_id:
            adjacency[edge.source_node_id].append(edge.target_node_id)
    for start in adjacency:
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        while stack:
            current, path = stack.pop()
            for next_node in adjacency[current]:
                if next_node == start and len(path) > 1:
                    diagnostics.append("cycle: " + " -> ".join((*path, start)))
                    stack.clear()
                    break
                if next_node not in path:
                    stack.append((next_node, [*path, next_node]))

    stage_by_id = {node.maturity.stage_id: node.maturity for _, node in prepared}
    maturities = tuple(sorted(stage_by_id.values(), key=lambda stage: (stage.ordinal, stage.stage_id)))
    return MaturityCanvasProjection(
        maturities=maturities,
        nodes=tuple(node for _, node in prepared) + tuple(carried),
        edges=tuple(edges),
        diagnostics=tuple(dict.fromkeys(diagnostics)),
    )


__all__ = ["project_maturity_canvas"]
