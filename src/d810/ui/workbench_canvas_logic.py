"""Qt-free projection of a registered recipe onto maturity stages."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping

from d810.ir.maturity import IRMaturity, ir_maturity_rank
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


def _maturity(stage_id: str) -> CanvasMaturity:
    normalized = str(stage_id).strip()
    if normalized == "any":
        return CanvasMaturity("any", "Any maturity", -1)
    boundary = normalized.removeprefix(">=").removeprefix("<=").split("..", 1)[0]
    try:
        maturity = IRMaturity(boundary)
    except ValueError:
        return CanvasMaturity(normalized or "unknown", normalized or "Unknown", 99)
    return CanvasMaturity(
        normalized,
        maturity.value.removeprefix("ir.").replace(".", " ").title(),
        ir_maturity_rank(maturity),
    )


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


def _contract_ports(
    entry: PassCatalogEntry,
) -> tuple[tuple[CanvasPort, ...], tuple[CanvasPort, ...]]:
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


def _diagnostics_by_ordinal(
    draft: PipelineRecipeDraft, validation: RecipeValidation
) -> dict[int, tuple[str, ...]]:
    if validation.draft_id != draft.draft_id or validation.revision != draft.revision:
        return {}
    grouped: dict[int, list[str]] = {}
    for diagnostic in validation.diagnostics:
        if diagnostic.ordinal is not None:
            grouped.setdefault(diagnostic.ordinal, []).append(diagnostic.message)
    return {ordinal: tuple(messages) for ordinal, messages in grouped.items()}


def _case_findings(case: object | None) -> tuple[object, ...]:
    evidence = getattr(case, "evidence", None)
    return tuple(getattr(evidence, "findings", ()) or ())


def linked_case_findings(node: CanvasNode, case: object | None) -> tuple[object, ...]:
    """Return only anchored findings with an exact declared output identity."""
    output_identities = {
        port.label for port in node.outputs if port.artifact_type == "evidence"
    }
    linked = []
    for finding in _case_findings(case):
        finding_id = getattr(finding, "finding_id", None)
        native_ea = getattr(finding, "native_ea", None)
        kind = getattr(getattr(finding, "kind", None), "value", None)
        if (
            isinstance(finding_id, str)
            and finding_id in output_identities
            and isinstance(native_ea, int)
            and native_ea >= 0
            and kind not in {"rejection", "unresolved_question"}
        ):
            linked.append(finding)
    return tuple(linked)


def _overlay_case_evidence(node: CanvasNode, case: object | None) -> CanvasNode:
    if node.state == "disabled":
        return node
    evidence = getattr(case, "evidence", None)
    verdict = getattr(evidence, "verdict", None)
    blocked_obligation = getattr(verdict, "first_blocked_obligation", None)
    blocked = bool(
        isinstance(blocked_obligation, str)
        and blocked_obligation
        and any(
            blocked_obligation in {port.label, port.port_id} for port in node.inputs
        )
    )
    findings = linked_case_findings(node, case)
    detail_lines = [node.detail]
    state = node.state
    if blocked:
        state = "blocked"
        detail_lines.extend(("", f"Blocked obligation: {blocked_obligation}"))
    elif findings and state == "ready":
        state = "evidence_produced"
        detail_lines.extend(("", "Evidence produced:"))
        detail_lines.extend(
            f"{finding.finding_id} @ 0x{finding.native_ea:X}: {finding.summary}"
            for finding in findings
        )
    return dataclasses.replace(node, state=state, detail="\n".join(detail_lines))


def project_maturity_canvas(
    draft: PipelineRecipeDraft,
    catalog: tuple[PassCatalogEntry, ...],
    validation: RecipeValidation,
    case: object | None,
) -> MaturityCanvasProjection:
    """Project recipe contracts without importing Qt, IDA, or live case state."""
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
        if maturity.stage_id != "any" and maturity.ordinal == 99:
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
                    state=(
                        "disabled"
                        if not item.enabled
                        else ("blocked" if node_messages else "ready")
                    ),
                    detail=detail,
                ),
            )
        )

    prepared = [
        (ordinal, _overlay_case_evidence(node, case)) for ordinal, node in prepared
    ]

    producers: dict[str, list[tuple[int, CanvasNode, CanvasPort]]] = {}
    for ordinal, node in prepared:
        for output in node.outputs:
            producers.setdefault(output.port_id, []).append((ordinal, node, output))
    edges: list[CanvasEdge] = []
    carried: list[CanvasNode] = []
    for target_ordinal, target in prepared:
        for input_port in target.inputs:
            matching = producers.get(input_port.port_id, ())
            candidates = [
                candidate for candidate in matching if candidate[0] < target_ordinal
            ]
            if candidates:
                _, source, source_port = candidates[-1]
                if source.maturity.ordinal < target.maturity.ordinal:
                    carrier = CanvasNode(
                        node_id=(
                            f"carry:{source.node_id}:{input_port.port_id}:{target.maturity.stage_id}"
                        ),
                        pass_id="carried-artifact",
                        label=f"Carry {input_port.label}",
                        maturity=target.maturity,
                        inputs=(
                            _artifact_port(
                                input_port.artifact_type, input_port.label, "input"
                            ),
                        ),
                        outputs=(
                            _artifact_port(
                                input_port.artifact_type, input_port.label, "output"
                            ),
                        ),
                        state="carried",
                        detail=f"Carried from {source.maturity.stage_id}.",
                    )
                    carried.append(carrier)
                    edges.extend(
                        (
                            CanvasEdge(
                                source.node_id,
                                source_port.port_id,
                                carrier.node_id,
                                carrier.inputs[0].port_id,
                                input_port.artifact_type,
                            ),
                            CanvasEdge(
                                carrier.node_id,
                                carrier.outputs[0].port_id,
                                target.node_id,
                                input_port.port_id,
                                input_port.artifact_type,
                            ),
                        )
                    )
                else:
                    edges.append(
                        CanvasEdge(
                            source.node_id,
                            source_port.port_id,
                            target.node_id,
                            input_port.port_id,
                            input_port.artifact_type,
                        )
                    )
                continue
            if matching:
                diagnostics.append(
                    f"out-of-order requirement: {input_port.artifact_type}:{input_port.label}"
                )
                if any(candidate[0] == target_ordinal for candidate in matching):
                    diagnostics.append(
                        f"cycle prevented: {target.node_id} -> {target.node_id}"
                    )
                continue
            same_label = [
                output
                for candidates_by_type in producers.values()
                for _, _, output in candidates_by_type
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
    stage_by_id = {node.maturity.stage_id: node.maturity for _, node in prepared}
    maturities = tuple(
        sorted(stage_by_id.values(), key=lambda stage: (stage.ordinal, stage.stage_id))
    )
    return MaturityCanvasProjection(
        maturities=maturities,
        nodes=tuple(node for _, node in prepared) + tuple(carried),
        edges=tuple(edges),
        diagnostics=tuple(dict.fromkeys(diagnostics)),
    )


__all__ = ["linked_case_findings", "project_maturity_canvas"]
