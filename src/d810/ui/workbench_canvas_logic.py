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
    CanvasSubgraph,
    MaturityCanvasProjection,
)
from d810.ui.workbench_recipe_logic import workflow_stage_label


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


def typed_port_lines(node: CanvasNode, direction: str) -> tuple[str, ...]:
    """Render one direction of a node's typed contract ports for inspection."""
    if direction == "input":
        ports = node.inputs
    elif direction == "output":
        ports = node.outputs
    else:
        raise ValueError(f"unknown canvas port direction: {direction!r}")
    return tuple(f"{port.artifact_type}: {port.label}" for port in ports)


def _contract_payload(detail: str) -> Mapping[str, object]:
    """Read the canonical contract before optional evidence annotations."""

    contract, _separator, _annotation = str(detail).partition("\n")
    try:
        decoded = json.loads(contract)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def _contract_runtime_value(
    payload: Mapping[str, object],
    name: str,
    default: str,
) -> str:
    runtime = payload.get("runtime")
    if not isinstance(runtime, Mapping):
        return default
    value = runtime.get(name)
    return str(value) if isinstance(value, str) and value else default


def _contract_safety_policy(payload: Mapping[str, object]) -> str:
    runtime = payload.get("runtime")
    safety = runtime.get("safety") if isinstance(runtime, Mapping) else None
    if isinstance(safety, Mapping):
        policy = safety.get("policy")
        if isinstance(policy, str) and policy:
            return policy
    policy = payload.get("safety_policy")
    return str(policy) if isinstance(policy, str) and policy else "default"


def _option_summary(options: Mapping[str, object]) -> str:
    if not options:
        return "None"
    names = tuple(sorted(str(name) for name in options))
    visible = ", ".join(names[:4])
    if len(names) > 4:
        visible += f", +{len(names) - 4} more"
    return f"{len(names)} configured ({visible})"


def compact_canvas_node_inspection_lines(
    node: CanvasNode,
    options: Mapping[str, object],
    evidence_references: tuple[str, ...],
    *,
    include_raw_contract: bool = False,
) -> tuple[str, ...]:
    """Return a readable node card; raw contracts remain an explicit detail."""

    payload = _contract_payload(node.detail)
    scope = _contract_runtime_value(payload, "scope", "function")
    backend_route = _contract_runtime_value(payload, "backend_route", "default")
    purpose = node.workflow_stage_label or "Registered pipeline pass"
    lines = (
        f"{node.label} ({node.pass_id})",
        f"Purpose: {purpose}",
        f"Maturity: {node.maturity.label}",
        f"State: {node.state.replace('_', ' ')}",
        f"Execution: {scope} via {backend_route}",
        f"Safety: {_contract_safety_policy(payload)}",
        "",
        "Inputs",
        *(typed_port_lines(node, "input") or ("None",)),
        "",
        "Outputs",
        *(typed_port_lines(node, "output") or ("None",)),
        "",
        "Options",
        _option_summary(options),
        "",
        "Linked evidence",
        *(evidence_references or ("None",)),
    )
    if include_raw_contract:
        return (*lines, "", "Raw contract", node.detail)
    return lines


def _pass_contract_identity(finding: object) -> tuple[str, str] | None:
    """Return explicit producer provenance retained by the case producer.

    Case finding identifiers describe rows, not pass outputs. The canvas may
    only attribute evidence to a node when the typed detail retained by the
    case producer names both the producer pass and its declared token.
    """
    detail = getattr(finding, "detail", None)
    if not isinstance(detail, str):
        return None
    try:
        decoded = json.loads(detail)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, Mapping):
        return None
    pass_id = decoded.get("pass_id")
    evidence_token = decoded.get("evidence_token")
    if not isinstance(pass_id, str) or not pass_id.strip():
        return None
    if not isinstance(evidence_token, str) or not evidence_token.strip():
        return None
    return pass_id, evidence_token


def _pass_contract_maturity(finding: object) -> str | None:
    """Return the producer maturity retained in a typed pass receipt."""
    detail = getattr(finding, "detail", None)
    if not isinstance(detail, str):
        return None
    try:
        decoded = json.loads(detail)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, Mapping):
        return None
    maturity = decoded.get("maturity")
    if not isinstance(maturity, str) or not maturity.strip():
        return None
    return maturity


def linked_case_findings(node: CanvasNode, case: object | None) -> tuple[object, ...]:
    """Return only anchored receipts from this node's declared evidence port."""
    output_identities = {
        port.label for port in node.outputs if port.artifact_type == "evidence"
    }
    linked = []
    for finding in _case_findings(case):
        identity = _pass_contract_identity(finding)
        native_ea = getattr(finding, "native_ea", None)
        kind = getattr(getattr(finding, "kind", None), "value", None)
        if (
            identity is not None
            and identity[0] == node.pass_id
            and identity[1] in output_identities
            and isinstance(native_ea, int)
            and native_ea >= 0
            and kind not in {"rejection", "unresolved_question"}
        ):
            linked.append(finding)
    return tuple(linked)


def _automatic_evidence_nodes(
    case: object | None,
    recipe_nodes: tuple[CanvasNode, ...],
) -> tuple[CanvasNode, ...]:
    """Project observed hook outputs that intentionally are not recipe passes.

    The frontend normalization pipeline runs before the editable config-v2
    recipe. Its receipts must remain visible and connectable, but must never
    appear editable or selectable from the registered-pass palette.
    """
    represented_outputs = {
        (node.pass_id, port.label)
        for node in recipe_nodes
        for port in node.outputs
        if port.artifact_type == "evidence"
    }
    observed: dict[tuple[str, str, str], list[object]] = {}
    for finding in _case_findings(case):
        identity = _pass_contract_identity(finding)
        maturity_id = _pass_contract_maturity(finding)
        kind = getattr(getattr(finding, "kind", None), "value", None)
        native_ea = getattr(finding, "native_ea", None)
        if (
            identity is None
            or maturity_id is None
            or identity in represented_outputs
            or kind in {"rejection", "unresolved_question"}
            or not isinstance(native_ea, int)
            or native_ea < 0
        ):
            continue
        observed.setdefault((identity[0], identity[1], maturity_id), []).append(finding)

    nodes: list[CanvasNode] = []
    for (pass_id, evidence_token, maturity_id), findings in sorted(observed.items()):
        maturity = _maturity(maturity_id)
        nodes.append(
            CanvasNode(
                node_id=(
                    f"automatic:{maturity.stage_id}:{pass_id}:{evidence_token}"
                ),
                pass_id=pass_id,
                label=pass_id.replace("_", " ").replace("-", " ").title(),
                maturity=maturity,
                inputs=(),
                outputs=(_artifact_port("evidence", evidence_token, "output"),),
                state="ready",
                detail=(
                    "Automatic hook evidence producer (read-only). "
                    f"{len(findings)} anchored receipt(s) were retained by diagnostics."
                ),
                workflow_stage_id="automatic-hook-evidence",
                workflow_stage_label="Automatic hook evidence",
                provenance="system",
                execution_maturity_ids=(maturity.stage_id,),
            )
        )
    return tuple(nodes)


def _case_result_nodes(
    case: object | None,
    recipe_nodes: tuple[CanvasNode, ...],
) -> dict[str, tuple[CanvasNode, ...]]:
    """Return read-only cards for receipts produced by one recipe item.

    A recipe item retains ownership of its own configuration. A receipt is a
    distinct historical observation, even when it was produced by that item.
    This prevents the workspace from representing a pass option and a finding
    as the same editable node.
    """

    result: dict[str, tuple[CanvasNode, ...]] = {}
    for recipe_node in recipe_nodes:
        cards: list[CanvasNode] = []
        for finding in linked_case_findings(recipe_node, case):
            finding_id = str(getattr(finding, "finding_id", "finding"))
            native_ea = int(getattr(finding, "native_ea", 0))
            receipt_maturity = _pass_contract_maturity(finding)
            maturity = _maturity(receipt_maturity or recipe_node.maturity.stage_id)
            cards.append(
                CanvasNode(
                    node_id=f"evidence:{recipe_node.node_id}:{finding_id}",
                    pass_id="case-evidence",
                    label=f"Evidence: {getattr(finding, 'summary', finding_id)}",
                    maturity=maturity,
                    inputs=tuple(
                        port
                        for port in recipe_node.outputs
                        if port.artifact_type == "evidence"
                    )[:1],
                    outputs=(),
                    state="evidence_produced",
                    detail=(
                        f"Observed receipt: {finding_id} @ 0x{native_ea:X}.\n"
                        f"{getattr(finding, 'summary', '')}"
                    ),
                    workflow_stage_id="observed-evidence",
                    workflow_stage_label="Observed evidence",
                    provenance="evidence",
                    execution_maturity_ids=(maturity.stage_id,),
                )
            )
        if cards:
            result[recipe_node.node_id] = tuple(cards)
    return result


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


def _subgraphs(
    nodes: tuple[CanvasNode, ...],
) -> tuple[CanvasSubgraph, ...]:
    """Group projected nodes without changing their recipes, edges, or order."""
    memberships: dict[tuple[str, str], list[str]] = {}
    labels: dict[tuple[str, str], str] = {}
    ordering: dict[tuple[str, str], tuple[int, int, str]] = {}
    for node_order, node in enumerate(nodes):
        key = (node.maturity.stage_id, node.workflow_stage_id)
        memberships.setdefault(key, []).append(node.node_id)
        labels.setdefault(key, node.workflow_stage_label)
        ordering.setdefault(
            key,
            (node.maturity.ordinal, node_order, node.workflow_stage_id),
        )
    return tuple(
        CanvasSubgraph(
            group_id=f"{maturity_id}:{strategy_stage_id}",
            maturity_id=maturity_id,
            strategy_stage_id=strategy_stage_id,
            label=labels[(maturity_id, strategy_stage_id)],
            node_ids=tuple(node_ids),
        )
        for (maturity_id, strategy_stage_id), node_ids in sorted(
            memberships.items(),
            key=lambda item: ordering[item[0]],
        )
    )


def project_maturity_canvas(
    draft: PipelineRecipeDraft,
    catalog: tuple[PassCatalogEntry, ...],
    validation: RecipeValidation,
    case: object | None,
) -> MaturityCanvasProjection:
    """Project recipe contracts without importing Qt, IDA, or live case state."""
    entries = {entry.pass_id: entry for entry in catalog}
    validation_messages = _diagnostics_by_ordinal(draft, validation)
    recipe_prepared: list[tuple[int, CanvasNode]] = []
    diagnostics: list[str] = []
    for ordinal, item in enumerate(draft.passes):
        entry = entries.get(item.pass_id)
        if entry is None:
            maturity = _maturity("unknown")
            inputs, outputs = (_artifact_port("pipeline", "pipeline", "input"),), ()
            label = item.pass_id
            detail = f"Pass {item.pass_id!r} is not in the current catalog."
            workflow_stage_id = "unknown"
            workflow_label = "Unknown workflow stage"
            diagnostics.append(f"unknown pass: {item.pass_id}")
        else:
            maturity = _maturity(entry.maturity)
            inputs, outputs = _contract_ports(entry)
            label = entry.display_name
            detail = entry.contract_json
            workflow_stage_id = entry.workflow_stage.value
            workflow_label = workflow_stage_label(entry.workflow_stage)
        node_messages = list(validation_messages.get(ordinal, ()))
        if maturity.stage_id != "any" and maturity.ordinal == 99:
            node_messages.append(f"unknown maturity: {maturity.stage_id}")
        if node_messages:
            diagnostics.extend(node_messages)
        recipe_prepared.append(
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
                    workflow_stage_id=workflow_stage_id,
                    workflow_stage_label=workflow_label,
                    provenance="recipe",
                    recipe_item_id=item.item_id,
                    execution_maturity_ids=(maturity.stage_id,),
                ),
            )
        )

    automatic_nodes = _automatic_evidence_nodes(
        case,
        tuple(node for _, node in recipe_prepared),
    )
    recipe_nodes = tuple(
        _overlay_case_evidence(node, case) for _, node in recipe_prepared
    )
    evidence_nodes = _case_result_nodes(case, recipe_nodes)
    prepared: list[tuple[int, CanvasNode]] = [
        (ordinal - len(automatic_nodes), _overlay_case_evidence(node, case))
        for ordinal, node in enumerate(automatic_nodes)
    ]
    for ordinal, recipe_node in enumerate(recipe_nodes):
        prepared.append((ordinal * 2, recipe_node))
        prepared.extend(
            (ordinal * 2 + 1, evidence_node)
            for evidence_node in evidence_nodes.get(recipe_node.node_id, ())
        )

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
                        workflow_stage_id="carried-artifacts",
                        workflow_stage_label="Carried artifacts",
                        provenance="system",
                        execution_maturity_ids=(target.maturity.stage_id,),
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
    ordered_recipe_nodes = tuple(
        node
        for _ordinal, node in sorted(prepared, key=lambda item: item[0])
        if node.provenance == "recipe" and node.state != "disabled"
    )
    for source, target in zip(ordered_recipe_nodes, ordered_recipe_nodes[1:]):
        edges.append(
            CanvasEdge(
                source_node_id=source.node_id,
                source_port_id=source.outputs[0].port_id if source.outputs else "",
                target_node_id=target.node_id,
                target_port_id=target.inputs[0].port_id if target.inputs else "",
                kind="sequence",
                relation="sequence",
            )
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
        subgraphs=_subgraphs(tuple(node for _, node in prepared) + tuple(carried)),
    )


__all__ = [
    "compact_canvas_node_inspection_lines",
    "linked_case_findings",
    "project_maturity_canvas",
    "typed_port_lines",
]
