"""Pure graph projections for normalized diagnostics evidence."""

from __future__ import annotations

import re
from pathlib import Path

from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphContext,
    DiagnosticGraphEdge,
    DiagnosticGraphGroup,
    DiagnosticGraphKind,
    DiagnosticGraphNode,
    DiagnosticGraphProjectionRequest,
    DiagnosticRecordRef,
    anchored_block_model_id,
    record_ref,
)
from d810.diagnostics.workbench_models import DiagnosticField, DiagnosticRecord


_BLOCK_REF = re.compile(r"\bblk(?P<serial>\d+)@(?P<ea>0[xX][0-9A-Fa-f]+)\b")


def _field_map(record: DiagnosticRecord) -> dict[str, DiagnosticField]:
    return {field.name: field for field in record.fields}


def _anchored_block(value: object) -> tuple[int, int] | None:
    match = _BLOCK_REF.fullmatch(str(value or "").strip())
    if match is None:
        return None
    return int(match.group("serial")), int(match.group("ea"), 16)


def _block_refs(value: object) -> tuple[tuple[int, int], ...]:
    return tuple(
        (int(match.group("serial")), int(match.group("ea"), 16))
        for match in _BLOCK_REF.finditer(str(value or ""))
    )


def _context_status(
    context: DiagnosticGraphContext,
    warnings: tuple[str, ...],
    title: str,
) -> str:
    database_name = Path(context.database_path).name or context.database_path
    function = (
        f"{context.function_name}@0x{context.function_ea:X}"
        if context.function_name
        else f"0x{context.function_ea:X}"
    )
    status = f"{title} | {database_name} | snapshot {context.snapshot_id} | {function}"
    return f"{status} | warnings: {len(warnings)}" if warnings else status


def _node_hint(record: DiagnosticRecord) -> tuple[tuple[str, str], ...]:
    return (
        *(tuple((field.name, field.display) for field in record.fields)),
        ("source table", record.source_table),
        ("snapshot", str(record.snapshot_id)),
        ("record", str(record.ordinal)),
    )


def project_block_cfg(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph:
    """Project fully anchored block records into a strict CFG graph."""

    context = request.context
    if context.kind is not DiagnosticGraphKind.BLOCK_CFG:
        raise ValueError(f"Block CFG request has kind: {context.kind.value}")

    warnings: list[str] = []
    candidates: list[tuple[str, int, int, DiagnosticRecord]] = []
    for record in request.primary_records:
        if record.snapshot_id != context.snapshot_id:
            warnings.append(
                f"Record snapshot mismatch: {record.source_table}#{record.ordinal}"
            )
            continue
        if record.source_table != "blocks":
            continue
        serial_field = _field_map(record).get("serial")
        identity = _anchored_block(None if serial_field is None else serial_field.value)
        if identity is None:
            warnings.append("Block record omitted: EA anchor unavailable")
            continue
        serial, anchor_ea = identity
        model_id = anchored_block_model_id(serial, anchor_ea)
        candidates.append((model_id, serial, anchor_ea, record))

    candidates.sort(key=lambda item: (item[0], item[3].ordinal))
    node_by_model_id: dict[str, DiagnosticGraphNode] = {}
    source_records: dict[str, DiagnosticRecord] = {}
    for model_id, _, anchor_ea, record in candidates:
        if model_id in node_by_model_id:
            warnings.append(f"Duplicate block record omitted: {model_id.removeprefix('block:')}")
            continue
        node_by_model_id[model_id] = DiagnosticGraphNode(
            model_id=model_id,
            label=model_id.removeprefix("block:"),
            category="block",
            anchor_ea=anchor_ea,
            hint_fields=_node_hint(record),
            record_refs=(record_ref(record),),
        )
        source_records[model_id] = record

    edges: list[DiagnosticGraphEdge] = []
    edge_ids: set[str] = set()
    for source_model_id in sorted(source_records):
        record = source_records[source_model_id]
        succs_field = _field_map(record).get("succs")
        for serial, anchor_ea in _block_refs(
            None if succs_field is None else succs_field.value
        ):
            target_model_id = anchored_block_model_id(serial, anchor_ea)
            if target_model_id not in node_by_model_id:
                warnings.append(
                    "Dangling CFG edge omitted: "
                    f"{source_model_id.removeprefix('block:')} -> "
                    f"{target_model_id.removeprefix('block:')}"
                )
                continue
            edge_id = f"cfg:{source_model_id}->{target_model_id}"
            if edge_id in edge_ids:
                continue
            edge_ids.add(edge_id)
            edges.append(
                DiagnosticGraphEdge(
                    model_id=edge_id,
                    source_model_id=source_model_id,
                    target_model_id=target_model_id,
                    category="cfg",
                    label=None,
                    hint_fields=(
                        ("source", source_model_id.removeprefix("block:")),
                        ("target", target_model_id.removeprefix("block:")),
                    ),
                    record_refs=(record_ref(record),),
                )
            )

    if not node_by_model_id:
        warnings.append("No trustworthy Block CFG records for this context")
    ordered_warnings = tuple(warnings)
    return DiagnosticGraph(
        context=context,
        nodes=tuple(node_by_model_id[model_id] for model_id in sorted(node_by_model_id)),
        edges=tuple(sorted(edges, key=lambda edge: edge.model_id)),
        expanded_group=None,
        warnings=ordered_warnings,
        status=_context_status(context, ordered_warnings, "Block CFG"),
    )


def _state_model_id(
    fields: dict[str, DiagnosticField],
    prefix: str = "state",
) -> str | None:
    i64 = fields.get(f"{prefix}_i64")
    if i64 is not None and i64.value is not None:
        return f"state:0x{int(i64.value):X}"
    value = fields.get(f"{prefix}_hex")
    if value is None or not str(value.value or "").strip():
        return None
    text = str(value.value).strip()
    try:
        return f"state:0x{int(text, 0):X}"
    except ValueError:
        return f"state:{text.upper()}"


def _state_label(
    model_id: str,
    entry_block: str | None,
    classification: str | None,
) -> str:
    parts = [model_id.removeprefix("state:")]
    if entry_block:
        parts.append(entry_block)
    if classification:
        parts.append(classification)
    return " | ".join(parts)


def _state_node_hint(
    record: DiagnosticRecord,
    owned_blocks: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    owned = ", ".join(owned_blocks) if owned_blocks else "none recorded"
    return (*_node_hint(record), ("owned blocks", owned))


def _owned_block_records(
    request: DiagnosticGraphProjectionRequest,
    member_node_ids: tuple[str, ...],
    warnings: list[str],
    state_model_id: str,
) -> tuple[tuple[DiagnosticGraphNode, DiagnosticRecord], ...]:
    records_by_id: dict[str, tuple[DiagnosticGraphNode, DiagnosticRecord]] = {}
    for record in request.block_records:
        if record.snapshot_id != request.context.snapshot_id:
            continue
        if record.source_table != "blocks":
            continue
        serial_field = _field_map(record).get("serial")
        identity = _anchored_block(None if serial_field is None else serial_field.value)
        if identity is None:
            continue
        serial, anchor_ea = identity
        model_id = anchored_block_model_id(serial, anchor_ea)
        records_by_id.setdefault(
            model_id,
            (
                DiagnosticGraphNode(
                    model_id=model_id,
                    label=model_id.removeprefix("block:"),
                    category="block",
                    anchor_ea=anchor_ea,
                    hint_fields=_node_hint(record),
                    record_refs=(record_ref(record),),
                ),
                record,
            ),
        )

    result: list[tuple[DiagnosticGraphNode, DiagnosticRecord]] = []
    for member_id in member_node_ids:
        candidate = records_by_id.get(member_id)
        if candidate is None:
            warnings.append(
                "Owned block evidence unavailable for "
                f"{state_model_id}: {member_id.removeprefix('block:')}"
            )
            continue
        result.append(candidate)
    return tuple(result)


def project_state_machine(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph:
    """Project recovered state/transition evidence and one owned-block expansion."""

    context = request.context
    if context.kind is not DiagnosticGraphKind.STATE_MACHINE:
        raise ValueError(f"State Machine request has kind: {context.kind.value}")

    warnings: list[str] = []
    state_records: dict[str, DiagnosticRecord] = {}
    state_entries: dict[str, str | None] = {}
    state_anchors: dict[str, int | None] = {}
    ownership: dict[str, list[tuple[str, DiagnosticRecord]]] = {}
    edge_records: list[DiagnosticRecord] = []

    for record in request.primary_records:
        if record.snapshot_id != context.snapshot_id:
            warnings.append(
                f"Record snapshot mismatch: {record.source_table}#{record.ordinal}"
            )
            continue
        warnings.extend(record.warnings)
        fields = _field_map(record)
        if record.source_table == "state_cfg_nodes":
            state_model_id = _state_model_id(fields)
            if state_model_id is None:
                warnings.append("State record omitted: state identity unavailable")
                continue
            if state_model_id in state_records:
                warnings.append(f"Duplicate state record omitted: {state_model_id}")
                continue
            entry_field = fields.get("entry_block")
            entry = None if entry_field is None else str(entry_field.value or "") or None
            state_records[state_model_id] = record
            state_entries[state_model_id] = entry
            entry_identity = _anchored_block(None if entry_field is None else entry_field.value)
            state_anchors[state_model_id] = (
                None if entry_identity is None else entry_identity[1]
            )
            ownership[state_model_id] = []
        elif record.source_table == "state_cfg_node_blocks":
            if str(fields.get("role", DiagnosticField("role", "", "")).value) != "owned":
                continue
            state_model_id = _state_model_id(fields)
            block_field = fields.get("block_serial")
            identity = _anchored_block(None if block_field is None else block_field.value)
            if state_model_id is None or identity is None:
                continue
            serial, anchor_ea = identity
            ownership.setdefault(state_model_id, []).append(
                (anchored_block_model_id(serial, anchor_ea), record)
            )
        elif record.source_table == "state_cfg_edges":
            edge_records.append(record)

    state_refs: dict[str, list[DiagnosticRecordRef]] = {
        model_id: [record_ref(record)] for model_id, record in state_records.items()
    }
    for state_model_id, owned_records in ownership.items():
        if state_model_id not in state_refs:
            continue
        state_refs[state_model_id].extend(record_ref(record) for _, record in owned_records)

    nodes_by_id: dict[str, DiagnosticGraphNode] = {}
    for state_model_id in sorted(state_records):
        record = state_records[state_model_id]
        fields = _field_map(record)
        owned_blocks = tuple(
            member_id.removeprefix("block:")
            for member_id, _ in ownership.get(state_model_id, ())
        )
        classification = fields.get("classification")
        nodes_by_id[state_model_id] = DiagnosticGraphNode(
            model_id=state_model_id,
            label=_state_label(
                state_model_id,
                state_entries[state_model_id],
                None if classification is None else str(classification.value or ""),
            ),
            category="state",
            anchor_ea=state_anchors[state_model_id],
            hint_fields=_state_node_hint(record, tuple(sorted(owned_blocks))),
            record_refs=tuple(state_refs[state_model_id]),
            expandable=bool(owned_blocks),
        )

    edges: list[DiagnosticGraphEdge] = []
    edge_ids: set[str] = set()
    for record in sorted(edge_records, key=lambda item: item.ordinal):
        fields = _field_map(record)
        source_model_id = _state_model_id(fields, "source_state")
        if source_model_id not in nodes_by_id:
            warnings.append("State transition omitted: source state unavailable")
            continue
        target_model_id = _state_model_id(fields, "target_state")
        kind_field = fields.get("edge_kind")
        edge_kind = "" if kind_field is None else str(kind_field.value or "")
        edge_id_field = fields.get("edge_id")
        edge_suffix = (
            str(record.ordinal)
            if edge_id_field is None or edge_id_field.value is None
            else str(edge_id_field.value)
        )
        if target_model_id is None and edge_kind in {
            "CONDITIONAL_RETURN",
            "EXIT_ROUTINE",
        }:
            target_model_id = f"terminal:{edge_suffix}"
            nodes_by_id.setdefault(
                target_model_id,
                DiagnosticGraphNode(
                    model_id=target_model_id,
                    label=edge_kind,
                    category="terminal",
                    anchor_ea=None,
                    hint_fields=_node_hint(record),
                    record_refs=(record_ref(record),),
                ),
            )
        elif target_model_id not in nodes_by_id:
            warnings.append("State transition omitted: target state unavailable")
            continue
        state_refs[source_model_id].append(record_ref(record))
        edge_model_id = f"state_edge:{edge_suffix}"
        if edge_model_id in edge_ids:
            warnings.append(f"Duplicate state transition omitted: {edge_model_id}")
            continue
        edge_ids.add(edge_model_id)
        edges.append(
            DiagnosticGraphEdge(
                model_id=edge_model_id,
                source_model_id=source_model_id,
                target_model_id=target_model_id,
                category="state_transition",
                label=edge_kind or None,
                hint_fields=_node_hint(record),
                record_refs=(record_ref(record),),
            )
        )

    for state_model_id, node in tuple(nodes_by_id.items()):
        if node.category != "state":
            continue
        nodes_by_id[state_model_id] = DiagnosticGraphNode(
            model_id=node.model_id,
            label=node.label,
            category=node.category,
            anchor_ea=node.anchor_ea,
            hint_fields=node.hint_fields,
            record_refs=tuple(state_refs[state_model_id]),
            expandable=node.expandable,
        )

    expanded_group: DiagnosticGraphGroup | None = None
    expanded_state_model_id = request.expanded_state_model_id
    if expanded_state_model_id is not None:
        expanded_state = nodes_by_id.get(expanded_state_model_id)
        if expanded_state is None or expanded_state.category != "state":
            warnings.append(f"Expanded state unavailable: {expanded_state_model_id}")
        else:
            member_ids = tuple(
                sorted(member_id for member_id, _ in ownership.get(expanded_state_model_id, ()))
            )
            owned_blocks = _owned_block_records(
                request, member_ids, warnings, expanded_state_model_id
            )
            for node, _ in owned_blocks:
                nodes_by_id[node.model_id] = node
            realized_member_ids = tuple(node.model_id for node, _ in owned_blocks)
            if realized_member_ids:
                expanded_group = DiagnosticGraphGroup(
                    model_id=f"group:{expanded_state_model_id}",
                    label=f"{expanded_state.label} owned blocks",
                    member_node_ids=realized_member_ids,
                    record_refs=tuple(
                        record_ref(record)
                        for member_id, record in ownership.get(expanded_state_model_id, ())
                        if member_id in realized_member_ids
                    ),
                    anchor_ea=expanded_state.anchor_ea,
                )
                block_records = {node.model_id: record for node, record in owned_blocks}
                for source_model_id, record in sorted(block_records.items()):
                    succs_field = _field_map(record).get("succs")
                    for serial, anchor_ea in _block_refs(
                        None if succs_field is None else succs_field.value
                    ):
                        target_model_id = anchored_block_model_id(serial, anchor_ea)
                        if target_model_id not in realized_member_ids:
                            continue
                        edge_model_id = f"cfg:{source_model_id}->{target_model_id}"
                        if edge_model_id in edge_ids:
                            continue
                        edge_ids.add(edge_model_id)
                        edges.append(
                            DiagnosticGraphEdge(
                                model_id=edge_model_id,
                                source_model_id=source_model_id,
                                target_model_id=target_model_id,
                                category="cfg",
                                label=None,
                                hint_fields=(
                                    ("source", source_model_id.removeprefix("block:")),
                                    ("target", target_model_id.removeprefix("block:")),
                                ),
                                record_refs=(record_ref(record),),
                            )
                        )
            else:
                warnings.append(
                    f"Expanded state has no anchored owned blocks: {expanded_state_model_id}"
                )

    if not any(node.category == "state" for node in nodes_by_id.values()):
        warnings.append("No trustworthy State Machine records for this context")
    ordered_warnings = tuple(warnings)
    return DiagnosticGraph(
        context=context,
        nodes=tuple(nodes_by_id[model_id] for model_id in sorted(nodes_by_id)),
        edges=tuple(sorted(edges, key=lambda edge: edge.model_id)),
        expanded_group=expanded_group,
        warnings=ordered_warnings,
        status=_context_status(context, ordered_warnings, "State Machine"),
    )


def project_diagnostic_graph(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph:
    """Dispatch a supported pure diagnostic graph projection."""

    if request.context.kind is DiagnosticGraphKind.BLOCK_CFG:
        return project_block_cfg(request)
    if request.context.kind is DiagnosticGraphKind.STATE_MACHINE:
        return project_state_machine(request)
    raise ValueError(f"Unsupported diagnostic graph kind: {request.context.kind.value}")


__all__ = [
    "project_block_cfg",
    "project_diagnostic_graph",
    "project_state_machine",
]
