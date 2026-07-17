"""Pure graph projections for normalized diagnostics evidence."""

from __future__ import annotations

import re
from pathlib import Path

from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphContext,
    DiagnosticGraphEdge,
    DiagnosticGraphKind,
    DiagnosticGraphNode,
    DiagnosticGraphProjectionRequest,
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


def _context_status(context: DiagnosticGraphContext, warnings: tuple[str, ...]) -> str:
    database_name = Path(context.database_path).name or context.database_path
    function = (
        f"{context.function_name}@0x{context.function_ea:X}"
        if context.function_name
        else f"0x{context.function_ea:X}"
    )
    status = (
        f"Block CFG | {database_name} | snapshot {context.snapshot_id} | {function}"
    )
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
        status=_context_status(context, ordered_warnings),
    )


def project_diagnostic_graph(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph:
    """Dispatch a supported pure diagnostic graph projection."""

    if request.context.kind is DiagnosticGraphKind.BLOCK_CFG:
        return project_block_cfg(request)
    raise ValueError(f"Unsupported diagnostic graph kind: {request.context.kind.value}")


__all__ = ["project_block_cfg", "project_diagnostic_graph"]
