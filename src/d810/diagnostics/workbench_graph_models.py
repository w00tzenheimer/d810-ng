"""Immutable, IDA-independent graph models for diagnostics evidence."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.diagnostics.workbench_models import DiagnosticRecord


class DiagnosticGraphKind(str, enum.Enum):
    """The diagnostic evidence views with native graph projections."""

    BLOCK_CFG = "block_cfg"
    STATE_MACHINE = "state_machine"
    CASE_LINEAGE = "case_lineage"


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticRecordRef:
    """Stable identity for one normalized record in a diagnostic snapshot."""

    source_table: str
    snapshot_id: int
    ordinal: int


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphContext:
    """The exact diagnostic evidence boundary rendered by a graph."""

    database_path: str
    snapshot_id: int
    function_ea: int
    function_name: str | None
    kind: DiagnosticGraphKind


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphNode:
    """One evidence-backed graph node."""

    model_id: str
    label: str
    category: str
    anchor_ea: int | None
    hint_fields: tuple[tuple[str, str], ...]
    record_refs: tuple[DiagnosticRecordRef, ...]
    expandable: bool = False
    requires_anchor: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphEdge:
    """One evidence-backed directed graph edge."""

    model_id: str
    source_model_id: str
    target_model_id: str
    category: str
    label: str | None
    hint_fields: tuple[tuple[str, str], ...]
    record_refs: tuple[DiagnosticRecordRef, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphGroup:
    """A native-graph-ready group representing one expanded state."""

    model_id: str
    label: str
    member_node_ids: tuple[str, ...]
    record_refs: tuple[DiagnosticRecordRef, ...]
    anchor_ea: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraph:
    """Validated immutable topology and visible evidence status."""

    context: DiagnosticGraphContext
    nodes: tuple[DiagnosticGraphNode, ...]
    edges: tuple[DiagnosticGraphEdge, ...]
    expanded_group: DiagnosticGraphGroup | None
    warnings: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        node_ids = tuple(node.model_id for node in self.nodes)
        node_id_set = set(node_ids)
        if len(node_id_set) != len(node_ids):
            raise ValueError("Duplicate graph node ID")

        edge_ids = tuple(edge.model_id for edge in self.edges)
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("Duplicate graph edge ID")

        for edge in self.edges:
            if (
                edge.source_model_id not in node_id_set
                or edge.target_model_id not in node_id_set
            ):
                raise ValueError(f"Graph edge endpoint is missing: {edge.model_id}")

        group = self.expanded_group
        if group is None:
            return
        member_ids = group.member_node_ids
        if len(set(member_ids)) != len(member_ids):
            raise ValueError("Duplicate graph group member ID")
        for member_id in member_ids:
            if member_id not in node_id_set:
                raise ValueError(f"Graph group member is missing: {member_id}")


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphProjectionRequest:
    """Complete normalized records necessary to project one graph context."""

    context: DiagnosticGraphContext
    primary_records: tuple[DiagnosticRecord, ...]
    block_records: tuple[DiagnosticRecord, ...] = ()
    expanded_state_model_id: str | None = None
    case_evidence: DeobfuscationCaseEvidence | None = None


def record_ref(record: DiagnosticRecord) -> DiagnosticRecordRef:
    """Return the source reference used by graph nodes and edges."""

    return DiagnosticRecordRef(
        source_table=record.source_table,
        snapshot_id=int(record.snapshot_id),
        ordinal=int(record.ordinal),
    )


def anchored_block_model_id(serial: int, anchor_ea: int) -> str:
    """Return a display-safe graph identity for a microcode block."""

    return f"block:blk{int(serial)}@0x{int(anchor_ea):X}"


def node_ids_for_record(
    graph: DiagnosticGraph, reference: DiagnosticRecordRef
) -> tuple[str, ...]:
    """Return node IDs in graph order for one source diagnostic record."""

    return tuple(
        node.model_id for node in graph.nodes if reference in node.record_refs
    )


__all__ = [
    "DiagnosticGraph",
    "DiagnosticGraphContext",
    "DiagnosticGraphEdge",
    "DiagnosticGraphGroup",
    "DiagnosticGraphKind",
    "DiagnosticGraphNode",
    "DiagnosticGraphProjectionRequest",
    "DiagnosticRecordRef",
    "anchored_block_model_id",
    "node_ids_for_record",
    "record_ref",
]
