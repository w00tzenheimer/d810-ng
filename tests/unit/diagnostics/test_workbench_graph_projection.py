from __future__ import annotations

import dataclasses

from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraphContext,
    DiagnosticGraphKind,
    DiagnosticGraphProjectionRequest,
)
from d810.diagnostics.workbench_graph_projection import (
    project_block_cfg,
    project_state_machine,
)
from d810.diagnostics.workbench_models import (
    DiagnosticField,
    DiagnosticRecord,
    DiagnosticViewKind,
)


def _context(kind: DiagnosticGraphKind) -> DiagnosticGraphContext:
    return DiagnosticGraphContext(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        kind=kind,
    )


def _block(
    ordinal: int,
    serial: str,
    succs: str,
    *,
    snapshot_id: int = 17,
) -> DiagnosticRecord:
    anchor_ea = int(serial.rsplit("@", 1)[1], 16) if "@" in serial else None
    return DiagnosticRecord(
        kind=DiagnosticViewKind.BLOCKS,
        source_table="blocks",
        snapshot_id=snapshot_id,
        ordinal=ordinal,
        fields=(
            DiagnosticField("serial", serial, serial, anchor_ea),
            DiagnosticField("succs", succs, succs),
        ),
        warnings=(),
        anchor_ea=anchor_ea,
    )


def _request(*records: DiagnosticRecord) -> DiagnosticGraphProjectionRequest:
    return DiagnosticGraphProjectionRequest(
        context=_context(DiagnosticGraphKind.BLOCK_CFG),
        primary_records=records,
    )


def test_block_cfg_projects_anchored_nodes_and_only_evidenced_edges() -> None:
    graph = project_block_cfg(
        _request(
            _block(2, "blk8@0x180012D10", ""),
            _block(1, "blk7@0x180012C9F", "blk8@0x180012D10"),
        )
    )

    assert [node.label for node in graph.nodes] == [
        "blk7@0x180012C9F",
        "blk8@0x180012D10",
    ]
    assert [(edge.source_model_id, edge.target_model_id) for edge in graph.edges] == [
        ("block:blk7@0x180012C9F", "block:blk8@0x180012D10")
    ]
    assert graph.nodes[0].record_refs[0].ordinal == 1


def test_block_cfg_omits_dangling_edges_and_unanchored_blocks_with_warnings() -> None:
    graph = project_block_cfg(
        _request(
            _block(1, "blk7@0x180012C9F", "blk8@0x180012D10"),
            _block(2, "blk9", ""),
        )
    )

    assert [node.label for node in graph.nodes] == ["blk7@0x180012C9F"]
    assert graph.edges == ()
    assert graph.warnings == (
        "Block record omitted: EA anchor unavailable",
        "Dangling CFG edge omitted: blk7@0x180012C9F -> blk8@0x180012D10",
    )


def test_block_cfg_omits_snapshot_mismatch_and_reports_unavailable_context() -> None:
    graph = project_block_cfg(
        _request(_block(1, "blk7@0x180012C9F", "", snapshot_id=16))
    )

    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.warnings == (
        "Record snapshot mismatch: blocks#1",
        "No trustworthy Block CFG records for this context",
    )
    assert graph.status.endswith("warnings: 2")


def _state_record(
    table: str,
    ordinal: int,
    **values: object,
) -> DiagnosticRecord:
    block_fields = {"entry_block", "block_serial", "source_block", "target_entry"}
    fields = tuple(
        DiagnosticField(
            name,
            value,
            str(value),
            (
                int(str(value).rsplit("@", 1)[1], 16)
                if name in block_fields and "@" in str(value)
                else None
            ),
        )
        for name, value in values.items()
    )
    anchor = next((field.anchor_ea for field in fields if field.anchor_ea), None)
    return DiagnosticRecord(
        kind=DiagnosticViewKind.STATE_MACHINE,
        source_table=table,
        snapshot_id=17,
        ordinal=ordinal,
        fields=fields,
        warnings=(),
        anchor_ea=anchor,
    )


def _state_request(
    primary_records: tuple[DiagnosticRecord, ...],
    block_records: tuple[DiagnosticRecord, ...],
    *,
    expanded_state_model_id: str | None = None,
) -> DiagnosticGraphProjectionRequest:
    return DiagnosticGraphProjectionRequest(
        context=_context(DiagnosticGraphKind.STATE_MACHINE),
        primary_records=primary_records,
        block_records=block_records,
        expanded_state_model_id=expanded_state_model_id,
    )


def test_state_machine_projects_states_transitions_and_one_owned_block_group() -> None:
    state_12 = _state_record(
        "state_cfg_nodes",
        1,
        state_hex="0x12",
        state_i64=18,
        entry_block="blk7@0x180012C9F",
        classification="dispatcher",
    )
    state_34 = _state_record(
        "state_cfg_nodes",
        2,
        state_hex="0x34",
        state_i64=52,
        entry_block="blk8@0x180012D10",
        classification="payload",
    )
    ownership_12 = _state_record(
        "state_cfg_node_blocks",
        3,
        state_hex="0x12",
        entry_block="blk7@0x180012C9F",
        block_serial="blk7@0x180012C9F",
        block_index=0,
        role="owned",
    )
    ownership_34 = _state_record(
        "state_cfg_node_blocks",
        4,
        state_hex="0x34",
        entry_block="blk8@0x180012D10",
        block_serial="blk8@0x180012D10",
        block_index=0,
        role="owned",
    )
    transition = _state_record(
        "state_cfg_edges",
        5,
        edge_id=4,
        source_state_hex="0x12",
        source_state_i64=18,
        target_state_hex="0x34",
        target_state_i64=52,
        edge_kind="TRANSITION",
        source_block="blk7@0x180012C9F",
        target_entry="blk8@0x180012D10",
    )
    request = _state_request(
        (state_12, state_34, ownership_12, ownership_34, transition),
        (
            _block(1, "blk7@0x180012C9F", ""),
            _block(2, "blk8@0x180012D10", ""),
        ),
    )

    graph = project_state_machine(request)

    assert [node.model_id for node in graph.nodes] == ["state:0x12", "state:0x34"]
    assert graph.nodes[0].expandable is True
    assert "blk7@0x180012C9F" in graph.nodes[0].label
    assert [(edge.category, edge.source_model_id, edge.target_model_id) for edge in graph.edges] == [
        ("state_transition", "state:0x12", "state:0x34")
    ]
    assert graph.expanded_group is None

    expanded = project_state_machine(
        dataclasses.replace(request, expanded_state_model_id="state:0x12")
    )

    assert expanded.expanded_group is not None
    assert expanded.expanded_group.member_node_ids == ("block:blk7@0x180012C9F",)
    assert "block:blk7@0x180012C9F" in {node.model_id for node in expanded.nodes}


def test_state_machine_omits_incomplete_ownership_and_rejects_unknown_expansion() -> None:
    state = _state_record(
        "state_cfg_nodes",
        1,
        state_hex="0x12",
        state_i64=18,
        entry_block="blk7@0x180012C9F",
        classification="dispatcher",
    )
    ownership = _state_record(
        "state_cfg_node_blocks",
        2,
        state_hex="0x12",
        entry_block="blk7@0x180012C9F",
        block_serial="blk9@0x180012E20",
        block_index=0,
        role="owned",
    )

    graph = project_state_machine(
        _state_request((state, ownership), (), expanded_state_model_id="state:0x99")
    )

    assert graph.expanded_group is None
    assert graph.warnings == ("Expanded state unavailable: state:0x99",)


def test_state_machine_projects_explicit_terminal_transition_without_anchor() -> None:
    state = _state_record(
        "state_cfg_nodes",
        1,
        state_hex="0x12",
        state_i64=18,
        entry_block="blk7@0x180012C9F",
        classification="dispatcher",
    )
    terminal = _state_record(
        "state_cfg_edges",
        2,
        edge_id=8,
        source_state_hex="0x12",
        source_state_i64=18,
        target_state_hex=None,
        target_state_i64=None,
        edge_kind="CONDITIONAL_RETURN",
        source_block="blk7@0x180012C9F",
        target_entry=None,
    )

    graph = project_state_machine(_state_request((state, terminal), ()))

    terminal_node = next(node for node in graph.nodes if node.category == "terminal")
    assert terminal_node.anchor_ea is None
    assert graph.edges[0].target_model_id == terminal_node.model_id
