from __future__ import annotations

from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraphContext,
    DiagnosticGraphKind,
    DiagnosticGraphProjectionRequest,
)
from d810.diagnostics.workbench_graph_projection import project_block_cfg
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
