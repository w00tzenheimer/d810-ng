from __future__ import annotations

import pytest

from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphContext,
    DiagnosticGraphEdge,
    DiagnosticGraphKind,
    DiagnosticGraphNode,
    DiagnosticRecordRef,
    anchored_block_model_id,
    node_ids_for_record,
)


def _context() -> DiagnosticGraphContext:
    return DiagnosticGraphContext(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        kind=DiagnosticGraphKind.BLOCK_CFG,
    )


def _node(
    model_id: str,
    *,
    record_refs: tuple[DiagnosticRecordRef, ...] = (),
) -> DiagnosticGraphNode:
    return DiagnosticGraphNode(
        model_id=model_id,
        label=model_id,
        category="block",
        anchor_ea=0x180012C9F,
        hint_fields=(),
        record_refs=record_refs,
    )


def test_anchored_block_identity_and_record_lookup_are_deterministic() -> None:
    reference = DiagnosticRecordRef("blocks", 17, 7)
    first = anchored_block_model_id(7, 0x180012C9F)
    second = anchored_block_model_id(8, 0x180012D10)
    graph = DiagnosticGraph(
        context=_context(),
        nodes=(
            _node(first, record_refs=(reference,)),
            _node(second, record_refs=(reference,)),
        ),
        edges=(),
        expanded_group=None,
        warnings=(),
        status="Block CFG | diag.sqlite3 | snapshot 17 | target@0x180012B60",
    )

    assert first == "block:blk7@0x180012C9F"
    assert node_ids_for_record(graph, reference) == (first, second)


def test_graph_rejects_duplicate_node_ids() -> None:
    node = _node("block:blk7@0x180012C9F")

    with pytest.raises(ValueError, match="Duplicate graph node ID"):
        DiagnosticGraph(
            context=_context(),
            nodes=(node, node),
            edges=(),
            expanded_group=None,
            warnings=(),
            status="status",
        )


def test_graph_rejects_edge_with_missing_endpoint() -> None:
    node = _node("block:blk7@0x180012C9F")
    edge = DiagnosticGraphEdge(
        model_id="cfg:block:blk7@0x180012C9F->block:blk8@0x180012D10",
        source_model_id=node.model_id,
        target_model_id="block:blk8@0x180012D10",
        category="cfg",
        label=None,
        hint_fields=(),
        record_refs=(),
    )

    with pytest.raises(ValueError, match="Graph edge endpoint is missing"):
        DiagnosticGraph(
            context=_context(),
            nodes=(node,),
            edges=(edge,),
            expanded_group=None,
            warnings=(),
            status="status",
        )


def test_graph_node_exposes_when_its_label_must_carry_a_native_anchor() -> None:
    node = DiagnosticGraphNode(
        model_id="case:receipt:0x180012C9F",
        label="receipt:0x180012C9F | published",
        category="case_receipt",
        anchor_ea=0x180012C9F,
        hint_fields=(),
        record_refs=(),
        requires_anchor=True,
    )

    assert node.requires_anchor is True
