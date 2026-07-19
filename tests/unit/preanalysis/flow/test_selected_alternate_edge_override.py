"""Tests for selected-alternate edge override."""
from __future__ import annotations
from tests.unit.core.diag._orm_bind import make_bound_diag_db

import contextlib
import dataclasses
import json
import os
import sqlite3
from unittest.mock import patch

import pytest

from d810.core.diag.models import (
    FactMapping as DiagFactMapping,
    FactObservation as DiagFactObservation,
    Snapshot,
    StateCfgEdge,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.ir.state_dag_key import StateDagNodeKey
from d810.core.observability import SnapshotRef
from d810.core.settings import reset_settings
from d810.analyses.value_flow.model import (
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
)
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.selected_alternate_edge_override import (
    apply_selected_alternate_edge_overrides,
)
from d810.diagnostics.selected_alternate_edge_override import (
    apply_selected_alternate_edge_overrides_from_diag,
)


_TEST_SNAP = SnapshotRef(
    key="bridge-test",
    func_ea=0x180012DF0,
    label="recon_dag",
    maturity="MMAT_GLBOPT1",
    phase="pre_d810",
)


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("D810_FACT_LIFECYCLE", raising=False)
    reset_settings()
    yield
    reset_settings()


@contextlib.contextmanager
def _bridge_resolves_to(conn: sqlite3.Connection | None, snap_id: int | None):
    """Patch the abstract observability resolvers so the bridge uses
    ``conn`` / ``snap_id`` for ``_TEST_SNAP``. The bridge imports the
    resolvers inside its function body, so we patch them at the source
    module's namespace."""
    with patch(
        "d810.core.observability.get_active_diag_conn",
        return_value=conn,
    ), patch(
        "d810.core.observability.resolve_snapshot_id_for",
        return_value=snap_id,
    ):
        yield


def _make_node(
    *,
    state_const: int,
    entry: int,
    label: str | None = None,
    kind: StateNodeKind = StateNodeKind.EXACT,
    owned_blocks: tuple[int, ...] = (),
    shared_suffix_blocks: tuple[int, ...] = (),
) -> StateDagNode:
    return StateDagNode(
        key=StateDagNodeKey(
            handler_serial=entry, state_const=state_const,
        ),
        kind=kind,
        state_label=label or f"STATE_{state_const:08X}",
        handler_serial=entry,
        entry_anchor=entry,
        owned_blocks=owned_blocks,
        exclusive_blocks=(),
        shared_suffix_blocks=shared_suffix_blocks,
        local_segments=(),
        local_edges=(),
    )


def _make_edge(
    *,
    src_state: int,
    src_entry: int,
    tgt_state: int,
    tgt_entry: int,
    source_block: int,
) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(
            handler_serial=src_entry, state_const=src_state,
        ),
        target_key=StateDagNodeKey(
            handler_serial=tgt_entry, state_const=tgt_state,
        ),
        target_state=tgt_state,
        target_entry_anchor=tgt_entry,
        target_label=f"STATE_{tgt_state:08X}",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=source_block,
        ),
        ordered_path=(source_block,),
    )


def _make_dag(nodes: tuple[StateDagNode, ...], edges: tuple[StateDagEdge, ...]) -> LinearizedStateDag:
    return LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        condition_chain_blocks=(),
        nodes=nodes,
        edges=edges,
    )


def _seed_byte5_diag(conn: sqlite3.Connection) -> None:
    """Seed the diag DB so the cascade re-runs and produces selections.

    We pre-populate ``state_cfg_edges``, ``state_cfg_nodes``, ``state_cfg_node_blocks``,
    ``fact_observations`` (StateWriteAnchorFact + TerminalByteEmitterFact)
    and ``fact_mappings`` (STATE_CONST_REWRITTEN) so the helper's
    cascade pass produces the same byte5 selection we observed live.
    """
    Snapshot.insert_many([
        {"id": 1, "label": "recon_dag", "func_ea_hex": "0x180012df0",
         "func_ea_i64": 0x180012df0, "maturity": "MMAT_GLBOPT1",
         "phase": "pre_d810", "block_count": 0, "timestamp": 0.0},
        {"id": 2, "label": "locopt_pre", "func_ea_hex": "0x180012df0",
         "func_ea_i64": 0x180012df0, "maturity": "MMAT_LOCOPT",
         "phase": "pre_d810", "block_count": 0, "timestamp": 0.0},
    ]).execute()
    # The collapsed edge: 0x385BBE2D -> 0x63D54755 at blk[100].
    StateCfgEdge.insert_many([
        {"snapshot": 1, "edge_id": 144, "source_state_hex": "0x00000000385bbe2d",
         "source_state_i64": 0x385bbe2d, "target_state_hex": "0x0000000063d54755",
         "target_state_i64": 0x63d54755, "edge_kind": "TRANSITION",
         "source_block": 100, "source_arm": None, "target_entry": 21,
         "ordered_path": "[100]"},
        {"snapshot": 1, "edge_id": 68, "source_state_hex": "0x000000003873bc53",
         "source_state_i64": 0x3873bc53, "target_state_hex": "0x0000000010743c4c",
         "target_state_i64": 0x10743c4c, "edge_kind": "TRANSITION",
         "source_block": 101, "source_arm": None, "target_entry": 158,
         "ordered_path": "[101, 103, 104]"},
        {"snapshot": 1, "edge_id": 39, "source_state_hex": "0x0000000010743c4c",
         "source_state_i64": 0x10743c4c, "target_state_hex": "0x000000006107f8ec",
         "target_state_i64": 0x6107f8ec, "edge_kind": "TRANSITION",
         "source_block": 158, "source_arm": None, "target_entry": 15,
         "ordered_path": "[158]"},
    ]).execute()
    # Source node EXACT, sibling node RANGE_BACKED with overlap.
    StateCfgNode.insert_many([
        {"snapshot": 1, "state_hex": state, "state_i64": int(state, 16),
         "entry_block": entry, "classification": kind, "shared_suffix": None}
        for state, entry, kind in (
            ("0x00000000385bbe2d", 100, "EXACT"),
            ("0x000000003873bc53", 101, "RANGE_BACKED"),
            ("0x0000000010743c4c", 158, "EXACT"),
            ("0x000000006107f8ec", 15,  "RANGE_BACKED"),
        )
    ]).execute()
    # Block ownerships: STATE_385BBE2D owns blk[100]; STATE_3873BC53
    # owns [101, 100, 102, 103, 104] (sibling overlap on 100); STATE_6107F8EC
    # owns [217] which is byte6 terminal_tail.
    StateCfgNodeBlock.insert_many([
        {"snapshot": 1, "state_hex": state, "entry_block": entry,
         "block_serial": blk, "block_index": block_index, "role": role}
        for block_index, (state, entry, blk, role) in enumerate((
            ("0x00000000385bbe2d", 100, 100, "owned"),
            ("0x000000003873bc53", 101, 101, "owned"),
            ("0x000000003873bc53", 101, 100, "shared_suffix"),
            ("0x000000003873bc53", 101, 102, "owned"),
            ("0x000000003873bc53", 101, 103, "owned"),
            ("0x000000003873bc53", 101, 104, "owned"),
            ("0x0000000010743c4c", 158, 158, "owned"),
            ("0x000000006107f8ec",  15, 217, "owned"),
        ))
    ]).execute()
    # TerminalByteEmitterFact: byte5 emit at blk[101], byte6 emit at blk[217].
    DiagFactObservation.insert_many([
        {"snapshot": 1, "func_ea_hex": "0x180012df0", "func_ea_i64": 0x180012df0,
         "fact_id": fact_id, "kind": "TerminalByteEmitterFact",
         "semantic_key": fact_id, "maturity": "MMAT_GLBOPT1", "phase": "pre_d810",
         "confidence": 0.9, "source_block": dest, "source_ea_hex": None,
         "source_ea_i64": None, "block_fingerprint": None, "mop_signature": None,
         "payload": json.dumps({
             "destination_block": dest, "block_serial": dest,
             "byte_index": bi, "corridor_role": "terminal_tail",
         }), "evidence": "[]"}
        for fact_id, dest, bi in (("byte5", 101, 5), ("byte6", 217, 6))
    ]).execute()
    # STATE_CONST_REWRITTEN mapping for blk[100]: 0x5A21D9DB -> 0x63D54755.
    DiagFactMapping.insert_many([
        {"snapshot": 1, "func_ea_hex": "0x180012df0", "func_ea_i64": 0x180012df0,
         "mapping_index": 0, "source_fact_id": "anchor:100", "target_fact_id": None,
         "source_maturity": "MMAT_LOCOPT", "target_maturity": "MMAT_GLBOPT1",
         "status": "STATE_CONST_REWRITTEN", "confidence": 0.9, "target_block": None,
         "target_ea_hex": None, "target_ea_i64": None, "target_mop_signature": None,
         "reason": "test", "payload": json.dumps({
             "block_serial": 100, "original_const_hex": "0x000000005a21d9db",
             "rewritten_const_hex": "0x0000000063d54755",
             "from_maturity": "MMAT_LOCOPT", "to_maturity": "MMAT_GLBOPT1",
         })},
        {"snapshot": 1, "func_ea_hex": "0x180012df0", "func_ea_i64": 0x180012df0,
         "mapping_index": 1, "source_fact_id": "anchor:21", "target_fact_id": None,
         "source_maturity": "MMAT_LOCOPT", "target_maturity": "MMAT_GLBOPT1",
         "status": "STATE_CONST_REWRITTEN", "confidence": 0.9, "target_block": None,
         "target_ea_hex": None, "target_ea_i64": None, "target_mop_signature": None,
         "reason": "test", "payload": json.dumps({
             "block_serial": 21, "original_const_hex": "0x000000004f000000",
             "rewritten_const_hex": "0x0000000063d54755",
             "from_maturity": "MMAT_LOCOPT", "to_maturity": "MMAT_GLBOPT1",
         })},
    ]).execute()
    conn.commit()


def _make_byte5_dag() -> LinearizedStateDag:
    nodes = (
        _make_node(state_const=0x385BBE2D, entry=100, owned_blocks=(100,)),
        _make_node(state_const=0x63D54755, entry=21, owned_blocks=(21,)),
        _make_node(
            state_const=0x3873BC53, entry=101,
            kind=StateNodeKind.RANGE_BACKED,
            owned_blocks=(101, 102, 103, 104),
            shared_suffix_blocks=(100,),
        ),
        _make_node(state_const=0x10743C4C, entry=158, owned_blocks=(158,)),
        _make_node(
            state_const=0x6107F8EC, entry=15,
            kind=StateNodeKind.RANGE_BACKED,
            owned_blocks=(217,),
        ),
    )
    edges = (
        _make_edge(
            src_state=0x385BBE2D, src_entry=100,
            tgt_state=0x63D54755, tgt_entry=21,
            source_block=100,
        ),
        _make_edge(
            src_state=0x3873BC53, src_entry=101,
            tgt_state=0x10743C4C, tgt_entry=158,
            source_block=101,
        ),
        _make_edge(
            src_state=0x10743C4C, src_entry=158,
            tgt_state=0x6107F8EC, tgt_entry=15,
            source_block=158,
        ),
    )
    return _make_dag(nodes, edges)


def _make_byte5_fact_view() -> ValidatedFactView:
    observations = (
        FactObservation(
            fact_id="byte5",
            kind="TerminalByteEmitterFact",
            semantic_key="byte5",
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
            confidence=0.9,
            source_block=101,
            payload={
                "destination_block": 101,
                "block_serial": 101,
                "byte_index": 5,
                "corridor_role": "terminal_tail",
            },
        ),
        FactObservation(
            fact_id="byte6",
            kind="TerminalByteEmitterFact",
            semantic_key="byte6",
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
            confidence=0.9,
            source_block=217,
            payload={
                "destination_block": 217,
                "block_serial": 217,
                "byte_index": 6,
                "corridor_role": "terminal_tail",
            },
        ),
    )
    mappings = (
        FactMapping(
            source_fact_id="anchor:100",
            source_maturity="MMAT_LOCOPT",
            target_maturity="MMAT_GLBOPT1",
            status=FactStatus.STATE_CONST_REWRITTEN,
            confidence=0.9,
            payload={
                "block_serial": 100,
                "original_const_hex": "0x000000005a21d9db",
                "rewritten_const_hex": "0x0000000063d54755",
                "from_maturity": "MMAT_LOCOPT",
                "to_maturity": "MMAT_GLBOPT1",
            },
        ),
        FactMapping(
            source_fact_id="anchor:21",
            source_maturity="MMAT_LOCOPT",
            target_maturity="MMAT_GLBOPT1",
            status=FactStatus.STATE_CONST_REWRITTEN,
            confidence=0.9,
            payload={
                "block_serial": 21,
                "original_const_hex": "0x000000004f000000",
                "rewritten_const_hex": "0x0000000063d54755",
                "from_maturity": "MMAT_LOCOPT",
                "to_maturity": "MMAT_GLBOPT1",
            },
        ),
    )
    return ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=observations,
        mappings=mappings,
    )


def test_no_op_when_setting_disabled() -> None:
    conn = make_bound_diag_db().connection()
    _seed_byte5_diag(conn)
    dag = _make_byte5_dag()
    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "0"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        reset_settings()
        result = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)
    assert result is dag


def test_pure_replaces_byte5_collapsed_edge_from_fact_view() -> None:
    dag = _make_byte5_dag()
    new_dag = apply_selected_alternate_edge_overrides(
        dag,
        _make_byte5_fact_view(),
    )

    assert new_dag is not dag
    overridden = [
        e for e in new_dag.edges
        if e.source_key.state_const == 0x385BBE2D
    ]
    assert len(overridden) == 1
    edge = overridden[0]
    assert edge.target_state == 0x6107F8EC
    assert edge.target_entry_anchor == 15


def test_no_op_when_diag_missing() -> None:
    dag = _make_byte5_dag()
    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False):
        assert apply_selected_alternate_edge_overrides_from_diag(dag, None) is dag


def test_no_op_when_no_selected_rows() -> None:
    """Empty diag DB -> cascade produces no selections -> no override."""
    conn = make_bound_diag_db().connection()
    Snapshot.insert(
        id=1, label="recon_dag", func_ea_hex="0x180012df0",
        func_ea_i64=0x180012df0, maturity="MMAT_GLBOPT1", phase="pre_d810",
        block_count=0, timestamp=0.0,
    ).execute()
    conn.commit()
    dag = _make_byte5_dag()
    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        result = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)
    assert result is dag


def test_replaces_byte5_collapsed_edge() -> None:
    """Live byte5 case: edge 144 collapsed -> reached state 0x6107F8EC."""
    conn = make_bound_diag_db().connection()
    _seed_byte5_diag(conn)
    dag = _make_byte5_dag()

    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        new_dag = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)

    assert new_dag is not dag, (
        "expected a NEW dag (frozen dataclass replace)"
    )
    overridden = [
        e for e in new_dag.edges
        if e.source_key.state_const == 0x385BBE2D
    ]
    assert len(overridden) == 1
    edge = overridden[0]
    # Reached state for byte5 in our seed is 0x6107F8EC (byte6 owner).
    assert edge.target_state == 0x6107F8EC
    assert edge.target_entry_anchor == 15
    assert edge.target_label.startswith("STATE_")


def test_recomputes_sccs_after_selected_alternate_rewrite() -> None:
    conn = make_bound_diag_db().connection()
    _seed_byte5_diag(conn)
    base = _make_byte5_dag()
    reverse_edge = _make_edge(
        src_state=0x6107F8EC,
        src_entry=15,
        tgt_state=0x385BBE2D,
        tgt_entry=100,
        source_block=15,
    )
    dag = dataclasses.replace(base, edges=(*base.edges, reverse_edge))

    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        new_dag = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)

    cyclic = [scc for scc in new_dag.sccs if scc.is_cyclic]
    assert len(cyclic) == 1
    assert cyclic[0].states == frozenset({0x385BBE2D, 0x6107F8EC})


def test_abstain_on_value_mapping_miss() -> None:
    """Diag DB has gating row but in-memory edge uses different
    source_block than what was persisted -> abstain."""
    conn = make_bound_diag_db().connection()
    _seed_byte5_diag(conn)
    nodes = (
        _make_node(state_const=0x385BBE2D, entry=100),
        _make_node(state_const=0x63D54755, entry=21),
        _make_node(state_const=0x6107F8EC, entry=15,
                   kind=StateNodeKind.RANGE_BACKED),
    )
    # Build edge with WRONG source_block (777) -- diag has source_block=100.
    edges = (
        _make_edge(
            src_state=0x385BBE2D, src_entry=100,
            tgt_state=0x63D54755, tgt_entry=21,
            source_block=777,
        ),
    )
    dag = _make_dag(nodes, edges)

    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        result = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)
    # Helper falls back to (src_hex, tgt_hex, None) when source_block
    # doesn't match -- in the gated map the key is
    # (src, tgt, source_block=100).  None-fallback also misses ->
    # abstain.
    assert result is dag


def test_abstain_when_reached_state_has_no_node() -> None:
    """Diag selects 0x6107F8EC but dag.nodes has no such node -> abstain."""
    conn = make_bound_diag_db().connection()
    _seed_byte5_diag(conn)
    nodes = (
        _make_node(state_const=0x385BBE2D, entry=100),
        _make_node(state_const=0x63D54755, entry=21),
        # No 0x6107F8EC node -> reached_state lookup will fail.
    )
    edges = (
        _make_edge(
            src_state=0x385BBE2D, src_entry=100,
            tgt_state=0x63D54755, tgt_entry=21,
            source_block=100,
        ),
    )
    dag = _make_dag(nodes, edges)

    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        result = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)
    assert result is dag
