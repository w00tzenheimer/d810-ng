"""Tests for selected-alternate edge override."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import sqlite3
from unittest.mock import patch

from d810.cfg.state_dag_key import StateDagNodeKey
from d810.core.diag.schema import create_tables
from d810.core.observability import SnapshotRef
from d810.recon.facts.model import (
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.recon.flow.selected_alternate_edge_override import (
    apply_selected_alternate_edge_overrides,
    apply_selected_alternate_edge_overrides_from_diag,
)


_TEST_SNAP = SnapshotRef(
    key="bridge-test",
    func_ea=0x180012DF0,
    label="recon_dag",
    maturity="MMAT_GLBOPT1",
    phase="pre_d810",
)


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
        bst_node_blocks=(),
        nodes=nodes,
        edges=edges,
    )


def _seed_byte5_diag(conn: sqlite3.Connection) -> None:
    """Seed the diag DB so the cascade re-runs and produces selections.

    We pre-populate ``dag_edges``, ``dag_nodes``, ``dag_node_blocks``,
    ``fact_observations`` (StateWriteAnchorFact + TerminalByteEmitterFact)
    and ``fact_mappings`` (STATE_CONST_REWRITTEN) so the helper's
    cascade pass produces the same byte5 selection we observed live.
    """
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (1, 'recon_dag', '0x180012df0', 0x180012df0,
                'MMAT_GLBOPT1', 'pre_d810', 0, 0.0),
               (2, 'locopt_pre', '0x180012df0', 0x180012df0,
                'MMAT_LOCOPT', 'pre_d810', 0, 0.0)
        """,
    )
    # The collapsed edge: 0x385BBE2D -> 0x63D54755 at blk[100].
    conn.execute(
        """
        INSERT INTO dag_edges
            (snapshot_id, edge_id, source_state_hex, source_state_i64,
             target_state_hex, target_state_i64, edge_kind,
             source_block, source_arm, target_entry, ordered_path)
        VALUES (1, 144, '0x00000000385bbe2d', 0x385bbe2d,
                '0x0000000063d54755', 0x63d54755, 'TRANSITION',
                100, NULL, 21, '[100]'),
               (1, 68, '0x000000003873bc53', 0x3873bc53,
                '0x0000000010743c4c', 0x10743c4c, 'TRANSITION',
                101, NULL, 158, '[101, 103, 104]'),
               (1, 39, '0x0000000010743c4c', 0x10743c4c,
                '0x000000006107f8ec', 0x6107f8ec, 'TRANSITION',
                158, NULL, 15, '[158]')
        """,
    )
    # Source node EXACT, sibling node RANGE_BACKED with overlap.
    for state, entry, kind in (
        ("0x00000000385bbe2d", 100, "EXACT"),
        ("0x000000003873bc53", 101, "RANGE_BACKED"),
        ("0x0000000010743c4c", 158, "EXACT"),
        ("0x000000006107f8ec", 15,  "RANGE_BACKED"),
    ):
        conn.execute(
            """
            INSERT INTO dag_nodes
                (snapshot_id, state_hex, state_i64, entry_block,
                 classification, shared_suffix)
            VALUES (1, ?, ?, ?, ?, NULL)
            """,
            (state, int(state, 16), entry, kind),
        )
    # Block ownerships: STATE_385BBE2D owns blk[100]; STATE_3873BC53
    # owns [101, 100, 102, 103, 104] (sibling overlap on 100); STATE_6107F8EC
    # owns [217] which is byte6 terminal_tail.
    block_index = 0
    for state, entry, blk, role in (
        ("0x00000000385bbe2d", 100, 100, "owned"),
        ("0x000000003873bc53", 101, 101, "owned"),
        ("0x000000003873bc53", 101, 100, "shared_suffix"),
        ("0x000000003873bc53", 101, 102, "owned"),
        ("0x000000003873bc53", 101, 103, "owned"),
        ("0x000000003873bc53", 101, 104, "owned"),
        ("0x0000000010743c4c", 158, 158, "owned"),
        ("0x000000006107f8ec",  15, 217, "owned"),
    ):
        conn.execute(
            """
            INSERT INTO dag_node_blocks
                (snapshot_id, state_hex, entry_block, block_serial,
                 block_index, role)
            VALUES (1, ?, ?, ?, ?, ?)
            """,
            (state, entry, blk, block_index, role),
        )
        block_index += 1
    # TerminalByteEmitterFact: byte5 emit at blk[101], byte6 emit at blk[217].
    for fact_id, dest, bi in (
        ("byte5", 101, 5),
        ("byte6", 217, 6),
    ):
        conn.execute(
            """
            INSERT INTO fact_observations
                (snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind,
                 semantic_key, maturity, phase, confidence,
                 source_block, source_ea_hex, source_ea_i64,
                 block_fingerprint, mop_signature, payload, evidence)
            VALUES (1, '0x180012df0', 0x180012df0, ?, 'TerminalByteEmitterFact',
                    ?, 'MMAT_GLBOPT1', 'pre_d810', 0.9, ?, NULL, NULL,
                    NULL, NULL, ?, '[]')
            """,
            (
                fact_id, fact_id, dest,
                json.dumps({
                    "destination_block": dest,
                    "block_serial": dest,
                    "byte_index": bi,
                    "corridor_role": "terminal_tail",
                }),
            ),
        )
    # STATE_CONST_REWRITTEN mapping for blk[100]: 0x5A21D9DB -> 0x63D54755.
    conn.execute(
        """
        INSERT INTO fact_mappings
            (snapshot_id, func_ea_hex, func_ea_i64, mapping_index,
             source_fact_id, target_fact_id, source_maturity,
             target_maturity, status, confidence,
             target_block, target_ea_hex, target_ea_i64,
             target_mop_signature, reason, payload)
        VALUES (1, '0x180012df0', 0x180012df0, 0, 'anchor:100', NULL,
                'MMAT_LOCOPT', 'MMAT_GLBOPT1', 'STATE_CONST_REWRITTEN', 0.9,
                NULL, NULL, NULL, NULL, 'test', ?),
               (1, '0x180012df0', 0x180012df0, 1, 'anchor:21', NULL,
                'MMAT_LOCOPT', 'MMAT_GLBOPT1', 'STATE_CONST_REWRITTEN', 0.9,
                NULL, NULL, NULL, NULL, 'test', ?)
        """,
        (
            json.dumps({
                "block_serial": 100,
                "original_const_hex": "0x000000005a21d9db",
                "rewritten_const_hex": "0x0000000063d54755",
                "from_maturity": "MMAT_LOCOPT",
                "to_maturity": "MMAT_GLBOPT1",
            }),
            json.dumps({
                "block_serial": 21,
                "original_const_hex": "0x000000004f000000",
                "rewritten_const_hex": "0x0000000063d54755",
                "from_maturity": "MMAT_LOCOPT",
                "to_maturity": "MMAT_GLBOPT1",
            }),
        ),
    )
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


def test_no_op_when_env_disabled() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    _seed_byte5_diag(conn)
    dag = _make_byte5_dag()
    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": ""}, clear=False), \
            _bridge_resolves_to(conn, 1):
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
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (1, 'recon_dag', '0x180012df0', 0x180012df0,
                'MMAT_GLBOPT1', 'pre_d810', 0, 0.0)
        """,
    )
    conn.commit()
    dag = _make_byte5_dag()
    with patch.dict(os.environ, {"D810_FACT_LIFECYCLE": "1"}, clear=False), \
            _bridge_resolves_to(conn, 1):
        result = apply_selected_alternate_edge_overrides_from_diag(dag, _TEST_SNAP)
    assert result is dag


def test_replaces_byte5_collapsed_edge() -> None:
    """Live byte5 case: edge 144 collapsed -> reached state 0x6107F8EC."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
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
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
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
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
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
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
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
