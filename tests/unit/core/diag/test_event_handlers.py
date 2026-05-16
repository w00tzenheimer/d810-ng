"""Tests for the SQLite event handlers (Phase 3).

Verify that with handlers installed on the bus and a connected diag DB,
the observation events from recon/cfg/hexrays emit rows in the expected
tables. The mapping ``SnapshotRef.key -> snapshots.id`` is driven by
the :class:`CaptureMbaSnapshotRequested` handler.
"""
from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from d810.cfg.observability import (
    observe_cfg_provenance,
    observe_cfg_provenance_latest,
    observe_watch_block_transition,
)
from d810.core.diag.event_handlers import (
    install_diag_event_handlers,
    is_installed,
    uninstall_diag_event_handlers,
)
from d810.core.diag.schema import create_tables
from d810.core.observability import (
    SnapshotRef,
    emit,
    has_subscribers,
    new_snapshot_key,
    reset_diagnostic_bus,
)
from d810.core.observability_events import (
    CaptureMbaSnapshotRequested,
    DagObserved,
    ModificationsObserved,
)
from d810.core.observability_models import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    Modification,
)
from d810.recon.observability import (
    observe_branch_ownership_proofs,
    observe_dag,
    observe_modifications,
    observe_reachability,
    observe_state_dispatcher_rows,
    observe_state_transition_dispatch_resolutions,
)


def request_capture_mba_snapshot(
    *,
    blocks,
    label: str,
    func_ea: int,
    maturity: str,
    phase: str,
) -> SnapshotRef | None:
    """Test-side request_capture wrapper that does not import hexrays.

    Mirrors what the real hexrays.observability helper does so the
    handler tests verify the end-to-end shape without crossing the
    unit-tests-no-hexrays boundary.
    """
    if not has_subscribers(CaptureMbaSnapshotRequested):
        return None
    snap = SnapshotRef(
        key=new_snapshot_key(),
        func_ea=int(func_ea),
        label=label,
        maturity=maturity,
        phase=phase,
    )
    emit(CaptureMbaSnapshotRequested(snapshot=snap, blocks=tuple(blocks)))
    return snap


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_conn():
    """In-memory SQLite with the diag schema populated."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    return conn


@pytest.fixture(autouse=True)
def _bus_and_handlers(fake_conn):
    """Install handlers with the fake conn standing in for get_diag_db()."""
    reset_diagnostic_bus()

    def fake_get_diag_db(_func_ea: int = 0, *_, **__):
        return fake_conn

    with patch(
        "d810.core.diag.event_handlers.get_diag_db", new=fake_get_diag_db,
    ):
        install_diag_event_handlers()
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def _make_snap_blocks() -> list[BlockSnapshot]:
    return [
        BlockSnapshot(
            serial=0,
            block_type=1,
            type_name="BLT_NWAY",
            start_ea=0x100,
        ),
    ]


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------


def test_install_is_idempotent():
    assert is_installed()
    # A second install should not crash.
    install_diag_event_handlers()
    assert is_installed()


def test_uninstall_clears_install_flag():
    uninstall_diag_event_handlers()
    assert not is_installed()


# ---------------------------------------------------------------------------
# CaptureMbaSnapshotRequested
# ---------------------------------------------------------------------------


def test_capture_inserts_snapshots_row_and_binds_mapping(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="MMAT_GLBOPT1_post_d810",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is not None

    rows = fake_conn.execute(
        "SELECT label, maturity, phase, block_count FROM snapshots"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0] == ("MMAT_GLBOPT1_post_d810", "MMAT_GLBOPT1", "post_d810", 1)


def test_followup_event_writes_under_correct_snapshot_id(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is not None

    nodes = [
        DagNode(state=0x10, state_hex="0x10", entry_block=5, classification="X"),
    ]
    edges = [
        DagEdge(
            edge_id=0, source_state=0x10, target_state=0x20,
            edge_kind="TRANSITION",
        ),
    ]
    observe_dag(snap, nodes, edges)

    dag_rows = fake_conn.execute(
        "SELECT snapshot_id, state_hex, classification FROM dag_nodes"
    ).fetchall()
    assert len(dag_rows) == 1
    assert dag_rows[0][1] == "0x0000000000000010"
    assert dag_rows[0][2] == "X"


def test_observe_modifications_writes_to_modifications_table(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=1, maturity="M", phase="post_d810",
    )
    assert snap is not None

    mods = [
        Modification(mod_index=0, mod_type="goto_redirect", source_block=5),
        Modification(mod_index=1, mod_type="insert_block", target_block=9),
    ]
    observe_modifications(snap, mods)

    rows = fake_conn.execute(
        "SELECT mod_index, mod_type FROM modifications ORDER BY mod_index"
    ).fetchall()
    assert rows == [(0, "goto_redirect"), (1, "insert_block")]


def test_reachability_translates_frozensets_to_classification_rows(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=1, maturity="M", phase="post_d810",
    )
    assert snap is not None

    observe_reachability(
        snap,
        all_serials=[0, 1, 2],
        reachable=[0, 1],
        bst_serials=[],
        gutted=[2],
        claimed_sources=[1],
    )

    rows = fake_conn.execute(
        "SELECT serial, is_reachable, is_gutted, in_claimed "
        "FROM block_classification ORDER BY serial"
    ).fetchall()
    assert rows == [
        (0, 1, 0, 0),
        (1, 1, 0, 1),
        (2, 0, 1, 0),
    ]


def test_event_without_snapshot_mapping_is_a_noop(fake_conn):
    # No capture happened; emit a DagObserved with a snapshot whose key
    # was never bound. Should not raise, should not write rows.
    snap = SnapshotRef(key="stale-key", func_ea=1, label="L", maturity="M", phase="p")
    emit(DagObserved(snapshot=snap, nodes=(), edges=()))

    rows = fake_conn.execute("SELECT COUNT(*) FROM dag_nodes").fetchone()
    assert rows[0] == 0


def test_state_dispatcher_rows_buffer_until_snapshot(fake_conn):
    observe_state_dispatcher_rows(
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        dispatcher_entry_block=2,
        dispatcher_kind="CONDITIONAL_CHAIN",
        rows=[
            {
                "state_const": 0x89407346,
                "target_block": 3,
                "compare_block": None,
                "branch_kind": "handler_state_map",
                "confidence": 1.0,
            }
        ],
    )

    pre_rows = fake_conn.execute(
        "SELECT COUNT(*) FROM state_dispatcher_rows"
    ).fetchone()
    assert pre_rows[0] == 0

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )

    row = fake_conn.execute(
        "SELECT state_const_hex, target_block, compare_block, branch_kind "
        "FROM state_dispatcher_rows"
    ).fetchone()
    assert row == (
        "0x0000000089407346",
        3,
        None,
        "handler_state_map",
    )


def test_state_transition_dispatch_resolutions_write_under_snapshot(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert snap is not None

    observe_state_transition_dispatch_resolutions(
        snap,
        [
            {
                "fact_id": "state_transition_anchor:blk=100",
                "source_block_serial": 100,
                "source_state_const_hex": "0x89407346",
                "resolved_next_block_serial": 76,
                "resolved_next_state_const_hex": "0x0000000010743c4c",
                "resolved_next_state_const_u64": 0x10743C4C,
                "resolution_kind": "ollvm_state_dispatcher_map",
                "resolution_reason": "resolved_exact_state",
                "resolution_maturity": "MMAT_GLBOPT1",
            },
        ],
    )

    row = fake_conn.execute(
        "SELECT fact_id, resolved_next_block_serial, resolution_kind "
        "FROM state_transition_dispatch_resolutions"
    ).fetchone()
    assert row == (
        "state_transition_anchor:blk=100",
        76,
        "ollvm_state_dispatcher_map",
    )


def test_branch_ownership_proofs_write_under_snapshot(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert snap is not None

    observe_branch_ownership_proofs(
        snap,
        [
            {
                "proof_id": "branch_ownership:edge=1",
                "proof_kind": "OBFUSCATION_RESIDUE_ARM",
                "trusted": True,
                "reason": "trusted_opaque_branch_provenance",
                "source_block": 100,
                "branch_arm": 0,
                "source_state": 0x10,
                "target_state": 0x20,
                "target_entry": 76,
                "predicate_block": 100,
                "dispatcher_entry_block": 2,
                "oracle_kind": "explicit_opaque_provenance",
                "evidence": {"edge_kind": "CONDITIONAL_TRANSITION"},
                "payload": {"profile_name": "ollvm_state_map"},
            },
        ],
    )

    row = fake_conn.execute(
        "SELECT proof_kind, trusted, target_entry, oracle_kind "
        "FROM branch_ownership_proofs"
    ).fetchone()
    assert row == ("OBFUSCATION_RESIDUE_ARM", 1, 76, "explicit_opaque_provenance")


def test_capture_handler_short_circuits_when_no_conn():
    """If get_diag_db returns None, handler must no-op without raising."""

    def no_conn(_ea: int = 0, *_, **__):
        return None

    reset_diagnostic_bus()
    with patch(
        "d810.core.diag.event_handlers.get_diag_db", new=no_conn,
    ):
        install_diag_event_handlers()
        snap = request_capture_mba_snapshot(
            blocks=_make_snap_blocks(),
            label="L", func_ea=1, maturity="M", phase="post_d810",
        )
        # Subscriber WAS installed, so request_capture returned a ref;
        # but the handler couldn't get a conn so it no-op'd. The
        # follow-on event is then unmapped.
        assert snap is not None
        # No mapping -> follow-on does nothing.
        observe_modifications(snap, [Modification(mod_index=0, mod_type="x")])
        uninstall_diag_event_handlers()


# ---------------------------------------------------------------------------
# CFG provenance
# ---------------------------------------------------------------------------


def test_cfg_provenance_buffers_until_next_capture(fake_conn):
    # Emit some provenance events first.
    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="DELETE",
        block_serial=42,
        reason="dead block",
    )
    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="REDIRECT_EDGE",
        block_serial=10,
        target_serial=20,
    )

    # No rows yet — they're buffered.
    pre_rows = fake_conn.execute(
        "SELECT COUNT(*) FROM cfg_provenance"
    ).fetchone()
    assert pre_rows[0] == 0

    # Capture flushes.
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=1, maturity="M", phase="post_d810",
    )

    rows = fake_conn.execute(
        "SELECT pass_name, action, block_serial, target_serial "
        "FROM cfg_provenance ORDER BY rowid"
    ).fetchall()
    assert rows == [
        ("cfg_mutations", "DELETE", 42, None),
        ("cfg_mutations", "REDIRECT_EDGE", 10, 20),
    ]


def test_cfg_provenance_latest_writes_to_current_function_snapshot(fake_conn):
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=0x401000, maturity="M", phase="post_d810",
    )

    observe_cfg_provenance_latest(
        func_ea=0x401000,
        pass_name="EmulatedDispatcherUnflattener",
        action="VETO_REDIRECT",
        block_serial=42,
        target_serial=99,
        reason="direct_use_def_severance",
        extra={"orphaned_use_count": 3},
    )

    rows = fake_conn.execute(
        "SELECT pass_name, action, block_serial, target_serial, reason, "
        "extra_json FROM cfg_provenance"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][:5] == (
        "EmulatedDispatcherUnflattener",
        "VETO_REDIRECT",
        42,
        99,
        "direct_use_def_severance",
    )
    assert '"orphaned_use_count": 3' in rows[0][5]


def test_cfg_provenance_latest_appends_sequence(fake_conn):
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=0x401000, maturity="M", phase="post_d810",
    )

    for block_serial in (42, 43):
        observe_cfg_provenance_latest(
            func_ea=0x401000,
            pass_name="EmulatedDispatcherUnflattener",
            action="VETO_REDIRECT",
            block_serial=block_serial,
            target_serial=99,
            reason="direct_use_def_severance",
        )

    rows = fake_conn.execute(
        "SELECT seq, block_serial FROM cfg_provenance ORDER BY seq"
    ).fetchall()
    assert rows == [(0, 42), (1, 43)]


def test_watch_block_transition_event_writes_immediately(fake_conn):
    # The watch-transition handler does not need a SnapshotRef; it uses
    # func_ea directly and writes through snapshot_watch_transition.
    observe_watch_block_transition(
        func_ea=0x401000,
        apply_session_id="apply_test",
        mod_index=5,
        mod_type="RedirectGoto",
        phase="post_apply",
        block_serial=12,
        prev_type_name="BLT_NWAY",
        prev_succs=(13, 14),
        prev_preds=(11,),
        now_type_name="BLT_1WAY",
        now_succs=(13,),
        now_preds=(11,),
    )

    rows = fake_conn.execute(
        "SELECT mod_type, block_serial, prev_type_name, now_type_name "
        "FROM watch_block_transitions"
    ).fetchall()
    assert rows == [("RedirectGoto", 12, "BLT_NWAY", "BLT_1WAY")]


# ---------------------------------------------------------------------------
# Handler exception safety (bus catches)
# ---------------------------------------------------------------------------


def test_handler_exception_is_swallowed_by_bus(fake_conn, caplog):
    # Force the snapshot insert to fail and verify the bus swallows.
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L", func_ea=1, maturity="M", phase="post_d810",
    )
    assert snap is not None

    # Emit a modifications event with a Modification missing the
    # required fields by manipulating the SQL execution surface:
    # easier path: close the connection so subsequent writes raise.
    fake_conn.close()
    # Must not raise.
    emit(ModificationsObserved(
        snapshot=snap,
        modifications=(Modification(mod_index=0, mod_type="goto_redirect"),),
    ))
