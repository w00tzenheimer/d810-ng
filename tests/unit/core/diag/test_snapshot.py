"""Tests for MBA diagnostic snapshot writers."""
from __future__ import annotations

import json
import sqlite3

import pytest

from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    InstructionSnapshot,
    Modification,
    snapshot_dag,
    snapshot_mba,
    snapshot_modifications,
    snapshot_reachability,
)


def _make_insn(
    index: int,
    opcode: int = 4,
    opcode_name: str = "m_mov",
    ea: int = 0x1000,
    **kwargs: object,
) -> InstructionSnapshot:
    """Helper to create an InstructionSnapshot with sensible defaults."""
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=opcode,
        opcode_name=opcode_name,
        dstr=kwargs.pop("dstr", f"insn_{index}"),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def _make_block(
    serial: int,
    block_type: int = 1,
    type_name: str = "BLT_1WAY",
    nsucc: int = 1,
    npred: int = 1,
    succs: list[int] | None = None,
    preds: list[int] | None = None,
    insn_count: int = 2,
) -> BlockSnapshot:
    """Helper to create a BlockSnapshot with N instructions."""
    instructions = [_make_insn(i) for i in range(insn_count)]
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        type_name=type_name,
        nsucc=nsucc,
        npred=npred,
        succs=succs or [],
        preds=preds or [],
        instructions=instructions,
    )


@pytest.fixture()
def mock_mba_3_blocks() -> list[BlockSnapshot]:
    """Fixture with 3 blocks, 2 instructions each."""
    return [
        _make_block(0, succs=[1], preds=[], npred=0),
        _make_block(1, succs=[2], preds=[0]),
        _make_block(2, block_type=0, type_name="BLT_STOP", nsucc=0, succs=[], preds=[1]),
    ]


# ── Task 2: snapshot_mba tests ──────────────────────────────────────────


class TestSnapshotMba:
    def test_writes_blocks(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snap_id = snapshot_mba(
            conn, mock_mba_3_blocks, label="test", func_ea=0x1000
        )
        assert snap_id == 1
        rows = conn.execute(
            "SELECT serial, nsucc, npred FROM blocks WHERE snapshot_id=1"
        ).fetchall()
        assert len(rows) == 3

    def test_writes_instructions(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(conn, mock_mba_3_blocks, label="test", func_ea=0x1000)
        rows = conn.execute(
            "SELECT COUNT(*) FROM instructions WHERE snapshot_id=1"
        ).fetchone()
        assert rows[0] == 6  # 3 blocks * 2 insns

    def test_snapshot_id_increments(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        id1 = snapshot_mba(conn, mock_mba_3_blocks, label="first", func_ea=0x1000)
        id2 = snapshot_mba(conn, mock_mba_3_blocks, label="second", func_ea=0x1000)
        assert id2 == id1 + 1

    def test_succs_preds_stored_as_json(
        self, mock_mba_3_blocks: list[BlockSnapshot]
    ) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(conn, mock_mba_3_blocks, label="test", func_ea=0x1000)
        row = conn.execute(
            "SELECT succs, preds FROM blocks WHERE snapshot_id=1 AND serial=1"
        ).fetchone()
        assert json.loads(row[0]) == [2]
        assert json.loads(row[1]) == [0]

    def test_maturity_stored(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(
            conn,
            mock_mba_3_blocks,
            label="test",
            func_ea=0x1000,
            maturity="MMAT_GLBOPT1",
        )
        row = conn.execute(
            "SELECT maturity FROM snapshots WHERE id=1"
        ).fetchone()
        assert row[0] == "MMAT_GLBOPT1"

    def test_block_snapshot_str(self) -> None:
        blk = _make_block(5, succs=[6], preds=[4])
        text = str(blk)
        assert "blk[5]" in text
        assert "BLT_1WAY" in text

    def test_instruction_snapshot_str(self) -> None:
        insn = _make_insn(0, dstr="mov #0xABC, %var_8.8")
        assert str(insn) == "mov #0xABC, %var_8.8"

    def test_empty_blocks_list(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snap_id = snapshot_mba(conn, [], label="empty", func_ea=0x2000)
        row = conn.execute(
            "SELECT block_count FROM snapshots WHERE id=?", (snap_id,)
        ).fetchone()
        assert row[0] == 0

    def test_instruction_dest_stkoff_stored(self) -> None:
        """Verify dest_stkoff is stored and queryable for variable provenance."""
        insn = _make_insn(
            0,
            opcode=38,
            opcode_name="m_xdu",
            dest_type="mop_S",
            dest_stkoff=0x7F0,
            dest_size=8,
            src_l_type="mop_S",
            src_l_stkoff=0x3C,
            dstr="xdu %var_7BC.4, %var_8.8",
        )
        blk = BlockSnapshot(
            serial=207,
            block_type=1,
            type_name="BLT_1WAY",
            nsucc=1,
            npred=1,
            succs=[218],
            preds=[206],
            instructions=[insn],
        )
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(conn, [blk], label="test", func_ea=0x1000)
        row = conn.execute(
            "SELECT dest_stkoff, src_l_stkoff FROM instructions "
            "WHERE snapshot_id=1 AND block_serial=207 AND insn_index=0"
        ).fetchone()
        assert row[0] == 0x7F0
        assert row[1] == 0x3C


# ── Task 3: Strategy metadata writer tests ───────────────────────────────


class TestSnapshotDag:
    def test_writes_nodes_and_edges(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        # Need a snapshot row first
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )

        nodes = [
            DagNode(0x0ACD0BD5, "0x0ACD0BD5", 131, "TRANSITION"),
            DagNode(0x258ED455, "0x258ED455", 199, "TRANSITION"),
            DagNode(0x432DC789, "0x432DC789", 62, "EXIT"),
        ]
        edges = [
            DagEdge(0, 0x0ACD0BD5, 0x258ED455, "CONDITIONAL_TRANSITION",
                    source_block=174, source_arm=1, target_entry=199,
                    ordered_path="[131,174,176,199]"),
            DagEdge(1, 0x0ACD0BD5, None, "CONDITIONAL_RETURN",
                    source_block=174, source_arm=0,
                    ordered_path="[131,174,175,218,219]"),
            DagEdge(2, 0x258ED455, 0x6465D165, "TRANSITION",
                    source_block=199, target_entry=23,
                    ordered_path="[199]"),
            DagEdge(3, 0x6465D165, 0x432DC789, "TRANSITION",
                    source_block=23, target_entry=62,
                    ordered_path="[23,24,32]"),
        ]

        snapshot_dag(conn, 1, nodes, edges)

        node_count = conn.execute(
            "SELECT COUNT(*) FROM dag_nodes WHERE snapshot_id=1"
        ).fetchone()[0]
        edge_count = conn.execute(
            "SELECT COUNT(*) FROM dag_edges WHERE snapshot_id=1"
        ).fetchone()[0]
        assert node_count == 3
        assert edge_count == 4

    def test_edge_kind_constraint(self) -> None:
        """Verify invalid edge_kind raises IntegrityError."""
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )

        bad_edge = DagEdge(0, None, None, "BOGUS_KIND")
        with pytest.raises(sqlite3.IntegrityError):
            snapshot_dag(conn, 1, [], [bad_edge])

    def test_ordered_path_as_json(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )

        edge = DagEdge(
            0, 0xABC, 0xDEF, "TRANSITION",
            ordered_path=json.dumps([131, 174, 176]),
        )
        snapshot_dag(conn, 1, [], [edge])

        row = conn.execute(
            "SELECT ordered_path FROM dag_edges WHERE snapshot_id=1"
        ).fetchone()
        assert json.loads(row[0]) == [131, 174, 176]


class TestSnapshotModifications:
    def test_writes_modifications(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )

        mods = [
            Modification(
                mod_index=0,
                mod_type="goto_redirect",
                source_block=131,
                target_block=174,
                old_target=50,
                status="emitted",
            ),
            Modification(
                mod_index=1,
                mod_type="nop_instructions",
                source_block=32,
                status="skipped",
                reason="shared block",
            ),
            Modification(
                mod_index=2,
                mod_type="edge_redirect",
                source_block=206,
                target_block=217,
                old_target=207,
                status="emitted",
            ),
        ]

        snapshot_modifications(conn, 1, mods)

        rows = conn.execute(
            "SELECT mod_type, status FROM modifications WHERE snapshot_id=1 "
            "ORDER BY mod_index"
        ).fetchall()
        assert len(rows) == 3
        assert rows[0] == ("goto_redirect", "emitted")
        assert rows[1] == ("nop_instructions", "skipped")

    def test_empty_modifications(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )
        snapshot_modifications(conn, 1, [])
        count = conn.execute(
            "SELECT COUNT(*) FROM modifications WHERE snapshot_id=1"
        ).fetchone()[0]
        assert count == 0


class TestSnapshotReachability:
    def test_writes_classification(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 10, 0.0)"
        )

        all_serials = {0, 1, 2, 3, 4}
        reachable = {0, 1, 2, 3}
        bst_serials = {3, 4}
        gutted = {4}
        claimed = {0, 1}

        snapshot_reachability(
            conn, 1, all_serials,
            reachable=reachable,
            bst_serials=bst_serials,
            gutted=gutted,
            claimed_sources=claimed,
        )

        rows = conn.execute(
            "SELECT serial, is_bst, is_reachable, is_gutted, in_claimed "
            "FROM block_classification WHERE snapshot_id=1 ORDER BY serial"
        ).fetchall()
        assert len(rows) == 5

        # serial=0: not bst, reachable, not gutted, claimed
        assert rows[0] == (0, 0, 1, 0, 1)
        # serial=3: bst, reachable, not gutted, not claimed
        assert rows[3] == (3, 1, 1, 0, 0)
        # serial=4: bst, NOT reachable, gutted, not claimed
        assert rows[4] == (4, 1, 0, 1, 0)

    def test_empty_sets(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
        )
        snapshot_reachability(conn, 1, {0, 1, 2})
        rows = conn.execute(
            "SELECT serial, is_bst, is_reachable, is_gutted, in_claimed "
            "FROM block_classification WHERE snapshot_id=1 ORDER BY serial"
        ).fetchall()
        assert len(rows) == 3
        # All defaults: not bst, not reachable, not gutted, not claimed
        assert all(row[1:] == (0, 0, 0, 0) for row in rows)
