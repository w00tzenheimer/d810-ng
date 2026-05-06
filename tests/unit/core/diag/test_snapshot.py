"""Tests for MBA diagnostic snapshot writers."""
from __future__ import annotations

import json
import sqlite3

import pytest

from d810.core.diag.formatting import format_block_id
from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    InstructionSnapshot,
    Modification,
    _dual,
    _safe_int,
    snapshot_dag,
    snapshot_fact_conflicts,
    snapshot_fact_consumers,
    snapshot_fact_mappings,
    snapshot_fact_observations,
    snapshot_mba,
    snapshot_modifications,
    snapshot_rendered_program,
    snapshot_reachability,
)
from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    RenderedProgramLine,
    RenderedProgramNode,
    RenderedProgramSnapshot,
)
from d810.recon.facts import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
    FactStatus,
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

    def test_phase_stored(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(
            conn,
            mock_mba_3_blocks,
            label="test",
            func_ea=0x1000,
            phase="post_apply",
        )
        row = conn.execute(
            "SELECT phase FROM snapshots WHERE id=1"
        ).fetchone()
        assert row[0] == "post_apply"

    def test_phase_post_d810_stored(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(
            conn,
            mock_mba_3_blocks,
            label="test",
            func_ea=0x1000,
            phase="post_d810",
        )
        row = conn.execute(
            "SELECT phase FROM snapshots WHERE id=1"
        ).fetchone()
        assert row[0] == "post_d810"

    def test_phase_defaults_to_unknown(self, mock_mba_3_blocks: list[BlockSnapshot]) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snapshot_mba(
            conn, mock_mba_3_blocks, label="test", func_ea=0x1000
        )
        row = conn.execute(
            "SELECT phase FROM snapshots WHERE id=1"
        ).fetchone()
        assert row[0] == "unknown"


class TestSnapshotFacts:
    def test_writes_fact_lifecycle_rows(
        self, mock_mba_3_blocks: list[BlockSnapshot]
    ) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snap_id = snapshot_mba(
            conn,
            mock_mba_3_blocks,
            label="facts",
            func_ea=0x180012B60,
            maturity="MMAT_LOCOPT",
            phase="pre_d810",
        )

        snapshot_fact_observations(
            conn,
            snap_id,
            0x180012B60,
            [
                FactObservation(
                    fact_id="induction:10",
                    kind="InductionCarrierFact",
                    semantic_key="loop:byte-counter",
                    maturity="MMAT_LOCOPT",
                    phase="pre_d810",
                    confidence=0.95,
                    source_block=10,
                    source_ea=0x180013000,
                    payload={"stkoff": 0x680},
                    evidence=("write dominates loop",),
                )
            ],
        )
        snapshot_fact_mappings(
            conn,
            snap_id,
            0x180012B60,
            [
                FactMapping(
                    source_fact_id="induction:10",
                    source_maturity="MMAT_LOCOPT",
                    target_maturity="MMAT_GLBOPT1",
                    status=FactStatus.REMAPPED,
                    confidence=0.8,
                    target_block=20,
                    reason="block duplicated",
                )
            ],
        )
        snapshot_fact_consumers(
            conn,
            snap_id,
            0x180012B60,
            [
                FactConsumerRecord(
                    consumer="hodur.hcc",
                    strategy="HandlerChainComposer",
                    fact_id="induction:10",
                    maturity="MMAT_GLBOPT1",
                    decision="observed",
                    payload={"mode": "dry_run"},
                )
            ],
        )
        snapshot_fact_conflicts(
            conn,
            snap_id,
            0x180012B60,
            [
                FactConflict(
                    conflict_id="conflict:1",
                    fact_id="induction:10",
                    other_fact_id="induction:11",
                    maturity="MMAT_GLBOPT1",
                    conflict_kind="different_counter",
                    reason="two counters claim same loop",
                )
            ],
        )

        obs = conn.execute(
            "SELECT kind, payload, evidence, source_ea_hex "
            "FROM fact_observations WHERE fact_id='induction:10'"
        ).fetchone()
        assert obs[0] == "InductionCarrierFact"
        assert json.loads(obs[1]) == {"stkoff": 0x680}
        assert json.loads(obs[2]) == ["write dominates loop"]
        assert obs[3] == "0x0000000180013000"
        assert conn.execute("SELECT status FROM fact_mappings").fetchone()[0] == "REMAPPED"
        assert conn.execute("SELECT decision FROM fact_consumers").fetchone()[0] == "observed"
        assert (
            conn.execute("SELECT conflict_kind FROM fact_conflicts").fetchone()[0]
            == "different_counter"
        )

    def test_fact_mapping_and_consumer_indices_append_across_calls(
        self, mock_mba_3_blocks: list[BlockSnapshot]
    ) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        snap_id = snapshot_mba(
            conn,
            mock_mba_3_blocks,
            label="facts",
            func_ea=0x180012B60,
        )

        snapshot_fact_mappings(
            conn,
            snap_id,
            0x180012B60,
            [
                {
                    "source_fact_id": "a",
                    "source_maturity": "MMAT_LOCOPT",
                    "target_maturity": "MMAT_GLBOPT1",
                    "status": "ACTIVE",
                    "confidence": 1.0,
                }
            ],
        )
        snapshot_fact_mappings(
            conn,
            snap_id,
            0x180012B60,
            [
                {
                    "source_fact_id": "b",
                    "source_maturity": "MMAT_LOCOPT",
                    "target_maturity": "MMAT_GLBOPT1",
                    "status": "ACTIVE",
                    "confidence": 1.0,
                }
            ],
        )
        snapshot_fact_consumers(
            conn,
            snap_id,
            0x180012B60,
            [
                {
                    "consumer": "one",
                    "strategy": "s",
                    "fact_id": "a",
                    "maturity": "MMAT_GLBOPT1",
                    "decision": "used",
                }
            ],
        )
        snapshot_fact_consumers(
            conn,
            snap_id,
            0x180012B60,
            [
                {
                    "consumer": "two",
                    "strategy": "s",
                    "fact_id": "b",
                    "maturity": "MMAT_GLBOPT1",
                    "decision": "used",
                }
            ],
        )

        assert conn.execute(
            "SELECT mapping_index, source_fact_id FROM fact_mappings "
            "ORDER BY mapping_index"
        ).fetchall() == [(0, "a"), (1, "b")]
        assert conn.execute(
            "SELECT consumer_index, consumer FROM fact_consumers "
            "ORDER BY consumer_index"
        ).fetchall() == [(0, "one"), (1, "two")]

    def test_block_snapshot_str(self) -> None:
        blk = _make_block(5, succs=[6], preds=[4])
        text = str(blk)
        assert "blk[5]@synthetic" in text
        assert "BLT_1WAY" in text

    def test_block_snapshot_str_uses_start_ea(self) -> None:
        blk = _make_block(5, succs=[6], preds=[4])
        blk.start_ea = 0x180015F08
        text = str(blk)
        assert "blk[5]@0x180015F08" in text

    def test_format_block_id_marks_copy_lineage_and_unknown(self) -> None:
        assert format_block_id(245, lineage_ea=0x180014848) == (
            "blk[245]@copy-of:0x180014848"
        )
        assert format_block_id(245, synthetic=True) == "blk[245]@synthetic"
        assert format_block_id(245) == "blk[245]@unknown"

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

    def test_large_unsigned_ea_does_not_overflow(self) -> None:
        """IDA unsigned 64-bit EAs > 0x7FFFFFFFFFFFFFFF must not crash SQLite."""
        large_ea = 0xFFFFFFFFFFFFFF80  # typical IDA high address
        large_imm = 0xC5FB34A1D9A6E315  # unsigned 64-bit immediate
        insn = _make_insn(
            0,
            ea=large_ea,
            src_l_value=large_imm,
            src_l_type="mop_n",
            dstr="mov #0xC5FB.., dest",
        )
        blk = BlockSnapshot(
            serial=0,
            block_type=1,
            type_name="BLT_1WAY",
            start_ea=large_ea,
            end_ea=large_ea + 4,
            nsucc=1,
            npred=0,
            succs=[1],
            preds=[],
            instructions=[insn],
        )
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        # This must NOT raise OverflowError
        snap_id = snapshot_mba(conn, [blk], label="overflow", func_ea=large_ea)
        assert snap_id is not None

        # Verify hex columns store fixed-width 16-digit hex
        row = conn.execute(
            "SELECT start_ea_hex, start_ea_i64 FROM blocks "
            "WHERE snapshot_id=? AND serial=0",
            (snap_id,),
        ).fetchone()
        assert row[0] == "0xffffffffffffff80"  # hex text
        assert row[1] < 0  # stored as signed negative

        irow = conn.execute(
            "SELECT ea_hex, ea_i64, src_l_value_hex, src_l_value_i64 "
            "FROM instructions WHERE snapshot_id=? AND block_serial=0",
            (snap_id,),
        ).fetchone()
        assert irow[0] == "0xffffffffffffff80"  # ea hex
        assert irow[1] < 0  # ea signed negative
        assert irow[2] == "0xc5fb34a1d9a6e315"  # immediate hex
        assert irow[3] < 0  # large immediate signed negative


# ── Task 3: Strategy metadata writer tests ───────────────────────────────


class TestSnapshotDag:
    def test_writes_nodes_and_edges(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        # Need a snapshot row first
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
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
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )

        bad_edge = DagEdge(0, None, None, "BOGUS_KIND")
        with pytest.raises(sqlite3.IntegrityError):
            snapshot_dag(conn, 1, [], [bad_edge])

    def test_ordered_path_as_json(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
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
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
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
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
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
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 10, 0.0)"
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
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )
        snapshot_reachability(conn, 1, {0, 1, 2})
        rows = conn.execute(
            "SELECT serial, is_bst, is_reachable, is_gutted, in_claimed "
            "FROM block_classification WHERE snapshot_id=1 ORDER BY serial"
        ).fetchall()
        assert len(rows) == 3
        # All defaults: not bst, not reachable, not gutted, not claimed
        assert all(row[1:] == (0, 0, 0, 0) for row in rows)


class TestSnapshotRenderedProgram:
    def test_writes_rendered_program_rows(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )
        program = RenderedProgramSnapshot(
            variant_name="semantic_reference_like",
            order_strategy=RenderOrderStrategy.SEMANTIC.value,
            program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE.value,
            label_render_mode=LabelRenderMode.STATE_FAMILY.name.lower(),
            boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL.name.lower(),
            comment_mode=ProgramCommentMode.MINIMAL.name.lower(),
            nodes=(
                RenderedProgramNode(
                    node_index=0,
                    label_text="STATE_DEADBEEF",
                    node_kind="state_family",
                    line_start=3,
                    line_end=5,
                    state_label="STATE_DEADBEEF",
                    handler_serial=12,
                    entry_anchor=12,
                ),
            ),
            lines=(
                RenderedProgramLine(1, "=== LINEARIZED STATE PROGRAM ===", None, 0, "statement"),
                RenderedProgramLine(2, "", None, 0, "blank"),
                RenderedProgramLine(3, "STATE_DEADBEEF:", 0, 0, "label"),
                RenderedProgramLine(4, "    x = 1", 0, 1, "statement"),
                RenderedProgramLine(5, "    goto STATE_FEEDC0DE;", 0, 1, "goto", "STATE_FEEDC0DE"),
            ),
        )

        snapshot_rendered_program(conn, 1, program)

        meta = conn.execute(
            "SELECT variant_name, line_count, node_count FROM rendered_programs "
            "WHERE snapshot_id=1"
        ).fetchone()
        assert meta == ("semantic_reference_like", 5, 1)

        node = conn.execute(
            "SELECT label_text, node_kind, handler_serial, line_start, line_end "
            "FROM rendered_program_nodes WHERE snapshot_id=1 AND variant_name='semantic_reference_like'"
        ).fetchone()
        assert node == ("STATE_DEADBEEF", "state_family", 12, 3, 5)

        line = conn.execute(
            "SELECT line_kind, target_label, text FROM rendered_program_lines "
            "WHERE snapshot_id=1 AND variant_name='semantic_reference_like' AND line_no=5"
        ).fetchone()
        assert line == ("goto", "STATE_FEEDC0DE", "    goto STATE_FEEDC0DE;")

    def test_replaces_existing_variant_rows(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )
        program_a = RenderedProgramSnapshot(
            variant_name="semantic_reference_like",
            order_strategy="semantic",
            program_strategy="local_boundary_selective",
            label_render_mode="state_family",
            boundary_inline_mode="inline_single_level",
            comment_mode="minimal",
            nodes=(RenderedProgramNode(0, "STATE_A", "state_family", 1, 2),),
            lines=(
                RenderedProgramLine(1, "STATE_A:", 0, 0, "label"),
                RenderedProgramLine(2, "    goto EXIT_ROUTINE;", 0, 1, "goto", "EXIT_ROUTINE"),
            ),
        )
        program_b = RenderedProgramSnapshot(
            variant_name="semantic_reference_like",
            order_strategy="semantic",
            program_strategy="local_boundary_selective",
            label_render_mode="state_family",
            boundary_inline_mode="inline_single_level",
            comment_mode="minimal",
            nodes=(RenderedProgramNode(0, "STATE_B", "state_family", 1, 1),),
            lines=(RenderedProgramLine(1, "STATE_B:", 0, 0, "label"),),
        )

        snapshot_rendered_program(conn, 1, program_a)
        snapshot_rendered_program(conn, 1, program_b)

        counts = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM rendered_program_nodes WHERE snapshot_id=1 AND variant_name='semantic_reference_like'), "
            "(SELECT COUNT(*) FROM rendered_program_lines WHERE snapshot_id=1 AND variant_name='semantic_reference_like')"
        ).fetchone()
        assert counts == (1, 1)


class TestDual:
    """Tests for _dual helper that returns (hex_text, signed_i64) pairs."""

    def test_none_returns_none_pair(self) -> None:
        assert _dual(None) == (None, None)

    def test_small_value(self) -> None:
        h, i = _dual(0x1000)
        assert h == "0x0000000000001000"
        assert i == 0x1000

    def test_large_unsigned(self) -> None:
        h, i = _dual(0xFFFFFFFFFFFFFF80)
        assert h == "0xffffffffffffff80"
        assert i == -128

    def test_max_unsigned(self) -> None:
        h, i = _dual(0xFFFFFFFFFFFFFFFF)
        assert h == "0xffffffffffffffff"
        assert i == -1

    def test_zero(self) -> None:
        h, i = _dual(0)
        assert h == "0x0000000000000000"
        assert i == 0

    def test_hex_sorting_matches_numeric_sorting(self) -> None:
        """Verify that lexicographic sort of hex strings matches unsigned numeric sort."""
        values = [0x0, 0x100, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF]
        hex_strs = [_dual(v)[0] for v in values]
        # Already in ascending order; sort by hex string should preserve order
        assert hex_strs == sorted(hex_strs)


class TestSafeInt:
    """Tests for _safe_int helper that clamps unsigned 64-bit to signed."""

    def test_none_passthrough(self) -> None:
        assert _safe_int(None) is None

    def test_small_positive_unchanged(self) -> None:
        assert _safe_int(0x1000) == 0x1000

    def test_max_signed_unchanged(self) -> None:
        assert _safe_int(0x7FFFFFFFFFFFFFFF) == 0x7FFFFFFFFFFFFFFF

    def test_one_above_max_signed_wraps(self) -> None:
        assert _safe_int(0x8000000000000000) == -0x8000000000000000

    def test_max_unsigned_wraps(self) -> None:
        assert _safe_int(0xFFFFFFFFFFFFFFFF) == -1

    def test_typical_ida_ea(self) -> None:
        # 0xFFFFFFFFFFFFFF80 -> signed = -128
        assert _safe_int(0xFFFFFFFFFFFFFF80) == -128

    def test_zero_unchanged(self) -> None:
        assert _safe_int(0) == 0
