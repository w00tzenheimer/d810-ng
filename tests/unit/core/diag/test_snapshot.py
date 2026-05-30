"""Tests for MBA diagnostic snapshot writers."""
from __future__ import annotations

import json
import sqlite3

import pytest

from d810.core.diag.formatting import format_block_id
from d810.core.diag.schema import create_tables
from d810.cfg.block_lineage import (
    BlockLineageEntry,
    buffer_block_lineage,
    reset_pending_block_lineage,
)
from d810.core.diag.snapshot import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    InstructionSnapshot,
    Modification,
    _dual,
    _safe_int,
    dag_node_diagnostic_state,
    snapshot_branch_ownership_proofs,
    snapshot_dag,
    snapshot_dag_local_facts,
    snapshot_fact_conflicts,
    snapshot_fact_consumers,
    snapshot_fact_mappings,
    snapshot_fact_observations,
    snapshot_mba,
    snapshot_modifications,
    snapshot_rendered_program,
    snapshot_reachability,
    snapshot_state_dispatcher_rows,
    snapshot_state_transition_dispatch_resolutions,
    snapshot_switch_case_transition_facts,
)
from d810.analyses.control_flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    LinearizedStateDag,
    LocalEdgeKind,
    LocalSegmentKind,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    RenderedProgramLine,
    RenderedProgramNode,
    RenderedProgramSnapshot,
    StateDagNode,
    StateDagNodeKey,
    StateLocalEdge,
    StateLocalSegment,
    StateNodeKind,
)
from d810.analyses.value_flow.facts import FactConflict, FactConsumerRecord, FactMapping, FactObservation, FactStatus


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


def test_snapshot_state_dispatcher_rows_round_trip() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
        "'unknown', 0, 0.0)"
    )

    snapshot_state_dispatcher_rows(
        conn,
        1,
        [
            {
                "state_const": 0x89407346,
                "target_block": 76,
                "dispatcher_entry_block": 5,
                "compare_block": 6,
                "dispatcher_kind": "CONDITIONAL_CHAIN",
                "branch_kind": "jz_taken",
                "payload": {"target_ea_hex": "0x00000001800178e3"},
            }
        ],
        dispatcher_entry_block=5,
        dispatcher_kind="CONDITIONAL_CHAIN",
        maturity="MMAT_GLBOPT1",
    )

    row = conn.execute(
        "SELECT state_const_hex, target_block, dispatcher_kind, payload_json "
        "FROM state_dispatcher_rows"
    ).fetchone()
    assert row[:3] == ("0x0000000089407346", 76, "CONDITIONAL_CHAIN")
    payload = json.loads(row[3])
    assert payload["row_kind"] is None
    assert payload["branch_kind"] == "jz_taken"
    assert payload["target_ea_hex"] == "0x00000001800178e3"


def test_snapshot_state_transition_dispatch_resolutions_round_trip() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
        "'unknown', 0, 0.0)"
    )

    snapshot_state_transition_dispatch_resolutions(
        conn,
        1,
        [
            {
                "fact_id": "fact-1",
                "source_block_serial": 10,
                "source_state_const_hex": "0x10",
                "resolved_next_block_serial": 20,
                "resolved_next_state_const_hex": "0x20",
                "resolved_next_state_const_u64": 0x20,
                "resolution_kind": "state_dispatcher_row",
                "resolution_reason": "resolved_exact_state",
                "resolution_maturity": "MMAT_GLBOPT1",
            }
        ],
    )

    row = conn.execute(
        "SELECT fact_id, resolved_next_block_serial, resolution_reason "
        "FROM state_transition_dispatch_resolutions"
    ).fetchone()
    assert row == ("fact-1", 20, "resolved_exact_state")


def test_snapshot_state_transition_dispatch_resolutions_deduplicates_rows() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
        "'unknown', 0, 0.0)"
    )

    snapshot_state_transition_dispatch_resolutions(
        conn,
        1,
        [
            {
                "fact_id": "fact-1",
                "source_block_serial": 10,
                "source_state_const_hex": "0x10",
                "resolved_next_block_serial": 20,
                "resolved_next_state_const_hex": "0x20",
                "resolved_next_state_const_u64": 0x20,
                "resolution_kind": "state_dispatcher_row",
                "resolution_reason": "first",
                "resolution_maturity": "MMAT_GLBOPT1",
            },
            {
                "fact_id": "fact-1",
                "source_block_serial": 10,
                "source_state_const_hex": "0x10",
                "resolved_next_block_serial": 21,
                "resolved_next_state_const_hex": "0x21",
                "resolved_next_state_const_u64": 0x21,
                "resolution_kind": "state_dispatcher_row",
                "resolution_reason": "latest",
                "resolution_maturity": "MMAT_GLBOPT1",
            },
        ],
    )

    rows = conn.execute(
        "SELECT fact_id, resolved_next_block_serial, resolution_reason "
        "FROM state_transition_dispatch_resolutions"
    ).fetchall()
    assert rows == [("fact-1", 21, "latest")]


def test_snapshot_switch_case_transition_facts_round_trip() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
        "'unknown', 0, 0.0)"
    )

    snapshot_switch_case_transition_facts(
        conn,
        1,
        [
            {
                "fact_id": "tigress_switch:case=4:conditional",
                "source_state_hex": "0x0000000000000004",
                "source_state_i64": 4,
                "case_entry_block": 104,
                "transition_kind": "CONDITIONAL",
                "next_state_a_hex": "0x0000000000000009",
                "next_state_a_i64": 9,
                "next_state_b_hex": "0x000000000000000d",
                "next_state_b_i64": 13,
                "proof_kind": "REAL_DATA_DEPENDENT",
                "trusted": 1,
                "reason": "conditional_case_transition_source_predicate",
                "payload": {"profile_name": "tigress_switch"},
            }
        ],
    )

    row = conn.execute(
        "SELECT source_state_hex, transition_kind, next_state_a_hex, "
        "next_state_b_hex, proof_kind, trusted "
        "FROM switch_case_transition_facts"
    ).fetchone()
    assert row == (
        "0x0000000000000004",
        "CONDITIONAL",
        "0x0000000000000009",
        "0x000000000000000d",
        "REAL_DATA_DEPENDENT",
        1,
    )


def test_snapshot_branch_ownership_proofs_round_trip() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
        "'unknown', 0, 0.0)"
    )

    snapshot_branch_ownership_proofs(
        conn,
        1,
        [
            {
                "proof_id": "branch_ownership:edge=1",
                "proof_kind": "OBFUSCATION_RESIDUE_ARM",
                "trusted": True,
                "reason": "trusted_opaque_branch_provenance",
                "source_block": 10,
                "branch_arm": 1,
                "source_state": 0x10,
                "target_state": 0x20,
                "target_entry": 30,
                "predicate_block": 10,
                "dispatcher_entry_block": 2,
                "oracle_kind": "explicit_opaque_provenance",
                "evidence": {"edge_kind": "CONDITIONAL_TRANSITION"},
                "payload": {"profile_name": "ollvm_state_map"},
            }
        ],
    )

    row = conn.execute(
        "SELECT proof_kind, trusted, source_block, source_state_hex, "
        "target_state_hex, oracle_kind FROM branch_ownership_proofs"
    ).fetchone()
    assert row == (
        "OBFUSCATION_RESIDUE_ARM",
        1,
        10,
        "0x0000000000000010",
        "0x0000000000000020",
        "explicit_opaque_provenance",
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

    def test_writes_block_observations(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        block = BlockSnapshot(
            serial=33,
            block_type=1,
            type_name="BLT_1WAY",
            start_ea=0x18001340F,
            nsucc=1,
            npred=1,
            succs=[24],
            preds=[28],
            instructions=[
                _make_insn(
                    0,
                    ea=0x18001340F,
                    opcode=4,
                    opcode_name="m_mov",
                    dest_type="mop_S",
                    dest_stkoff=0x400,
                    src_l_type="mop_n",
                    src_l_value=0x27EEEA11,
                ),
                _make_insn(
                    1,
                    ea=0x180013421,
                    opcode=6,
                    opcode_name="m_goto",
                ),
            ],
        )
        snapshot_mba(
            conn,
            [block],
            label="test",
            func_ea=0x1000,
            maturity="MMAT_GLBOPT1",
            phase="post_apply",
        )

        row = conn.execute(
            "SELECT maturity, phase, start_ea_hex, insn_count, "
            "insn_ea_fingerprint, opcode_fingerprint, operand_fingerprint, "
            "body_fingerprint "
            "FROM block_observations WHERE snapshot_id=1 AND serial=33"
        ).fetchone()
        assert row[0] == "MMAT_GLBOPT1"
        assert row[1] == "post_apply"
        assert row[2] == "0x000000018001340f"
        assert row[3] == 2
        assert json.loads(row[4]) == [
            "0x000000018001340f",
            "0x0000000180013421",
        ]
        assert json.loads(row[5]) == [4, 6]
        operand_fp = json.loads(row[6])
        assert operand_fp[0]["d_o"] == 0x400
        assert operand_fp[0]["l_v"] == "0x0000000027eeea11"
        assert row[7].startswith("fnv1a64:0x")

    def test_duplicate_ea_observations_remain_distinct_by_serial(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        original = BlockSnapshot(
            serial=32,
            block_type=1,
            type_name="BLT_1WAY",
            start_ea=0x180013274,
            nsucc=1,
            npred=1,
            succs=[2],
            preds=[24],
            instructions=[_make_insn(0, ea=0x180013274, opcode=4)],
        )
        clone = BlockSnapshot(
            serial=220,
            block_type=1,
            type_name="BLT_1WAY",
            start_ea=0x180013274,
            nsucc=1,
            npred=1,
            succs=[62],
            preds=[31],
            instructions=[_make_insn(0, ea=0x180013274, opcode=4)],
        )
        snapshot_mba(
            conn,
            [original, clone],
            label="post_hcc",
            func_ea=0x1000,
            maturity="MMAT_GLBOPT1",
            phase="post_apply",
        )

        rows = conn.execute(
            "SELECT serial, start_ea_hex, body_fingerprint "
            "FROM block_observations WHERE start_ea_hex=? ORDER BY serial",
            ("0x0000000180013274",),
        ).fetchall()
        assert [row[0] for row in rows] == [32, 220]
        assert rows[0][1] == rows[1][1]
        assert rows[0][2] == rows[1][2]

    def test_snapshot_mba_flushes_pending_block_lineage(self) -> None:
        reset_pending_block_lineage()
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        block = BlockSnapshot(
            serial=220,
            block_type=1,
            type_name="BLT_1WAY",
            start_ea=0x180013274,
            nsucc=1,
            npred=1,
            succs=[62],
            preds=[31],
            instructions=[_make_insn(0, ea=0x180013274, opcode=4)],
        )
        buffer_block_lineage([
            BlockLineageEntry(
                serial=220,
                origin_snapshot_id=7,
                origin_serial=32,
                origin_start_ea_hex="0x180013274",
                origin_body_fingerprint="fp=[0x180013274:op4]",
                creation_kind="edge_split_trampoline",
                creation_reason="patch_plan:edge_split_trampoline",
                planner_block_id="edge_split:0",
                source_mod_type="EdgeRedirectViaPredSplit",
                extra_json='{"origin_label":"blk[32]@0x180013274"}',
            )
        ])
        try:
            snap_id = snapshot_mba(
                conn,
                [block],
                label="post_hcc",
                func_ea=0x1000,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )
            row = conn.execute(
                "SELECT snapshot_id, serial, origin_snapshot_id, origin_serial, "
                "creation_kind, planner_block_id "
                "FROM block_lineage WHERE snapshot_id=? AND serial=220",
                (snap_id,),
            ).fetchone()
            assert row == (
                snap_id,
                220,
                7,
                32,
                "edge_split_trampoline",
                "edge_split:0",
            )
        finally:
            reset_pending_block_lineage()

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

    def test_snapshot_dag_local_facts_writes_node_internals(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )

        node = StateDagNode(
            key=StateDagNodeKey(handler_serial=205, state_const=0x298372CC),
            kind=StateNodeKind.RANGE_BACKED,
            state_label="STATE_298372CC",
            handler_serial=205,
            entry_anchor=205,
            owned_blocks=(205, 207, 206, 217, 218),
            exclusive_blocks=(205, 207, 206),
            shared_suffix_blocks=(217, 218),
            local_segments=(
                StateLocalSegment("blk[205]", LocalSegmentKind.BRANCH, (205,)),
                StateLocalSegment("blk[207]", LocalSegmentKind.STRAIGHT_LINE, (207,)),
                StateLocalSegment("blk[206]", LocalSegmentKind.STRAIGHT_LINE, (206,)),
                StateLocalSegment("blk[217]", LocalSegmentKind.SHARED_SUFFIX, (217,)),
                StateLocalSegment("blk[218]", LocalSegmentKind.TERMINAL_SUFFIX, (218,)),
            ),
            local_edges=(
                StateLocalEdge("blk[205]", "blk[207]", LocalEdgeKind.TAKEN, 1),
                StateLocalEdge("blk[205]", "blk[206]", LocalEdgeKind.FALLTHROUGH, 0),
                StateLocalEdge("blk[206]", "blk[217]", LocalEdgeKind.SHARED_SUFFIX),
                StateLocalEdge("blk[217]", "blk[218]", LocalEdgeKind.TERMINAL),
            ),
        )
        dag = LinearizedStateDag(
            dispatcher_entry_serial=1,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=0x298372CC,
            bst_node_blocks=(),
            nodes=(node,),
            edges=(),
        )

        snapshot_dag_local_facts(conn, 1, dag)

        block_rows = conn.execute(
            "SELECT role, block_serial FROM dag_node_blocks "
            "WHERE snapshot_id=1 ORDER BY role, block_serial"
        ).fetchall()
        assert ("shared_suffix", 217) in block_rows
        assert ("owned", 205) in block_rows

        segment_row = conn.execute(
            "SELECT kind, blocks_json FROM dag_local_segments "
            "WHERE snapshot_id=1 AND segment_id='blk[205]'"
        ).fetchone()
        assert segment_row == ("BRANCH", "[205]")

        edge_rows = conn.execute(
            "SELECT source_segment_id, target_segment_id, kind, branch_arm "
            "FROM dag_local_edges WHERE snapshot_id=1 ORDER BY edge_index"
        ).fetchall()
        assert edge_rows[0] == ("blk[205]", "blk[207]", "TAKEN", 1)
        assert edge_rows[-1] == ("blk[217]", "blk[218]", "TERMINAL", None)

    def test_range_only_node_identity_matches_outer_and_local_tables(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
        )

        node = StateDagNode(
            key=StateDagNodeKey(
                handler_serial=205,
                state_const=None,
                range_lo=0x29837000,
                range_hi=0x29837FFF,
            ),
            kind=StateNodeKind.RANGE_BACKED,
            state_label="STATE_29837000",
            handler_serial=205,
            entry_anchor=205,
            owned_blocks=(205,),
            exclusive_blocks=(205,),
            shared_suffix_blocks=(),
            local_segments=(
                StateLocalSegment("blk[205]", LocalSegmentKind.STRAIGHT_LINE, (205,)),
            ),
            local_edges=(),
        )
        dag = LinearizedStateDag(
            dispatcher_entry_serial=1,
            state_var_stkoff=0x3C,
            pre_header_serial=None,
            initial_state=None,
            bst_node_blocks=(),
            nodes=(node,),
            edges=(),
        )
        diagnostic_state = dag_node_diagnostic_state(node)
        assert diagnostic_state == 0x29837000

        snapshot_dag(
            conn,
            1,
            [DagNode(diagnostic_state, "ignored", 205, "RANGE_BACKED")],
            [],
        )
        snapshot_dag_local_facts(conn, 1, dag)

        outer_hex = conn.execute(
            "SELECT state_hex FROM dag_nodes WHERE snapshot_id=1"
        ).fetchone()[0]
        local_hex = conn.execute(
            "SELECT DISTINCT state_hex FROM dag_node_blocks WHERE snapshot_id=1"
        ).fetchone()[0]
        assert outer_hex == "0x0000000029837000"
        assert local_hex == outer_hex

    def test_anonymous_node_identity_is_stable_and_nonzero(self) -> None:
        key = StateDagNodeKey(handler_serial=77)

        first = dag_node_diagnostic_state(key)
        second = dag_node_diagnostic_state(key)

        assert first == second
        assert first != 0
        assert f"0x{first:016x}".startswith("0xd810")


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
