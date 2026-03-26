"""Regression tests for sub_7FFD3338C040 return-family structural facts.

These tests verify the return-family mapping extracted from the diagnostic
SQLite DB. They do NOT require IDA — they run against a pre-existing diag DB.

Run with:
    PYTHONPATH=src pytest tests/unit/test_return_family_ledger.py -v
"""
from __future__ import annotations

import json
import sqlite3
from collections import deque
from pathlib import Path

import pytest

# The diag DB from the March 24 21:19 run (OUTPUT.txt baseline).
_DB_PATH = Path(".tmp/logs/d810_logs/0000000180012b60_1774412338_33.diag.sqlite3")
_SNAPSHOT_ID = 17  # state_write_reconstruction_post_apply (POST-PTS, PRE-GutAndWire)


@pytest.fixture(scope="module")
def db():
    if not _DB_PATH.exists():
        pytest.skip(f"Diag DB not found: {_DB_PATH}")
    conn = sqlite3.connect(str(_DB_PATH))
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def blocks(db):
    rows = db.execute(
        "SELECT serial, type_name, preds, succs FROM blocks WHERE snapshot_id=?",
        (_SNAPSHOT_ID,),
    ).fetchall()
    return {
        serial: {"type": tn, "preds": json.loads(p), "succs": json.loads(s)}
        for serial, tn, p, s in rows
    }


@pytest.fixture(scope="module")
def reachable(blocks):
    visited: set[int] = set()
    q: deque[int] = deque([0])
    while q:
        cur = q.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        for s in blocks[cur]["succs"]:
            if s not in visited:
                q.append(s)
    return visited


@pytest.fixture(scope="module")
def return_slot_writers(db):
    rows = db.execute(
        """SELECT block_serial, opcode_name, src_l_type, src_l_stkoff, src_l_value_hex
           FROM instructions
           WHERE snapshot_id=? AND dest_stkoff=2032""",
        (_SNAPSHOT_ID,),
    ).fetchall()
    return {bs: {"opcode": op, "src_type": st, "src_stkoff": ss, "src_value": sv}
            for bs, op, st, ss, sv in rows}


@pytest.fixture(scope="module")
def v660_writers(db):
    rows = db.execute(
        """SELECT block_serial, src_l_value_hex
           FROM instructions
           WHERE snapshot_id=? AND dest_stkoff=1632 AND src_l_value_hex IS NOT NULL""",
        (_SNAPSHOT_ID,),
    ).fetchall()
    return {bs: val for bs, val in rows}


# ---------------------------------------------------------------------------
# Structural topology
# ---------------------------------------------------------------------------


class TestTopology:
    def test_blt_stop_is_blk240(self, blocks):
        stop_blocks = [s for s, b in blocks.items() if b["type"] == "BLT_STOP"]
        assert 240 in stop_blocks

    def test_blt_stop_preds(self, blocks):
        assert sorted(blocks[240]["preds"]) == [218, 235, 236, 237, 238, 239]

    def test_shared_epilogue_preds(self, blocks):
        assert sorted(blocks[218]["preds"]) == [41, 47, 71, 217]

    def test_blk217_preds(self, blocks):
        assert sorted(blocks[217]["preds"]) == [207, 215]

    def test_blk71_preds(self, blocks):
        assert sorted(blocks[71]["preds"]) == [16, 70]

    def test_pts_clones_single_pred(self, blocks):
        """Each PTS clone has exactly one predecessor (the return root)."""
        expected = {235: [175], 236: [94], 237: [27], 238: [119], 239: [162]}
        for clone, exp_preds in expected.items():
            assert blocks[clone]["preds"] == exp_preds, f"blk[{clone}]"

    def test_total_blocks(self, blocks):
        assert len(blocks) == 241


# ---------------------------------------------------------------------------
# Reachability (2-gap proof)
# ---------------------------------------------------------------------------


class TestReachability:
    def test_reachable_count(self, reachable):
        assert len(reachable) == 193

    def test_blk41_unreachable(self, reachable):
        assert 41 not in reachable

    def test_blk47_unreachable(self, reachable):
        assert 47 not in reachable

    def test_blk40_unreachable(self, reachable):
        """blk[41]'s predecessor is also unreachable."""
        assert 40 not in reachable

    def test_blk46_unreachable(self, reachable):
        """blk[47]'s predecessor is also unreachable."""
        assert 46 not in reachable

    def test_blk70_unreachable(self, reachable):
        """blk[71]'s second pred (the dead one) is unreachable."""
        assert 70 not in reachable

    def test_blk71_reachable(self, reachable):
        assert 71 in reachable

    def test_blk16_reachable(self, reachable):
        """blk[71]'s live predecessor."""
        assert 16 in reachable

    def test_all_pts_roots_reachable(self, reachable):
        for root in [27, 94, 119, 162, 175]:
            assert root in reachable, f"blk[{root}]"

    def test_blk217_family_both_reachable(self, reachable):
        assert 207 in reachable
        assert 215 in reachable

    def test_eight_live_families(self, reachable, blocks):
        """Count live semantic families: 5 PTS + 3 epilogue families."""
        # PTS roots
        pts_roots = [175, 94, 27, 119, 162]
        live_pts = sum(1 for r in pts_roots if r in reachable)
        assert live_pts == 5

        # Epilogue: blk[218] feeders, split on multi-pred
        # blk[71]: preds [16(R), 70(U)] → 1 live family (via 16)
        # blk[217]: preds [207(R), 215(R)] → 2 live families
        # blk[41]: unreachable → 0
        # blk[47]: unreachable → 0
        epilogue_live = 0
        for feeder in blocks[218]["preds"]:
            if feeder not in reachable:
                continue
            feeder_preds = blocks[feeder]["preds"]
            if len(feeder_preds) <= 1:
                epilogue_live += 1
            else:
                epilogue_live += sum(1 for p in feeder_preds if p in reachable)

        assert live_pts + epilogue_live == 8


# ---------------------------------------------------------------------------
# Return-slot writers
# ---------------------------------------------------------------------------


class TestReturnSlotWriters:
    def test_expected_writers(self, return_slot_writers):
        assert sorted(return_slot_writers.keys()) == [94, 119, 162, 175, 217]

    def test_blk162_writes_v6(self, return_slot_writers):
        """blk[162] copies %var_7C8.8 (stkoff=0x30=48) to return slot → v6."""
        w = return_slot_writers[162]
        assert w["src_stkoff"] == 48  # stkoff 0x30 = v6

    def test_blk119_writes_v79_ptr(self, return_slot_writers):
        """blk[119] copies %var_178.8 (stkoff=0x680=1664) to return slot → a5+0xD0."""
        w = return_slot_writers[119]
        assert w["src_stkoff"] == 1664  # stkoff 0x680 = v79 ptr

    def test_blk217_writes_v79_ptr(self, return_slot_writers):
        w = return_slot_writers[217]
        assert w["src_stkoff"] == 1664

    def test_no_leaked_state_writers(self, return_slot_writers):
        """No block writes the OLLVM state var (stkoff=0x3C=60) to return slot."""
        for bs, w in return_slot_writers.items():
            assert w["src_stkoff"] != 60, (
                f"blk[{bs}] writes state var to return slot — leaked constant"
            )


# ---------------------------------------------------------------------------
# v660 (byte cursor) writers
# ---------------------------------------------------------------------------


class TestBlk71UpstreamWriter:
    """blk[71]'s return-slot attribution: no direct-path writer found."""

    def test_blk71_no_return_slot_writer(self, return_slot_writers):
        """blk[71] has no return-slot writer in snapshot 17 (DSVE stripped xdu)."""
        assert 71 not in return_slot_writers

    def test_blk71_present_in_snapshot17(self, blocks):
        """blk[71] exists in snapshot 17 as a bare goto shell."""
        assert 71 in blocks

    def test_blk71_disappears_after_post_d810_compaction(self, db):
        """blk[71] disappears after IDA's post-d810 block merge/renumber.

        Serial 71 exists in pre-collapse snapshots but not in the
        post-d810 compacted graph (maturity_MMAT_GLBOPT1_post_d810).
        The specific snapshot ID varies by DB — we find it by label.
        """
        post_d810 = db.execute(
            "SELECT id, block_count FROM snapshots WHERE label='maturity_MMAT_GLBOPT1_post_d810'"
        ).fetchone()
        if post_d810 is None:
            pytest.skip("No maturity_MMAT_GLBOPT1_post_d810 snapshot in this DB")
        sid, bc = post_d810
        row = db.execute(
            "SELECT serial FROM blocks WHERE snapshot_id=? AND serial=71", (sid,)
        ).fetchone()
        assert row is None, (
            f"blk[71] should be absent in post_d810 compaction "
            f"(snapshot {sid}, {bc} blocks)"
        )

    def test_no_upstream_return_writer_on_blk71_path(self, db, reachable):
        """No reachable predecessor of blk[71] writes to return slot (stkoff=2032).

        This means the return value for the blk[71] family is NOT set on
        its direct predecessor path. The reaching definition likely comes
        from a different control flow path (plausibly loop-carried), but
        that attribution is inferred, not proven from this data alone.
        """
        import json
        from collections import deque

        SID = _SNAPSHOT_ID
        rows = db.execute(
            "SELECT serial, preds FROM blocks WHERE snapshot_id=?", (SID,)
        ).fetchall()
        pred_map = {s: json.loads(p) for s, p in rows}

        visited: set[int] = set()
        q: deque[int] = deque([71])
        found_writer = False

        while q:
            cur = q.popleft()
            if cur in visited:
                continue
            visited.add(cur)

            writers = db.execute(
                "SELECT block_serial FROM instructions "
                "WHERE snapshot_id=? AND block_serial=? AND dest_stkoff=2032",
                (SID, cur),
            ).fetchall()
            if writers:
                found_writer = True
                break

            for p in pred_map.get(cur, []):
                if p in reachable and p not in visited:
                    q.append(p)

        assert not found_writer, "Expected no return-slot writer on blk[71] backward path"


class TestV660Writers:
    def test_expected_v660_writers(self, v660_writers):
        expected_blocks = {102, 119, 162, 164, 207}
        assert set(v660_writers.keys()) == expected_blocks

    def test_v660_values(self, v660_writers):
        assert v660_writers[119] == "0x0000000000000002"
        assert v660_writers[162] == "0x0000000000000003"
        assert v660_writers[207] == "0x0000000000000000"
        assert v660_writers[164] == "0x0000000000000004"
        assert v660_writers[102] == "0x0000000000000005"
