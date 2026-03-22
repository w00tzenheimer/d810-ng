"""Tests that verify diagnostic queries catch real debugging scenarios.

These tests drive Task 4 (query helpers). They will FAIL until query.py
is implemented -- the expected failure mode is ImportError or AttributeError
on the query functions, NOT on fixture setup.
"""
from __future__ import annotations

import sqlite3

from d810.diag.query import block_detail, chain, return_paths, var_writes
from tests.unit.diag.fixtures import create_sub_7ffd_scenario


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    create_sub_7ffd_scenario(conn)
    return conn


def test_chain_detects_broken_hop_at_blk206():
    """The chain 131->...->206->217->218 has a broken hop:
    blk[206].succs=[207,208], not 217.
    """
    conn = _db()
    result = chain(
        conn, 1, [131, 174, 176, 200, 23, 24, 32, 62, 206, 217, 218, 219]
    )
    # Find the hop from 206 to 217
    hop_206 = next(r for r in result if r and r["serial"] == 206)
    assert hop_206["hop_ok"] is False, (
        "blk[206]->blk[217] should be broken (actual succ is 207)"
    )
    assert hop_206["expected_next"] == 217


def test_chain_confirms_correct_hops():
    """All hops except 206->217 should be correct."""
    conn = _db()
    result = chain(conn, 1, [131, 174, 176, 200, 23, 24, 32, 62])
    for r in result:
        if r and "hop_ok" in r:
            assert r["hop_ok"] is True, f"blk[{r['serial']}] hop should be correct"


def test_var_writes_finds_return_slot_clobber():
    """var_writes for stkoff=0x7F0 (return slot) should find blk[175],
    blk[207], and blk[217].
    """
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x7F0)
    writer_blocks = {w["block_serial"] for w in writes}
    assert 175 in writer_blocks, "blk[175] writes correct MBA result to return slot"
    assert 207 in writer_blocks, (
        "blk[207] clobbers return slot with m_xdu from state var"
    )
    assert 217 in writer_blocks, "blk[217] writes var_178 to return slot"


def test_var_writes_identifies_mxdu_as_state_var_source():
    """blk[207]'s write to var_8 sources from stkoff=0x3C (state var),
    not 0x30 (var_7C8).
    """
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x7F0)
    mxdu_write = next(w for w in writes if w["block_serial"] == 207)
    assert mxdu_write["opcode_name"] == "m_xdu"
    assert mxdu_write["src_l_stkoff"] == 0x3C, (
        "m_xdu reads from state var (0x3C), not var_7C8 (0x30)"
    )


def test_return_path_identifies_mxdu_on_path():
    """CONDITIONAL_RETURN edge [206,207,218,219] includes blk[207]
    which has m_xdu.
    """
    conn = _db()
    paths = return_paths(conn, 1)
    # Find the 0x298372CC return path
    ret_path = next(p for p in paths if 206 in p.get("path_serials", []))
    assert 207 in ret_path["path_serials"]
    # The hop check should flag blk[207] as containing an m_xdu to the return slot
    hop_207 = next(h for h in ret_path["hops"] if h["serial"] == 207)
    assert hop_207.get("has_return_slot_write") is True
    assert hop_207.get("write_opcode") == "m_xdu"


def test_var_writes_finds_unnopped_state_write_at_blk32():
    """blk[32] writes 0x432DC789 to state var -- the un-NOPed
    duplicate-and-redirect site.
    """
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x3C)
    blk32_write = next(w for w in writes if w["block_serial"] == 32)
    assert blk32_write["src_l_value"] == 0x432DC789
    assert blk32_write["opcode_name"] == "m_mov"


def test_block_detail_shows_valranges_from_meta():
    """block_detail for blk[206] should expose valranges from meta JSON."""
    conn = _db()
    detail = block_detail(conn, 1, serial=206)
    assert detail is not None
    assert detail["type_name"] == "BLT_2WAY"
    assert "valranges" in detail.get("meta_parsed", {})
    assert detail["meta_parsed"]["valranges"]["0x3C"] == "==298372CC"
