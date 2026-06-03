"""Unit tests for ``python -m d810.diagnostics residual-worksheet``.

Covers:

- pure helpers (``parse_int``, ``_normalize_maturity_name``, ``_collapse``,
  ``_truncate``, ``_unique_preserve_order``, ``parse_residual_log_events``)
- feeder-block selection (``detect_feeder_blocks``, ``_bfs_reachable``)
- end-to-end ``build_residual_dispatcher_worksheet`` on a synthetic
  SQLite fixture (no recon DB, no log) and the rendered Markdown / JSON
  output
- the CLI: ``--list-snapshots``, missing diag DB, end-to-end Markdown
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from d810.core.diag import create_diag_database, diag_models_on
from d810.core.diag.models import (
    Block,
    BlockClassification,
    Instruction,
    RenderedProgramLine,
    RenderedProgramNode,
    Snapshot,
)
from d810.diagnostics.residual_worksheet import (
    BlockInfo,
    DagEdgeInfo,
    ResidualLogEvent,
    TransitionMeta,
    _bfs_reachable,
    _collapse,
    _normalize_maturity_name,
    _truncate,
    _unique_preserve_order,
    build_residual_dispatcher_worksheet,
    detect_feeder_blocks,
    parse_int,
    parse_residual_log_events,
    render_json,
    render_markdown,
    render_tsv,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# parse_int / _normalize_maturity_name / small helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("0", 0),
        ("42", 42),
        ("0x10", 16),
        ("0X1800134A5", 0x1800134A5),
    ],
)
def test_parse_int_accepts_dec_and_hex(text, expected):
    assert parse_int(text) == expected


def test_parse_int_rejects_garbage():
    with pytest.raises(ValueError):
        parse_int("not a number")


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("GLBOPT1", "MMAT_GLBOPT1"),
        ("mmat_locopt", "MMAT_LOCOPT"),
        ("MMAT_GLBOPT2", "MMAT_GLBOPT2"),
    ],
)
def test_normalize_maturity_name(raw, expected):
    assert _normalize_maturity_name(raw) == expected


def test_collapse_squashes_whitespace():
    assert _collapse("  a  b\nc\t d ") == "a b c d"


def test_truncate_returns_input_when_short():
    assert _truncate("short", limit=20) == "short"


def test_truncate_adds_ellipsis_when_over_limit():
    out = _truncate("x" * 200, limit=20)
    assert out.endswith("...")
    assert len(out) <= 20


def test_unique_preserve_order_drops_dupes_and_empty():
    assert _unique_preserve_order(["a", "", "b", "a", "c", "b"]) == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# parse_residual_log_events
# ---------------------------------------------------------------------------


PRED_SPLIT_LINE = (
    "[TRACE] LFG DAG: residual dispatcher pred-split blk[123] via blk[45]"
    " -> blk[201] (state 0x5FE86821)"
)
GOTO_LINE = (
    "[TRACE] LFG DAG: residual dispatcher handoff blk[7] -> blk[8]"
    " (state 0xDEADBEEF)"
)
CYCLE_LINE = (
    "[TRACE] LFG DAG: residual handoff blk[12] -> blk[34]"
    " still forms a non-dispatcher cycle, skipping"
)
NOOP_LINE = (
    "[TRACE] LFG DAG: residual handoff blk[5] already targets blk[5],"
    " skipping live no-op"
)


def test_parse_residual_log_events_extracts_pred_split():
    events = parse_residual_log_events(PRED_SPLIT_LINE + "\n")
    assert len(events) == 1
    e = events[0]
    assert e.source_block == 123
    assert e.via_pred == 45
    assert e.target_entry == 201
    assert e.state_value == 0x5FE86821


def test_parse_residual_log_events_extracts_goto():
    events = parse_residual_log_events(GOTO_LINE + "\n")
    assert len(events) == 1
    e = events[0]
    assert e.source_block == 7
    assert e.target_entry == 8
    assert e.state_value == 0xDEADBEEF


def test_parse_residual_log_events_extracts_cycle_skip():
    events = parse_residual_log_events(CYCLE_LINE + "\n")
    assert len(events) == 1
    assert events[0].source_block == 12
    assert events[0].target_entry == 34
    assert "cycle" in events[0].note.lower()


def test_parse_residual_log_events_extracts_unresolved_predecessors():
    line = (
        "unresolved non-BST dispatcher predecessors remain:"
        " {'pre_d810': [10, 20], 'post_d810': [30]}"
    )
    events = parse_residual_log_events(line + "\n")
    sources = sorted(e.source_block for e in events)
    assert sources == [10, 20, 30]
    notes = [e.note for e in events]
    assert any("pre_d810" in n for n in notes)
    assert any("post_d810" in n for n in notes)


def test_parse_residual_log_events_skips_unrelated_lines():
    text = "\n".join([
        "INFO: starting pipeline",
        "DEBUG: some stat = 17",
        PRED_SPLIT_LINE,
        "INFO: done",
    ])
    events = parse_residual_log_events(text)
    assert len(events) == 1
    assert events[0].source_block == 123


# ---------------------------------------------------------------------------
# _bfs_reachable / detect_feeder_blocks
# ---------------------------------------------------------------------------


def _block(serial: int, *, succs=(), preds=(), type_name="BLT_NWAY") -> BlockInfo:
    return BlockInfo(
        serial=serial,
        type_name=type_name,
        succs=tuple(succs),
        preds=tuple(preds),
        meta={},
        instructions=(),
    )


def test_bfs_reachable_from_block_zero():
    blocks = {
        0: _block(0, succs=(1, 2)),
        1: _block(1, succs=(3,)),
        2: _block(2, succs=()),
        3: _block(3, succs=()),
        # Unreachable island.
        9: _block(9, succs=(10,)),
        10: _block(10, succs=()),
    }
    assert _bfs_reachable(blocks) == {0, 1, 2, 3}


def test_bfs_reachable_returns_empty_when_no_block_zero():
    assert _bfs_reachable({1: _block(1)}) == set()


def test_detect_feeder_blocks_prefers_log_event_sources():
    """If we have any log events at all, those source blocks are the
    truth and the other heuristics are bypassed."""
    log_events = [
        ResidualLogEvent(source_block=42, note="x"),
        ResidualLogEvent(source_block=7, note="y"),
        ResidualLogEvent(source_block=42, note="z"),  # dup → still 42
    ]
    out = detect_feeder_blocks(
        blocks={},
        classification={},
        transition_meta=None,
        log_events=log_events,
        dag_edges=[],
    )
    assert out == [7, 42]


def test_detect_feeder_blocks_uses_dispatcher_residual_preds():
    """When no log, no claimed-non-BST: emit residual non-BST preds of
    the dispatcher entry that are reachable."""
    blocks = {
        0: _block(0, succs=(100,)),
        100: _block(100, preds=(0, 5, 6, 7)),
        5: _block(5),
        6: _block(6),
        7: _block(7),
    }
    classification = {s: {"is_reachable": True} for s in (0, 5, 6, 7, 100)}
    transition_meta = TransitionMeta(
        dispatcher_entry_serial=100,
        state_var_stkoff=0x3C,
        bst_node_blocks=(5,),  # 5 is a real BST node, not a feeder
    )
    out = detect_feeder_blocks(
        blocks=blocks,
        classification=classification,
        transition_meta=transition_meta,
        log_events=[],
        dag_edges=[],
    )
    # 0 is a pred but is the entry; 5 is in bst_node_blocks → excluded.
    # Remaining: 6, 7 (sorted, both reachable).
    assert out == [0, 6, 7]


def test_detect_feeder_blocks_falls_back_to_dag_edges():
    edges = [
        DagEdgeInfo(
            edge_kind="K", source_block=99, target_entry=None,
            source_state_hex=None, target_state_hex=None, ordered_path=(),
        ),
        DagEdgeInfo(
            edge_kind="K", source_block=99, target_entry=None,
            source_state_hex=None, target_state_hex=None, ordered_path=(),
        ),  # dup
        DagEdgeInfo(
            edge_kind="K", source_block=42, target_entry=None,
            source_state_hex=None, target_state_hex=None, ordered_path=(),
        ),
    ]
    out = detect_feeder_blocks(
        blocks={},
        classification={},
        transition_meta=None,
        log_events=[],
        dag_edges=edges,
    )
    # _unique_ints preserves first-seen order over the *sorted* input,
    # which yields [42, 99].
    assert out == [42, 99]


# ---------------------------------------------------------------------------
# Synthetic SQLite end-to-end
# ---------------------------------------------------------------------------


def _make_diag_db(tmp_path: Path) -> Path:
    """Build a minimal diag DB with one snapshot and three blocks."""
    db_path = tmp_path / "diag.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        snap = Snapshot.create(
            id=5,
            label="GLBOPT1_post_d810",
            func_ea_hex="0x00000001800012df0",
            func_ea_i64=0x180012DF0,
            maturity="MMAT_GLBOPT1",
            phase="post_d810",
            block_count=3,
            timestamp=0.0,
        )
        Block.insert_many([
            dict(snapshot=snap.id, serial=0, block_type=1, type_name="BLT_NWAY",
                 nsucc=1, npred=0, succs=json.dumps([100]), preds=json.dumps([]),
                 insn_count=0, meta="{}"),
            dict(snapshot=snap.id, serial=100, block_type=1, type_name="BLT_NWAY",
                 nsucc=1, npred=3, succs=json.dumps([200]), preds=json.dumps([0, 6, 7]),
                 insn_count=0, meta="{}"),
            dict(snapshot=snap.id, serial=6, block_type=1, type_name="BLT_NWAY",
                 nsucc=1, npred=0, succs=json.dumps([100]), preds=json.dumps([]),
                 insn_count=2, meta="{}"),
            dict(snapshot=snap.id, serial=7, block_type=1, type_name="BLT_NWAY",
                 nsucc=1, npred=0, succs=json.dumps([100]), preds=json.dumps([]),
                 insn_count=1, meta="{}"),
            dict(snapshot=snap.id, serial=200, block_type=4, type_name="BLT_STOP",
                 nsucc=0, npred=1, succs=json.dumps([]), preds=json.dumps([100]),
                 insn_count=0, meta="{}"),
        ]).execute()
        Instruction.insert_many([
            dict(snapshot=snap.id, block_serial=6, insn_index=0,
                 ea_hex="0x0000000000001000", ea_i64=0x1000,
                 opcode=4, opcode_name="m_mov",
                 dest_stkoff=0x3C, src_l_value_hex="0x5FE86821",
                 dstr="i = 0x5FE86821"),
            dict(snapshot=snap.id, block_serial=6, insn_index=1,
                 ea_hex="0x0000000000001001", ea_i64=0x1001,
                 opcode=7, opcode_name="m_goto",
                 dstr="goto blk[100]"),
            dict(snapshot=snap.id, block_serial=7, insn_index=0,
                 ea_hex="0x0000000000001002", ea_i64=0x1002,
                 opcode=4, opcode_name="m_mov",
                 dest_stkoff=0x3C, src_l_value_hex="0xDEADBEEF",
                 dstr="i = 0xDEADBEEF"),
        ]).execute()
        RenderedProgramNode.insert(
            snapshot_id=snap.id,
            variant_name="semantic_reference_like",
            node_index=0,
            label_text="STATE_5FE86821",
            node_kind="handler",
            state_label="5FE86821",
            handler_serial=6,
            entry_anchor=6,
            line_start=0,
            line_end=1,
        ).execute()
        RenderedProgramLine.insert(
            snapshot_id=snap.id,
            variant_name="semantic_reference_like",
            line_no=1,
            node_index=0,
            indent_level=0,
            line_kind="label",
            text="STATE_5FE86821:",
        ).execute()
        BlockClassification.insert_many([
            dict(snapshot=snap.id, serial=0, is_bst=0, is_reachable=1,
                 is_gutted=0, in_claimed=0),
            dict(snapshot=snap.id, serial=100, is_bst=1, is_reachable=1,
                 is_gutted=0, in_claimed=0),
            dict(snapshot=snap.id, serial=6, is_bst=0, is_reachable=1,
                 is_gutted=0, in_claimed=1),
            dict(snapshot=snap.id, serial=7, is_bst=0, is_reachable=1,
                 is_gutted=0, in_claimed=1),
            dict(snapshot=snap.id, serial=200, is_bst=0, is_reachable=1,
                 is_gutted=0, in_claimed=0),
        ]).execute()
    db.close()
    return db_path


def test_build_worksheet_uses_dag_fallback_when_no_log_or_dispatcher(
    tmp_path: Path,
):
    """With no log_path and no transition_meta, build_residual_dispatcher_worksheet
    falls through to the in-claimed-not-BST path: blocks 6 and 7 qualify."""
    db = _make_diag_db(tmp_path)
    result = build_residual_dispatcher_worksheet(
        diag_db_path=db,
        snapshot_id=5,
        recon_db_path=None,
        log_path=None,
        func_ea=0x180012DF0,
    )
    assert result.snapshot_id == 5
    assert result.snapshot_label == "GLBOPT1_post_d810"
    assert [row.block for row in result.rows] == [6, 7]


def test_build_worksheet_summarizes_microcode_and_corridor(
    tmp_path: Path,
):
    db = _make_diag_db(tmp_path)
    result = build_residual_dispatcher_worksheet(
        diag_db_path=db,
        snapshot_id=5,
        recon_db_path=None,
        log_path=None,
        func_ea=0x180012DF0,
    )
    block_six = next(r for r in result.rows if r.block == 6)
    # Without transition_meta, state_var_stkoff is None → no "write state="
    # is emitted, but the dstr lines + 1-way successor still summarize.
    assert "blk[100]" in block_six.post_pipeline_microcode_meaning
    # rendered_program_nodes maps entry_anchor=6 → STATE_5FE86821 hit;
    # summarize_semantic_corridor uses the bare hex form `5FE86821 @ blk[6]`.
    assert "5FE86821" in block_six.semantic_state_corridor
    assert "blk[6]" in block_six.semantic_state_corridor


def test_render_markdown_emits_table_for_rows(tmp_path: Path):
    db = _make_diag_db(tmp_path)
    result = build_residual_dispatcher_worksheet(
        diag_db_path=db,
        snapshot_id=5,
        recon_db_path=None,
        log_path=None,
        func_ea=0x180012DF0,
    )
    markdown = render_markdown(result)
    assert "| block |" in markdown.lower() or "| Block |" in markdown
    assert "blk[6]" in markdown or " 6 " in markdown


def test_render_tsv_emits_tab_separated(tmp_path: Path):
    db = _make_diag_db(tmp_path)
    result = build_residual_dispatcher_worksheet(
        diag_db_path=db,
        snapshot_id=5,
        recon_db_path=None,
        log_path=None,
        func_ea=0x180012DF0,
    )
    tsv = render_tsv(result)
    assert "\t" in tsv


def test_render_json_round_trips(tmp_path: Path):
    db = _make_diag_db(tmp_path)
    result = build_residual_dispatcher_worksheet(
        diag_db_path=db,
        snapshot_id=5,
        recon_db_path=None,
        log_path=None,
        func_ea=0x180012DF0,
    )
    parsed = json.loads(render_json(result))
    assert parsed["snapshot_id"] == 5
    assert parsed["snapshot_label"] == "GLBOPT1_post_d810"
    assert any(row["block"] == 6 for row in parsed["rows"])


# ---------------------------------------------------------------------------
# CLI: `python -m d810.diagnostics residual-worksheet`
# ---------------------------------------------------------------------------


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env_path = str(REPO_ROOT / "src")
    # Force HOME to an isolated dir so `Path.home() / .idapro / logs / ...`
    # never resolves to a real diag DB on the developer's machine.
    home_path = (cwd / "fake_home") if cwd is not None else Path("/nonexistent")
    if cwd is not None:
        home_path.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "residual-worksheet", *args],
        capture_output=True,
        text=True,
        env={
            "PYTHONPATH": env_path,
            "PATH": "",
            "HOME": str(home_path),
        },
        cwd=str(cwd if cwd is not None else REPO_ROOT),
    )


def test_cli_lists_snapshots_for_a_synthetic_db(tmp_path: Path):
    db = _make_diag_db(tmp_path)
    result = _run_cli("--diag-db", str(db), "--list-snapshots", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "GLBOPT1_post_d810" in result.stdout
    assert "MMAT_GLBOPT1" in result.stdout


def test_cli_returns_one_when_no_diag_db_can_be_found(tmp_path: Path):
    """No --diag-db given and a clean log-dir + isolated cwd/HOME →
    diagnostics command must fail loudly with a non-zero exit code.

    The runner forces ``HOME`` and ``cwd`` to fresh empty directories so
    ``_search_roots`` cannot fall back to a real diag DB on the
    developer's machine.
    """
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    cwd = tmp_path / "isolated_cwd"
    cwd.mkdir()
    result = _run_cli("--log-dir", str(empty_dir), cwd=cwd)
    assert result.returncode == 1
    assert "Unable to find a diagnostic DB" in result.stderr


def test_cli_renders_markdown_against_synthetic_db(tmp_path: Path):
    db = _make_diag_db(tmp_path)
    result = _run_cli(
        "--diag-db", str(db),
        "--snapshot-id", "5",
        "--func-ea", "0x180012DF0",
        "--format", "markdown",
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    # Markdown table mentions the block we synthesized.
    assert "blk[6]" in result.stdout or " 6 " in result.stdout
