"""Read-only HCC opaque-call anchor snapshot context.

This module owns the post-hoc diag SQLite query used to explain where
opaque-call anchor blocks disappear across HCC/pipeline snapshots. Runtime
strategy code should emit observations or log fields; persisted diag DB lookup
belongs here.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from d810.core.diag import open_diag_database
from d810.core.diag.models import Block, Snapshot


_KILL_POINT_SNAPSHOT_ORDER: tuple[str, ...] = (
    "maturity_MMAT_GLBOPT1_pre_d810",
    "handler_chain_composer_post_apply",
    "post_pipeline",
    "maturity_MMAT_GLBOPT1_post_d810",
)

_DEFAULT_CONTEXT: dict[str, object] = {
    "preds_pre_pipeline": "UNKNOWN",
    "preds_post_hcc": "UNKNOWN",
    "preds_post_pipeline": "UNKNOWN",
    "succs_pre_pipeline": "UNKNOWN",
    "succs_post_hcc": "UNKNOWN",
    "succs_post_pipeline": "UNKNOWN",
    "reachable_from_entry_post_pipeline": "UNKNOWN",
    "survives_glbopt1_post_d810": "UNKNOWN",
    "earliest_kill_point": "unknown",
}


def default_anchor_snapshot_context() -> dict[str, object]:
    """Return HCC anchor snapshot fields for missing/unavailable diag DBs."""
    return dict(_DEFAULT_CONTEXT)


def _format_serial_list(items) -> str:
    """Render an iterable of ints as ``[blk[a], blk[b], ...]`` (sorted)."""
    try:
        sorted_items = sorted({int(s) for s in items})
    except Exception:
        return "[]"
    if not sorted_items:
        return "[]"
    return "[" + ", ".join(f"blk[{s}]" for s in sorted_items) + "]"


def _open_diag_db_readonly() -> sqlite3.Connection | None:
    """Return a diag DB connection usable for cross-snapshot HCC queries."""
    try:
        from d810.core.settings import get_settings
    except Exception:
        return None
    try:
        if not get_settings().diag_snapshots:
            return None
    except Exception:
        return None

    try:
        log_dir = Path(os.path.expanduser("~/.idapro/logs/d810_logs"))
        if not log_dir.exists():
            return None
        candidates = sorted(
            log_dir.glob("*.diag.sqlite3"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in candidates:
            try:
                # Bind Models read-only; returns the bound connection so the
                # cross-snapshot ORM reads below target this diag DB.
                conn = open_diag_database(str(path)).connection()
            except Exception:
                continue
            try:
                has_post_pipeline = (
                    Snapshot.select(Snapshot.id)
                    .where(Snapshot.label == "post_pipeline")
                    .exists()
                )
                has_glbopt1_post = (
                    Snapshot.select(Snapshot.id)
                    .where(
                        Snapshot.label == "maturity_MMAT_GLBOPT1_post_d810"
                    )
                    .exists()
                )
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            if has_post_pipeline and has_glbopt1_post:
                return conn
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return None
    return None


def _query_block_state_in_snapshot(
    conn: sqlite3.Connection,
    snapshot_label: str,
    block_serial: int,
) -> dict[str, object] | None:
    """Return predecessor/successor/reachability state for one snapshot."""
    try:
        row = (
            Snapshot.select(Snapshot.id)
            .where(Snapshot.label == snapshot_label)
            .order_by(Snapshot.id.desc())
            .limit(1)
            .tuples()
            .first()
        )
    except Exception:
        return None
    if row is None:
        return None
    snapshot_id = int(row[0])
    try:
        blk_row = (
            Block.select(Block.preds, Block.succs)
            .where(
                (Block.snapshot == snapshot_id)
                & (Block.serial == block_serial)
            )
            .tuples()
            .first()
        )
    except Exception:
        return None
    if blk_row is None:
        return {"preds": None, "succs": None, "reachable_from_0": "NO"}
    try:
        preds = json.loads(blk_row[0]) if blk_row[0] else []
        succs = json.loads(blk_row[1]) if blk_row[1] else []
    except Exception:
        preds, succs = [], []

    reachable = "UNKNOWN"
    try:
        all_rows = (
            Block.select(Block.serial, Block.succs)
            .where(Block.snapshot == snapshot_id)
            .tuples()
        )
        succ_map: dict[int, list[int]] = {}
        for serial, succs_blob in all_rows:
            try:
                succ_map[int(serial)] = (
                    json.loads(succs_blob) if succs_blob else []
                )
            except Exception:
                succ_map[int(serial)] = []
        visited: set[int] = set()
        stack = [0]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in succ_map.get(cur, ()):
                stack.append(int(nxt))
        reachable = "YES" if int(block_serial) in visited else "NO"
    except Exception:
        reachable = "UNKNOWN"
    return {
        "preds": [int(p) for p in preds],
        "succs": [int(s) for s in succs],
        "reachable_from_0": reachable,
    }


def collect_anchor_snapshot_context_from_connection(
    conn: sqlite3.Connection,
    *,
    anchor_serial: int,
) -> dict[str, object]:
    """Collect HCC anchor snapshot context from an already-open diag DB."""
    snapshot_results: dict[str, dict[str, object] | None] = {}
    for label in _KILL_POINT_SNAPSHOT_ORDER:
        try:
            snapshot_results[label] = _query_block_state_in_snapshot(
                conn, label, anchor_serial,
            )
        except Exception:
            snapshot_results[label] = None

    def _fmt(label: str, key: str) -> str:
        snap = snapshot_results.get(label)
        if snap is None or snap.get(key) is None:
            return "UNKNOWN"
        return _format_serial_list(snap.get(key) or ())

    pre_pipeline_lbl = "maturity_MMAT_GLBOPT1_pre_d810"
    post_hcc_lbl = "handler_chain_composer_post_apply"
    post_pipeline_lbl = "post_pipeline"
    post_glbopt1_lbl = "maturity_MMAT_GLBOPT1_post_d810"

    reach_post_pipeline = "UNKNOWN"
    snap_post = snapshot_results.get(post_pipeline_lbl)
    if snap_post is not None:
        v = snap_post.get("reachable_from_0")
        if isinstance(v, str):
            reach_post_pipeline = v

    survives_glbopt1 = "UNKNOWN"
    snap_glbopt1 = snapshot_results.get(post_glbopt1_lbl)
    if snap_glbopt1 is not None:
        survives_glbopt1 = (
            "NO" if snap_glbopt1.get("preds") is None else "YES"
        )

    earliest_kill_point = "NEVER"
    first_snap = snapshot_results.get(_KILL_POINT_SNAPSHOT_ORDER[0])
    if first_snap is None or first_snap.get("preds") is None:
        earliest_kill_point = "unknown"
    else:
        for label in _KILL_POINT_SNAPSHOT_ORDER:
            snap = snapshot_results.get(label)
            if snap is None:
                continue
            if snap.get("preds") is None:
                earliest_kill_point = label
                break

    return {
        "preds_pre_pipeline": _fmt(pre_pipeline_lbl, "preds"),
        "preds_post_hcc": _fmt(post_hcc_lbl, "preds"),
        "preds_post_pipeline": _fmt(post_pipeline_lbl, "preds"),
        "succs_pre_pipeline": _fmt(pre_pipeline_lbl, "succs"),
        "succs_post_hcc": _fmt(post_hcc_lbl, "succs"),
        "succs_post_pipeline": _fmt(post_pipeline_lbl, "succs"),
        "reachable_from_entry_post_pipeline": reach_post_pipeline,
        "survives_glbopt1_post_d810": survives_glbopt1,
        "earliest_kill_point": earliest_kill_point,
    }


def collect_anchor_snapshot_context(
    *,
    anchor_serial: int,
) -> dict[str, object]:
    """Collect HCC anchor context from the latest complete diag DB."""
    conn = _open_diag_db_readonly()
    if conn is None:
        return default_anchor_snapshot_context()
    try:
        return collect_anchor_snapshot_context_from_connection(
            conn,
            anchor_serial=anchor_serial,
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass
