"""Build a residual dispatcher worksheet from persisted diagnostics.

The worksheet is intentionally read-only. It correlates:

- post-pipeline microcode blocks from the diagnostic SQLite DB
- semantic rendered-program spans from the same DB
- optional DAG/modification snapshots from the diagnostic DB
- optional transition/planner data from the recon DB
- optional residual-handoff log lines from a text dump or log file

Exposed as the ``residual-worksheet`` subcommand of
``python -m d810.diagnostics``. Distinct from ``d810cli.py residuals``
(which is a text-only grep over the AFTER pseudocode).
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from d810.core.typing import Iterable, Sequence

DEFAULT_PHASE = "post_d810"
DEFAULT_MATURITY = "MMAT_GLBOPT1"
DEFAULT_VARIANT = "semantic_reference_like"
HANDLER_TRANSITIONS_COLLECTOR = "handler_transitions"
HODUR_PLANNER_CONSUMER = "hodur_planner"


@dataclass(frozen=True)
class BlockInfo:
    serial: int
    type_name: str
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    meta: dict[str, object]
    instructions: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class RenderedNodeInfo:
    node_index: int
    label_text: str
    node_kind: str
    state_label: str | None
    handler_serial: int | None
    entry_anchor: int | None
    preview: str


@dataclass(frozen=True)
class DagEdgeInfo:
    edge_kind: str
    source_block: int | None
    target_entry: int | None
    source_state_hex: str | None
    target_state_hex: str | None
    ordered_path: tuple[int, ...]


@dataclass(frozen=True)
class ModificationInfo:
    mod_type: str
    source_block: int | None
    target_block: int | None
    status: str
    reason: str


@dataclass(frozen=True)
class PlannerOwnershipInfo:
    strategy_name: str
    phase: str
    reason_code: str
    reason: str
    notes: str
    ownership_blocks: tuple[int, ...]


@dataclass(frozen=True)
class TransitionMeta:
    dispatcher_entry_serial: int | None
    state_var_stkoff: int | None
    bst_node_blocks: tuple[int, ...]


@dataclass(frozen=True)
class ResidualLogEvent:
    source_block: int
    note: str
    target_entry: int | None = None
    state_value: int | None = None
    via_pred: int | None = None
    raw: str = ""


@dataclass(frozen=True)
class WorksheetRow:
    block: int
    post_pipeline_microcode_meaning: str
    semantic_state_corridor: str
    dag_provenance_note: str


@dataclass(frozen=True)
class WorksheetResult:
    diag_db_path: Path
    snapshot_id: int
    snapshot_label: str
    dag_snapshot_id: int | None
    dag_snapshot_label: str | None
    recon_db_path: Path | None
    log_path: Path | None
    rows: tuple[WorksheetRow, ...]


def parse_int(value: str) -> int:
    """Parse an integer from decimal or 0x-prefixed text."""
    return int(value, 0)


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _blk(serial: int | None) -> str:
    return f"blk[{serial}]" if serial is not None else "None"


def _truncate(text: str, limit: int = 140) -> str:
    text = _collapse(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalize_maturity_name(maturity: str | None) -> str | None:
    if maturity is None:
        return None
    cleaned = maturity.strip().upper()
    if not cleaned:
        return None
    if not cleaned.startswith("MMAT_"):
        cleaned = f"MMAT_{cleaned}"
    return cleaned


def _search_roots(
    *,
    log_dir: Path | None = None,
    extra_paths: Sequence[Path] = (),
) -> list[Path]:
    roots: list[Path] = []
    candidates = [
        log_dir,
        Path.cwd() / ".tmp" / "logs" / "d810_logs",
        Path.cwd() / ".tmp",
        Path.cwd(),
        Path.home() / ".idapro" / "logs" / "d810_logs",
    ]
    candidates.extend(extra_paths)
    for candidate in candidates:
        if candidate is None:
            continue
        resolved = candidate.resolve()
        if resolved.exists() and resolved not in roots:
            roots.append(resolved)
    return roots


def _sorted_by_mtime(paths: Iterable[Path]) -> list[Path]:
    return sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)


def find_latest_diag_db(
    *,
    func_ea: int | None = None,
    search_roots: Sequence[Path],
) -> Path | None:
    """Find the latest diagnostic DB, optionally filtered by function EA."""
    candidates: list[Path] = []
    for root in search_roots:
        pattern = f"{func_ea:016x}_*.diag.sqlite3" if func_ea is not None else "*.diag.sqlite3"
        candidates.extend(root.glob(pattern))
    for path in _sorted_by_mtime(candidates):
        try:
            with sqlite3.connect(str(path)) as conn:
                row = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()
        except sqlite3.DatabaseError:
            continue
        if row is not None and int(row[0] or 0) > 0:
            return path
    return None


def find_latest_recon_db(*, search_roots: Sequence[Path]) -> Path | None:
    """Find the latest recon DB in known log roots."""
    candidates: list[Path] = []
    for root in search_roots:
        candidate = root / "d810_recon.db"
        if candidate.exists():
            candidates.append(candidate)
    ordered = _sorted_by_mtime(candidates)
    return ordered[0] if ordered else None


def find_latest_log_file(
    *,
    search_roots: Sequence[Path],
    func_token: str | None = None,
) -> Path | None:
    """Find the latest text log that looks relevant to residual handoffs."""
    patterns = ("*.txt", "*.log", "*.out")
    token = func_token.lower() if func_token else None
    candidates: list[Path] = []
    for root in search_roots:
        for pattern in patterns:
            candidates.extend(root.glob(pattern))
    for path in _sorted_by_mtime(candidates):
        name = path.name.lower()
        if token is not None and token not in name:
            try:
                sample = path.read_text(encoding="utf-8", errors="ignore")[:65536].lower()
            except OSError:
                continue
            if token not in sample:
                continue
        try:
            sample = path.read_text(encoding="utf-8", errors="ignore")[:65536]
        except OSError:
            continue
        if (
            "LFG DAG:" in sample
            or "residual handoff" in sample
            or "unresolved non-BST dispatcher predecessors" in sample
        ):
            return path
    return None


def _open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def list_snapshots(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, label, maturity, phase, block_count FROM snapshots ORDER BY id"
    ).fetchall()


def resolve_snapshot_id(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None,
    maturity: str | None,
    phase: str | None,
    variant_name: str | None,
) -> int:
    """Resolve the primary worksheet snapshot."""
    if snapshot_id is not None:
        return snapshot_id

    mat = _normalize_maturity_name(maturity)
    clauses: list[str] = []
    params: list[object] = []
    if mat is not None:
        clauses.append("s.maturity = ?")
        params.append(mat)
    if phase:
        clauses.append("s.phase = ?")
        params.append(phase)
    where = " AND ".join(clauses) if clauses else "1=1"

    if variant_name:
        query = (
            "SELECT s.id FROM snapshots s "
            "JOIN rendered_programs rp ON rp.snapshot_id = s.id AND rp.variant_name = ? "
            f"WHERE {where} "
            "ORDER BY s.id DESC LIMIT 1"
        )
        row = conn.execute(query, [variant_name, *params]).fetchone()
        if row is not None:
            return int(row["id"])

    row = conn.execute(
        f"SELECT s.id FROM snapshots s WHERE {where} ORDER BY s.id DESC LIMIT 1",
        params,
    ).fetchone()
    if row is not None:
        return int(row["id"])

    row = conn.execute("SELECT MAX(id) AS id FROM snapshots").fetchone()
    if row is None or row["id"] is None:
        raise ValueError("diag DB does not contain any snapshots")
    return int(row["id"])


def _snapshot_metadata(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM snapshots WHERE id = ?",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"snapshot {snapshot_id} not found")
    return row


def resolve_aux_snapshot_id(
    conn: sqlite3.Connection,
    *,
    func_ea_i64: int,
    table_name: str,
    preferred_phase: str | None = None,
    preferred_label_substring: str | None = None,
) -> int | None:
    """Resolve the latest snapshot that contains rows in ``table_name``."""
    query = (
        "SELECT s.id, s.label, s.phase FROM snapshots s "
        f"WHERE s.func_ea_i64 = ? AND EXISTS (SELECT 1 FROM {table_name} t WHERE t.snapshot_id = s.id) "
        "ORDER BY "
    )
    order_parts: list[str] = []
    params: list[object] = [func_ea_i64]
    if preferred_phase is not None:
        order_parts.append("(s.phase = ?) DESC")
        params.append(preferred_phase)
    if preferred_label_substring is not None:
        order_parts.append("(instr(lower(s.label), lower(?)) > 0) DESC")
        params.append(preferred_label_substring)
    order_parts.append("s.id DESC")
    row = conn.execute(query + ", ".join(order_parts) + " LIMIT 1", params).fetchone()
    return int(row["id"]) if row is not None else None


def load_blocks(conn: sqlite3.Connection, snapshot_id: int) -> dict[int, BlockInfo]:
    """Load blocks plus instructions for one snapshot."""
    blocks: dict[int, BlockInfo] = {}
    block_rows = conn.execute(
        "SELECT serial, type_name, succs, preds, meta FROM blocks "
        "WHERE snapshot_id = ? ORDER BY serial",
        (snapshot_id,),
    ).fetchall()
    insn_rows = conn.execute(
        "SELECT block_serial, insn_index, opcode_name, dest_stkoff, src_l_value_hex, dstr "
        "FROM instructions WHERE snapshot_id = ? ORDER BY block_serial, insn_index",
        (snapshot_id,),
    ).fetchall()
    instructions_by_block: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in insn_rows:
        instructions_by_block[int(row["block_serial"])].append({
            "insn_index": int(row["insn_index"]),
            "opcode_name": row["opcode_name"],
            "dest_stkoff": row["dest_stkoff"],
            "src_l_value_hex": row["src_l_value_hex"],
            "dstr": row["dstr"] or "",
        })
    for row in block_rows:
        succs = tuple(json.loads(row["succs"] or "[]"))
        preds = tuple(json.loads(row["preds"] or "[]"))
        meta = json.loads(row["meta"] or "{}")
        serial = int(row["serial"])
        blocks[serial] = BlockInfo(
            serial=serial,
            type_name=str(row["type_name"]),
            succs=tuple(int(v) for v in succs),
            preds=tuple(int(v) for v in preds),
            meta=meta if isinstance(meta, dict) else {},
            instructions=tuple(instructions_by_block.get(serial, ())),
        )
    return blocks


def load_block_classification(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
) -> dict[int, dict[str, bool]]:
    """Load reachability/BST flags for one snapshot."""
    if snapshot_id is None:
        return {}
    rows = conn.execute(
        "SELECT serial, is_bst, is_reachable, is_gutted, in_claimed "
        "FROM block_classification WHERE snapshot_id = ? ORDER BY serial",
        (snapshot_id,),
    ).fetchall()
    result: dict[int, dict[str, bool]] = {}
    for row in rows:
        result[int(row["serial"])] = {
            "is_bst": bool(row["is_bst"]),
            "is_reachable": bool(row["is_reachable"]),
            "is_gutted": bool(row["is_gutted"]),
            "in_claimed": bool(row["in_claimed"]),
        }
    return result


def _node_preview(lines: list[str]) -> str:
    preview_lines = [
        _collapse(line)
        for line in lines
        if line.strip()
        and not line.strip().startswith("//")
        and not line.strip().endswith(":")
    ]
    if not preview_lines:
        preview_lines = [_collapse(line) for line in lines if line.strip() and not line.strip().endswith(":")]
    return _truncate(" ".join(preview_lines[:2]), limit=100)


def load_rendered_nodes(
    conn: sqlite3.Connection,
    snapshot_id: int,
    variant_name: str,
) -> list[RenderedNodeInfo]:
    """Load rendered program nodes plus short previews."""
    line_rows = conn.execute(
        "SELECT node_index, text FROM rendered_program_lines "
        "WHERE snapshot_id = ? AND variant_name = ? ORDER BY line_no",
        (snapshot_id, variant_name),
    ).fetchall()
    lines_by_node: dict[int, list[str]] = defaultdict(list)
    for row in line_rows:
        if row["node_index"] is None:
            continue
        lines_by_node[int(row["node_index"])].append(str(row["text"]))

    node_rows = conn.execute(
        "SELECT node_index, label_text, node_kind, state_label, handler_serial, entry_anchor "
        "FROM rendered_program_nodes WHERE snapshot_id = ? AND variant_name = ? "
        "ORDER BY node_index",
        (snapshot_id, variant_name),
    ).fetchall()
    nodes: list[RenderedNodeInfo] = []
    for row in node_rows:
        node_index = int(row["node_index"])
        nodes.append(
            RenderedNodeInfo(
                node_index=node_index,
                label_text=str(row["label_text"]),
                node_kind=str(row["node_kind"]),
                state_label=row["state_label"],
                handler_serial=(
                    int(row["handler_serial"]) if row["handler_serial"] is not None else None
                ),
                entry_anchor=(
                    int(row["entry_anchor"]) if row["entry_anchor"] is not None else None
                ),
                preview=_node_preview(lines_by_node.get(node_index, [])),
            )
        )
    return nodes


def load_dag_edges(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
) -> list[DagEdgeInfo]:
    """Load DAG edges for one auxiliary snapshot."""
    if snapshot_id is None:
        return []
    rows = conn.execute(
        "SELECT edge_kind, source_block, target_entry, source_state_hex, target_state_hex, ordered_path "
        "FROM dag_edges WHERE snapshot_id = ? ORDER BY edge_id",
        (snapshot_id,),
    ).fetchall()
    edges: list[DagEdgeInfo] = []
    for row in rows:
        ordered_path = tuple(int(v) for v in json.loads(row["ordered_path"] or "[]"))
        edges.append(
            DagEdgeInfo(
                edge_kind=str(row["edge_kind"]),
                source_block=(
                    int(row["source_block"]) if row["source_block"] is not None else None
                ),
                target_entry=(
                    int(row["target_entry"]) if row["target_entry"] is not None else None
                ),
                source_state_hex=row["source_state_hex"],
                target_state_hex=row["target_state_hex"],
                ordered_path=ordered_path,
            )
        )
    return edges


def load_modifications(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
) -> list[ModificationInfo]:
    """Load emitted modifications for one auxiliary snapshot."""
    if snapshot_id is None:
        return []
    rows = conn.execute(
        "SELECT mod_type, source_block, target_block, status, reason "
        "FROM modifications WHERE snapshot_id = ? ORDER BY mod_index",
        (snapshot_id,),
    ).fetchall()
    return [
        ModificationInfo(
            mod_type=str(row["mod_type"]),
            source_block=(
                int(row["source_block"]) if row["source_block"] is not None else None
            ),
            target_block=(
                int(row["target_block"]) if row["target_block"] is not None else None
            ),
            status=str(row["status"]),
            reason=str(row["reason"] or ""),
        )
        for row in rows
    ]


def load_transition_meta(recon_db_path: Path | None, *, func_ea: int) -> TransitionMeta | None:
    """Load dispatcher metadata from the latest handler transition report."""
    if recon_db_path is None or not recon_db_path.exists():
        return None
    conn = _open_db(recon_db_path)
    try:
        row = conn.execute(
            "SELECT metrics_json FROM recon_results "
            "WHERE func_ea = ? AND collector_name = ? "
            "ORDER BY maturity DESC, timestamp DESC LIMIT 1",
            (func_ea, HANDLER_TRANSITIONS_COLLECTOR),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    try:
        metrics = json.loads(row["metrics_json"] or "{}")
    except json.JSONDecodeError:
        return None
    report = metrics.get("transition_report")
    if not isinstance(report, dict):
        return None
    bst_nodes = report.get("bst_node_blocks") or ()
    return TransitionMeta(
        dispatcher_entry_serial=(
            int(report["dispatcher_entry_serial"])
            if report.get("dispatcher_entry_serial") is not None
            else None
        ),
        state_var_stkoff=(
            int(report["state_var_stkoff"])
            if report.get("state_var_stkoff") is not None
            else None
        ),
        bst_node_blocks=tuple(int(v) for v in bst_nodes),
    )


def load_planner_ownership(
    recon_db_path: Path | None,
    *,
    func_ea: int,
) -> list[PlannerOwnershipInfo]:
    """Load the latest Hodur planner provenance rows."""
    if recon_db_path is None or not recon_db_path.exists():
        return []
    conn = _open_db(recon_db_path)
    try:
        row = conn.execute(
            "SELECT provenance_json FROM consumer_outcomes "
            "WHERE func_ea = ? AND consumer_name = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (func_ea, HODUR_PLANNER_CONSUMER),
        ).fetchone()
    finally:
        conn.close()
    if row is None or not row["provenance_json"]:
        return []
    try:
        payload = json.loads(row["provenance_json"])
    except json.JSONDecodeError:
        return []
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return []
    result: list[PlannerOwnershipInfo] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        ownership = item.get("ownership_blocks") or ()
        result.append(
            PlannerOwnershipInfo(
                strategy_name=str(item.get("strategy_name", "")),
                phase=str(item.get("phase", "")),
                reason_code=str(item.get("reason_code", "")),
                reason=str(item.get("reason", "")),
                notes=str(item.get("notes", "")),
                ownership_blocks=tuple(int(v) for v in ownership),
            )
        )
    return result


_PRED_SPLIT_RE = re.compile(
    r"LFG DAG: residual dispatcher pred-split "
    r"blk\[(?P<source>\d+)\] via blk\[(?P<via>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"\(state 0x(?P<state>[0-9A-Fa-f]+)\)"
)
_GOTO_RE = re.compile(
    r"LFG DAG: residual dispatcher handoff "
    r"blk\[(?P<source>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"\(state 0x(?P<state>[0-9A-Fa-f]+)\)"
)
_PREFIX_RE = re.compile(
    r"LFG DAG: residual prefix handoff "
    r"blk\[(?P<via>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"\(bypassing blk\[(?P<source>\d+)\] via (?P<kind>[^)]+)\)"
)
_SHARED_SUFFIX_RE = re.compile(
    r"LFG DAG: residual handoff "
    r"blk\[(?P<source>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"suppressed because blk\[(?P<tail>\d+)\] is a shared-suffix tail"
)
_PRIOR_BRANCH_CUT_RE = re.compile(
    r"LFG DAG: residual handoff "
    r"blk\[(?P<source>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"suppressed because an earlier conditional corridor already owns state "
    r"0x(?P<state>[0-9A-Fa-f]+)"
)
_CYCLE_RE = re.compile(
    r"LFG DAG: residual handoff "
    r"blk\[(?P<source>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"still forms a non-dispatcher cycle, skipping"
)
_NOOP_RE = re.compile(
    r"LFG DAG: residual handoff "
    r"blk\[(?P<source>\d+)\] already targets blk\[(?P<target>\d+)\], skipping live no-op"
)
_NORMALIZED_RE = re.compile(
    r"LFG DAG: normalized projected residual handoff "
    r"blk\[(?P<source>\d+)\] -> blk\[(?P<target>\d+)\] "
    r"\(was blk\[(?P<old>\d+)\]\)"
)
_UNRESOLVED_PREDS_RE = re.compile(
    r"unresolved non-BST dispatcher predecessors remain:\s*(?P<payload>\{.*\})"
)


def parse_residual_log_events(text: str) -> list[ResidualLogEvent]:
    """Parse residual-dispatcher outcome lines from a log or dump."""
    events: list[ResidualLogEvent] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        unresolved_match = _UNRESOLVED_PREDS_RE.search(line)
        if unresolved_match:
            try:
                payload = ast.literal_eval(unresolved_match.group("payload"))
            except (ValueError, SyntaxError):
                payload = None
            if isinstance(payload, dict):
                for stage_name, blocks in payload.items():
                    if not isinstance(blocks, (list, tuple)):
                        continue
                    for block in blocks:
                        try:
                            source = int(block)
                        except (TypeError, ValueError):
                            continue
                        events.append(
                            ResidualLogEvent(
                                source_block=source,
                                note=f"unresolved dispatcher predecessor ({stage_name})",
                                raw=line,
                            )
                        )
                continue
        if "LFG DAG:" not in line:
            continue
        match = _PRED_SPLIT_RE.search(line)
        if match:
            source = int(match.group("source"))
            via_pred = int(match.group("via"))
            target = int(match.group("target"))
            state_value = int(match.group("state"), 16)
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    state_value=state_value,
                    via_pred=via_pred,
                    note=f"pred-split via {_blk(via_pred)} -> {_blk(target)} state=0x{state_value:08X}",
                    raw=line,
                )
            )
            continue
        match = _GOTO_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            state_value = int(match.group("state"), 16)
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    state_value=state_value,
                    note=f"handoff -> {_blk(target)} state=0x{state_value:08X}",
                    raw=line,
                )
            )
            continue
        match = _PREFIX_RE.search(line)
        if match:
            source = int(match.group("source"))
            via_pred = int(match.group("via"))
            target = int(match.group("target"))
            edge_kind = _collapse(match.group("kind"))
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    via_pred=via_pred,
                    note=f"prefix via {_blk(via_pred)} -> {_blk(target)} ({edge_kind.lower()})",
                    raw=line,
                )
            )
            continue
        match = _SHARED_SUFFIX_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    note=f"suppressed shared-suffix tail -> {_blk(target)}",
                    raw=line,
                )
            )
            continue
        match = _PRIOR_BRANCH_CUT_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            state_value = int(match.group("state"), 16)
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    state_value=state_value,
                    note=f"suppressed prior-branch-cut state=0x{state_value:08X}",
                    raw=line,
                )
            )
            continue
        match = _CYCLE_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    note=f"suppressed cycle-risk -> {_blk(target)}",
                    raw=line,
                )
            )
            continue
        match = _NOOP_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    note=f"live no-op already -> {_blk(target)}",
                    raw=line,
                )
            )
            continue
        match = _NORMALIZED_RE.search(line)
        if match:
            source = int(match.group("source"))
            target = int(match.group("target"))
            old_target = int(match.group("old"))
            events.append(
                ResidualLogEvent(
                    source_block=source,
                    target_entry=target,
                    note=f"normalized target {_blk(old_target)} -> {_blk(target)}",
                    raw=line,
                )
            )
    return events


def _bfs_reachable(blocks: dict[int, BlockInfo]) -> set[int]:
    if 0 not in blocks:
        return set()
    visited: set[int] = set()
    worklist: list[int] = [0]
    while worklist:
        current = worklist.pop()
        if current in visited or current not in blocks:
            continue
        visited.add(current)
        worklist.extend(int(succ) for succ in blocks[current].succs if succ not in visited)
    return visited


def detect_feeder_blocks(
    *,
    blocks: dict[int, BlockInfo],
    classification: dict[int, dict[str, bool]],
    transition_meta: TransitionMeta | None,
    log_events: Sequence[ResidualLogEvent],
    dag_edges: Sequence[DagEdgeInfo],
) -> list[int]:
    """Choose the block set that should become worksheet rows."""
    from_log = sorted({event.source_block for event in log_events})
    if from_log:
        return from_log

    reachable = {
        serial for serial, flags in classification.items() if flags.get("is_reachable", False)
    } or _bfs_reachable(blocks)

    if transition_meta is not None and transition_meta.dispatcher_entry_serial is not None:
        dispatcher = blocks.get(transition_meta.dispatcher_entry_serial)
        if dispatcher is not None:
            bst_blocks = set(int(v) for v in transition_meta.bst_node_blocks)
            residual_preds = [
                int(pred)
                for pred in dispatcher.preds
                if pred != dispatcher.serial and pred not in bst_blocks and pred in reachable
            ]
            if residual_preds:
                return sorted(residual_preds)

    claimed = sorted(
        serial
        for serial, flags in classification.items()
        if flags.get("in_claimed", False) and not flags.get("is_bst", False)
    )
    if claimed:
        return claimed

    from_dag = sorted(
        int(edge.source_block)
        for edge in dag_edges
        if edge.source_block is not None
    )
    return _unique_ints(from_dag)


def _unique_ints(values: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    result: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def summarize_microcode(
    block: BlockInfo | None,
    *,
    state_var_stkoff: int | None,
) -> str:
    """Build a compact one-line summary for a post-pipeline block."""
    if block is None:
        return "(block missing in selected snapshot)"

    parts: list[str] = []
    if state_var_stkoff is not None:
        for insn in block.instructions:
            if insn.get("dest_stkoff") == state_var_stkoff and insn.get("src_l_value_hex"):
                parts.append(f"write state={insn['src_l_value_hex']}")
                break

    statement_texts = [
        _collapse(str(insn.get("dstr", "")))
        for insn in block.instructions
        if str(insn.get("dstr", "")).strip()
    ]
    for text in statement_texts[:2]:
        if text.startswith("goto ") or text.startswith("if ") or text.startswith("return "):
            continue
        parts.append(text)

    if block.type_name == "BLT_STOP":
        parts.append("stop")
    elif len(block.succs) == 1:
        parts.append(f"1-way to {_blk(block.succs[0])}")
    elif len(block.succs) == 2:
        parts.append(f"2-way to {_blk(block.succs[0])}/{_blk(block.succs[1])}")
    elif block.succs:
        joined = ",".join(_blk(succ) for succ in block.succs[:3])
        suffix = ",..." if len(block.succs) > 3 else ""
        parts.append(f"succs={joined}{suffix}")

    if not parts and statement_texts:
        parts.extend(statement_texts[:2])
    if not parts:
        parts.append(block.type_name.lower())
    return _truncate("; ".join(_unique_preserve_order(parts)))


def _rendered_lookup(nodes: Sequence[RenderedNodeInfo]) -> tuple[dict[int, RenderedNodeInfo], dict[int, RenderedNodeInfo]]:
    by_entry: dict[int, RenderedNodeInfo] = {}
    by_handler: dict[int, RenderedNodeInfo] = {}
    for node in nodes:
        if node.entry_anchor is not None:
            by_entry.setdefault(node.entry_anchor, node)
        if node.handler_serial is not None:
            by_handler.setdefault(node.handler_serial, node)
    return by_entry, by_handler


def _describe_node(node: RenderedNodeInfo) -> str:
    label = node.state_label or node.label_text
    anchor = f"@ {_blk(node.entry_anchor)}" if node.entry_anchor is not None else ""
    preview = f": {node.preview}" if node.preview else ""
    return _truncate(f"{label} {anchor}{preview}".strip(), limit=120)


def summarize_semantic_corridor(
    block_serial: int,
    *,
    log_events: Sequence[ResidualLogEvent],
    dag_edges: Sequence[DagEdgeInfo],
    rendered_nodes: Sequence[RenderedNodeInfo],
) -> str:
    """Map a block to rendered semantic state/corridor text."""
    by_entry, by_handler = _rendered_lookup(rendered_nodes)
    parts: list[str] = []

    for event in log_events:
        if event.source_block != block_serial:
            continue
        descriptor: str | None = None
        if event.target_entry is not None and event.target_entry in by_entry:
            descriptor = _describe_node(by_entry[event.target_entry])
        elif block_serial in by_handler:
            descriptor = _describe_node(by_handler[block_serial])
        if descriptor is None and event.target_entry is not None:
            descriptor = _blk(event.target_entry)
        if descriptor is None:
            continue
        if event.state_value is not None:
            parts.append(f"0x{event.state_value:08X} -> {descriptor}")
        else:
            parts.append(descriptor)

    for edge in dag_edges:
        if edge.source_block != block_serial:
            continue
        descriptor: str | None = None
        if edge.target_entry is not None and edge.target_entry in by_entry:
            descriptor = _describe_node(by_entry[edge.target_entry])
        elif block_serial in by_handler:
            descriptor = _describe_node(by_handler[block_serial])
        elif edge.target_entry is not None:
            descriptor = _blk(edge.target_entry)
        if descriptor is None:
            continue
        prefix = edge.source_state_hex or edge.edge_kind.lower()
        if len(edge.ordered_path) > 1:
            path = "->".join(_blk(serial) for serial in edge.ordered_path[:4])
            if len(edge.ordered_path) > 4:
                path += "->..."
            parts.append(f"{prefix} via {path} -> {descriptor}")
        else:
            parts.append(f"{prefix} -> {descriptor}")

    if not parts:
        node = by_entry.get(block_serial) or by_handler.get(block_serial)
        if node is not None:
            parts.append(_describe_node(node))
    collapsed = _unique_preserve_order(parts)
    if not collapsed:
        return "(no rendered corridor match)"
    return _truncate(" | ".join(collapsed[:2]), limit=140)


def _planner_phase_rank(phase: str) -> int:
    order = {
        "applied": 0,
        "selected": 1,
        "gate_failed": 2,
        "policy_filtered": 3,
        "conflict_dropped": 4,
        "preflight_rejected": 5,
        "inapplicable": 6,
        "bypassed": 7,
        "crashed": 8,
    }
    return order.get(phase, 99)


def summarize_dag_note(
    block_serial: int,
    *,
    log_events: Sequence[ResidualLogEvent],
    dag_edges: Sequence[DagEdgeInfo],
    modifications: Sequence[ModificationInfo],
    planner_rows: Sequence[PlannerOwnershipInfo],
) -> str:
    """Choose the best provenance note for a row."""
    notes: list[str] = []

    notes.extend(event.note for event in log_events if event.source_block == block_serial)

    matching_planner_rows = [
        row for row in planner_rows if block_serial in row.ownership_blocks
    ]
    matching_planner_rows.sort(key=lambda row: (_planner_phase_rank(row.phase), row.strategy_name))
    for row in matching_planner_rows[:1]:
        detail = _collapse(row.notes or row.reason)
        summary = f"planner {row.phase} {row.strategy_name}"
        if detail:
            summary = f"{summary}: {detail}"
        notes.append(summary)

    for modification in modifications:
        if modification.source_block != block_serial:
            continue
        detail = f"{modification.status} {modification.mod_type}"
        if modification.target_block is not None:
            detail = f"{detail} -> {_blk(modification.target_block)}"
        if modification.reason:
            detail = f"{detail}: {_collapse(modification.reason)}"
        notes.append(detail)

    for edge in dag_edges:
        if edge.source_block != block_serial:
            continue
        detail = f"DAG {edge.edge_kind.lower()}"
        if edge.target_entry is not None:
            detail = f"{detail} -> {_blk(edge.target_entry)}"
        if len(edge.ordered_path) > 1:
            detail = f"{detail} path=" + "->".join(_blk(v) for v in edge.ordered_path[:4])
            if len(edge.ordered_path) > 4:
                detail += "->..."
        notes.append(detail)

    collapsed = _unique_preserve_order(notes)
    if not collapsed:
        return "(no provenance note)"
    return _truncate(" | ".join(collapsed[:2]), limit=140)


def build_residual_dispatcher_worksheet(
    *,
    diag_db_path: Path,
    snapshot_id: int | None = None,
    dag_snapshot_id: int | None = None,
    reachability_snapshot_id: int | None = None,
    recon_db_path: Path | None = None,
    log_path: Path | None = None,
    func_ea: int | None = None,
    maturity: str | None = DEFAULT_MATURITY,
    phase: str | None = DEFAULT_PHASE,
    variant_name: str = DEFAULT_VARIANT,
) -> WorksheetResult:
    """Build worksheet rows from the available persisted sources."""
    diag_conn = _open_db(diag_db_path)
    try:
        resolved_snapshot_id = resolve_snapshot_id(
            diag_conn,
            snapshot_id=snapshot_id,
            maturity=maturity,
            phase=phase,
            variant_name=variant_name,
        )
        snapshot_meta = _snapshot_metadata(diag_conn, resolved_snapshot_id)
        resolved_func_ea = int(func_ea if func_ea is not None else snapshot_meta["func_ea_i64"])

        resolved_dag_snapshot_id = (
            dag_snapshot_id
            if dag_snapshot_id is not None
            else resolve_aux_snapshot_id(
                diag_conn,
                func_ea_i64=resolved_func_ea,
                table_name="dag_edges",
                preferred_phase="post_apply",
                preferred_label_substring="state_write_reconstruction",
            )
        )
        resolved_reachability_snapshot_id = (
            reachability_snapshot_id
            if reachability_snapshot_id is not None
            else resolve_aux_snapshot_id(
                diag_conn,
                func_ea_i64=resolved_func_ea,
                table_name="block_classification",
                preferred_phase="post_gut_wire",
            )
        )

        blocks = load_blocks(diag_conn, resolved_snapshot_id)
        classification = load_block_classification(diag_conn, resolved_reachability_snapshot_id)
        rendered_nodes = load_rendered_nodes(diag_conn, resolved_snapshot_id, variant_name)
        dag_edges = load_dag_edges(diag_conn, resolved_dag_snapshot_id)
        modifications = load_modifications(diag_conn, resolved_dag_snapshot_id)

        dag_snapshot_label: str | None = None
        if resolved_dag_snapshot_id is not None:
            dag_snapshot_label = str(_snapshot_metadata(diag_conn, resolved_dag_snapshot_id)["label"])
    finally:
        diag_conn.close()

    transition_meta = load_transition_meta(recon_db_path, func_ea=resolved_func_ea)
    planner_rows = load_planner_ownership(recon_db_path, func_ea=resolved_func_ea)

    log_events: list[ResidualLogEvent] = []
    if log_path is not None and log_path.exists():
        log_events = parse_residual_log_events(
            log_path.read_text(encoding="utf-8", errors="ignore")
        )

    feeder_blocks = detect_feeder_blocks(
        blocks=blocks,
        classification=classification,
        transition_meta=transition_meta,
        log_events=log_events,
        dag_edges=dag_edges,
    )

    rows: list[WorksheetRow] = []
    for block_serial in feeder_blocks:
        block = blocks.get(block_serial)
        rows.append(
            WorksheetRow(
                block=block_serial,
                post_pipeline_microcode_meaning=summarize_microcode(
                    block,
                    state_var_stkoff=(
                        transition_meta.state_var_stkoff if transition_meta is not None else None
                    ),
                ),
                semantic_state_corridor=summarize_semantic_corridor(
                    block_serial,
                    log_events=log_events,
                    dag_edges=dag_edges,
                    rendered_nodes=rendered_nodes,
                ),
                dag_provenance_note=summarize_dag_note(
                    block_serial,
                    log_events=log_events,
                    dag_edges=dag_edges,
                    modifications=modifications,
                    planner_rows=planner_rows,
                ),
            )
        )

    return WorksheetResult(
        diag_db_path=diag_db_path,
        snapshot_id=resolved_snapshot_id,
        snapshot_label=str(snapshot_meta["label"]),
        dag_snapshot_id=resolved_dag_snapshot_id,
        dag_snapshot_label=dag_snapshot_label,
        recon_db_path=recon_db_path,
        log_path=log_path,
        rows=tuple(rows),
    )


def render_markdown(result: WorksheetResult) -> str:
    """Render the worksheet as a Markdown table."""
    lines = [
        f"Snapshot: [{result.snapshot_id}] {result.snapshot_label}",
    ]
    if result.dag_snapshot_id is not None and result.dag_snapshot_label is not None:
        lines.append(f"DAG snapshot: [{result.dag_snapshot_id}] {result.dag_snapshot_label}")
    lines.extend(
        [
            "",
            "| block | post-pipeline microcode meaning | semantic state/corridor from linearization/render | DAG/provenance note |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in result.rows:
        values = [
            _blk(row.block),
            row.post_pipeline_microcode_meaning,
            row.semantic_state_corridor,
            row.dag_provenance_note,
        ]
        escaped = [value.replace("|", "\\|") for value in values]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines)


def render_tsv(result: WorksheetResult) -> str:
    """Render the worksheet as TSV."""
    header = "\t".join(
        [
            "block",
            "post-pipeline microcode meaning",
            "semantic state/corridor from linearization/render",
            "DAG/provenance note",
        ]
    )
    rows = [
        "\t".join(
            [
                _blk(row.block),
                row.post_pipeline_microcode_meaning,
                row.semantic_state_corridor,
                row.dag_provenance_note,
            ]
        )
        for row in result.rows
    ]
    return "\n".join([header, *rows])


def render_json(result: WorksheetResult) -> str:
    """Render the worksheet as JSON."""
    payload = {
        "diag_db": str(result.diag_db_path),
        "snapshot_id": result.snapshot_id,
        "snapshot_label": result.snapshot_label,
        "dag_snapshot_id": result.dag_snapshot_id,
        "dag_snapshot_label": result.dag_snapshot_label,
        "recon_db": str(result.recon_db_path) if result.recon_db_path is not None else None,
        "log_path": str(result.log_path) if result.log_path is not None else None,
        "rows": [
            {
                "block": row.block,
                "post_pipeline_microcode_meaning": row.post_pipeline_microcode_meaning,
                "semantic_state_corridor": row.semantic_state_corridor,
                "dag_provenance_note": row.dag_provenance_note,
            }
            for row in result.rows
        ],
    }
    return json.dumps(payload, indent=2)


def register_parser(sub) -> None:
    """Register the ``residual-worksheet`` subparser.

    No ``common`` parent: this command uses ``--diag-db`` / ``--recon-db``
    rather than the diag DB heuristic ``--db`` and owns its own
    maturity/phase defaults.
    """
    p = sub.add_parser(
        "residual-worksheet",
        help=(
            "Build a residual dispatcher worksheet from persisted diag,"
            " recon, and log artifacts. Correlates post-pipeline microcode,"
            " semantic rendered-program spans, DAG/modification snapshots,"
            " transition/planner data, and residual-handoff log lines."
        ),
    )
    p.add_argument("--diag-db", type=Path, default=None, help="Diagnostic SQLite DB")
    p.add_argument("--recon-db", type=Path, default=None, help="Recon SQLite DB")
    p.add_argument("--log", type=Path, default=None, help="Optional text log/dump to parse")
    p.add_argument(
        "--log-dir", type=Path, default=None,
        help="Search root for auto-detected DBs/logs",
    )
    p.add_argument(
        "--func-ea", type=parse_int, default=None,
        help="Function EA (decimal or hex)",
    )
    p.add_argument(
        "--func-token", default=None,
        help="Function token for log auto-detection, e.g. sub_7FFD",
    )
    p.add_argument(
        "--snapshot-id", type=int, default=None,
        help="Primary worksheet snapshot ID",
    )
    p.add_argument(
        "--dag-snapshot-id", type=int, default=None,
        help="Auxiliary DAG snapshot ID",
    )
    p.add_argument(
        "--reachability-snapshot-id",
        type=int,
        default=None,
        help="Auxiliary block-classification snapshot ID",
    )
    p.add_argument(
        "--maturity", default=DEFAULT_MATURITY,
        help="Preferred maturity, default GLBOPT1",
    )
    p.add_argument(
        "--phase", default=DEFAULT_PHASE,
        help="Preferred phase, default post_d810",
    )
    p.add_argument(
        "--variant", default=DEFAULT_VARIANT,
        help="Rendered-program variant name",
    )
    p.add_argument(
        "--format",
        choices=("markdown", "tsv", "json"),
        default="markdown",
        help="Output format",
    )
    p.add_argument(
        "--output", type=Path, default=None,
        help="Write output to this path instead of stdout",
    )
    p.add_argument(
        "--list-snapshots", action="store_true",
        help="List snapshots and exit",
    )


def run(args: argparse.Namespace) -> int:
    """Execute ``residual-worksheet`` from parsed args; return exit code."""
    extra_paths = []
    for candidate in (args.diag_db, args.recon_db, args.log):
        if candidate is not None:
            extra_paths.append(candidate.parent)
    search_roots = _search_roots(log_dir=args.log_dir, extra_paths=extra_paths)

    diag_db_path = args.diag_db or find_latest_diag_db(
        func_ea=args.func_ea,
        search_roots=search_roots,
    )
    if diag_db_path is None:
        print("Unable to find a diagnostic DB. Pass --diag-db.", file=sys.stderr)
        return 1

    if args.list_snapshots:
        conn = _open_db(diag_db_path)
        try:
            for row in list_snapshots(conn):
                print(
                    f"[{int(row['id']):>3}] {row['label']} "
                    f"({row['maturity']} / {row['phase']} / {row['block_count']} blocks)"
                )
        finally:
            conn.close()
        return 0

    recon_db_path = args.recon_db or find_latest_recon_db(search_roots=search_roots)
    log_path = args.log or find_latest_log_file(
        search_roots=search_roots,
        func_token=args.func_token,
    )

    result = build_residual_dispatcher_worksheet(
        diag_db_path=diag_db_path,
        snapshot_id=args.snapshot_id,
        dag_snapshot_id=args.dag_snapshot_id,
        reachability_snapshot_id=args.reachability_snapshot_id,
        recon_db_path=recon_db_path,
        log_path=log_path,
        func_ea=args.func_ea,
        maturity=args.maturity,
        phase=args.phase,
        variant_name=args.variant,
    )

    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "tsv":
        rendered = render_tsv(result)
    else:
        rendered = render_markdown(result)

    if args.output is not None:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0
