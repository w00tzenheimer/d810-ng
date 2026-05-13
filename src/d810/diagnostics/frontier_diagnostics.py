"""Query DAG-frontier closure diagnostics from the diag DB."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path


def _loads_json_list(text: str | None) -> list[int]:
    if not text:
        return []
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for item in value:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return out


def load_frontier_diagnostics(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
    kind: str | None = "unresolved",
) -> list[dict[str, object]]:
    clauses: list[str] = []
    params: list[object] = []
    if snapshot_id is not None:
        clauses.append("d.snapshot_id = ?")
        params.append(int(snapshot_id))
    if kind:
        kinds = tuple(
            item.strip()
            for item in str(kind).split(",")
            if item.strip()
        )
        if len(kinds) == 1:
            clauses.append("d.kind = ?")
            params.append(kinds[0])
        elif kinds:
            placeholders = ",".join("?" for _ in kinds)
            clauses.append(f"d.kind IN ({placeholders})")
            params.extend(kinds)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT
            d.snapshot_id,
            s.func_ea_hex,
            s.label,
            s.maturity,
            s.phase,
            d.kind,
            d.reason,
            d.source_block,
            d.observed_target,
            d.branch_arm,
            d.from_dag_scc,
            d.to_dag_scc,
            d.candidate_targets_json,
            d.path_json,
            d.cfg_scc_size,
            d.payload_json
        FROM dag_frontier_closure_diagnostics d
        JOIN snapshots s ON s.id = d.snapshot_id
        {where}
        ORDER BY
            d.snapshot_id,
            d.kind,
            d.source_block,
            d.observed_target,
            d.branch_arm,
            d.reason
    """
    rows: list[dict[str, object]] = []
    for row in conn.execute(sql, params):
        rows.append({
            "snapshot_id": int(row[0]),
            "func_ea_hex": row[1],
            "label": row[2],
            "maturity": row[3],
            "phase": row[4],
            "kind": row[5],
            "reason": row[6],
            "source_block": row[7],
            "observed_target": row[8],
            "branch_arm": row[9],
            "from_dag_scc": row[10],
            "to_dag_scc": row[11],
            "candidate_targets": _loads_json_list(row[12]),
            "path": _loads_json_list(row[13]),
            "cfg_scc_size": row[14],
            "payload": _loads_json_object(row[15]),
        })
    return rows


def _loads_json_object(text: str | None) -> dict[str, object]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _block(value: object) -> str:
    if value is None:
        return "blk[?]"
    return f"blk[{int(value)}]"


def _arm(value: object) -> str:
    return "-" if value is None else str(int(value))


def _payload_suffix(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    parts: list[str] = []
    state = payload.get("state")
    if state:
        parts.append(f"state={state}")
    proof = payload.get("proof")
    if proof:
        parts.append(f"proof={proof}")
    return "" if not parts else " " + " ".join(parts)


def format_frontier_diagnostics(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "(no DAG frontier closure diagnostics)\n"
    grouped: dict[tuple[object, object, object, object, object], list[dict[str, object]]] = (
        defaultdict(list)
    )
    for row in rows:
        key = (
            row["snapshot_id"],
            row["func_ea_hex"],
            row["label"],
            row["maturity"],
            row["phase"],
        )
        grouped[key].append(row)

    lines: list[str] = []
    for key in sorted(grouped, key=lambda item: int(item[0])):
        snap_id, func_ea, label, maturity, phase = key
        lines.append(
            f"## snapshot {snap_id} {func_ea} {label} [{maturity}/{phase}]"
        )
        for row in grouped[key]:
            candidates = ",".join(
                str(v) for v in row["candidate_targets"]  # type: ignore[index]
            )
            path = ",".join(str(v) for v in row["path"])  # type: ignore[index]
            lines.append(
                "- "
                f"kind={row['kind']} "
                f"reason={row['reason'] or '-'} "
                f"source={_block(row['source_block'])} "
                f"observed={_block(row['observed_target'])} "
                f"arm={_arm(row['branch_arm'])} "
                f"dag_scc={row['from_dag_scc']}->{row['to_dag_scc']} "
                f"cfg_scc_size={row['cfg_scc_size']} "
                f"candidates=[{candidates}] "
                f"path=[{path}]"
                f"{_payload_suffix(row.get('payload'))}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def register_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "frontier-diagnostics",
        help="Print persisted DAG-frontier closure diagnostics.",
    )
    parser.add_argument(
        "--db",
        required=True,
        help="Path to SQLite diagnostic database.",
    )
    parser.add_argument(
        "--snapshot-id",
        type=int,
        default=None,
        help="Filter to one snapshot id (default: all snapshots).",
    )
    parser.add_argument(
        "--kind",
        default="unresolved,resolved",
        help=(
            "Filter by diagnostic kind, comma-separated "
            "(default: unresolved,resolved)."
        ),
    )
    parser.add_argument(
        "--all-kinds",
        action="store_true",
        help="Show every diagnostic kind instead of only unresolved rows.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"error: db not found: {db_path}", file=sys.stderr)
        return 2
    kind = None if args.all_kinds else args.kind
    conn = sqlite3.connect(str(db_path))
    try:
        rows = load_frontier_diagnostics(
            conn,
            snapshot_id=args.snapshot_id,
            kind=kind,
        )
    finally:
        conn.close()
    if args.json_output:
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        sys.stdout.write(format_frontier_diagnostics(rows))
    return 0


__all__ = [
    "format_frontier_diagnostics",
    "load_frontier_diagnostics",
    "register_parser",
    "run",
]
