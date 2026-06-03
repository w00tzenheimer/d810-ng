"""Query DAG-frontier closure diagnostics from the diag DB."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

from d810.core.diag import read_diag_db
from d810.core.diag.models import Snapshot, StateCfgFrontierClosureDiagnostic
from d810.diagnostics.output import add_output_argument, get_output, write_output



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
    d = StateCfgFrontierClosureDiagnostic
    query = (
        d.select(
            d.snapshot.alias("snapshot_id"),
            Snapshot.func_ea_hex,
            Snapshot.label,
            Snapshot.maturity,
            Snapshot.phase,
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
            d.payload_json,
        )
        .join(Snapshot, on=(Snapshot.id == d.snapshot))
    )
    if snapshot_id is not None:
        query = query.where(d.snapshot == int(snapshot_id))
    if kind:
        kinds = tuple(
            item.strip()
            for item in str(kind).split(",")
            if item.strip()
        )
        if len(kinds) == 1:
            query = query.where(d.kind == kinds[0])
        elif kinds:
            query = query.where(d.kind.in_(list(kinds)))
    query = query.order_by(
        d.snapshot,
        d.kind,
        d.source_block,
        d.observed_target,
        d.branch_arm,
        d.reason,
    )
    rows: list[dict[str, object]] = []
    for row in query.dicts():
        rows.append({
            "snapshot_id": int(row["snapshot_id"]),
            "func_ea_hex": row["func_ea_hex"],
            "label": row["label"],
            "maturity": row["maturity"],
            "phase": row["phase"],
            "kind": row["kind"],
            "reason": row["reason"],
            "source_block": row["source_block"],
            "observed_target": row["observed_target"],
            "branch_arm": row["branch_arm"],
            "from_dag_scc": row["from_dag_scc"],
            "to_dag_scc": row["to_dag_scc"],
            "candidate_targets": _loads_json_list(row["candidate_targets_json"]),
            "path": _loads_json_list(row["path_json"]),
            "cfg_scc_size": row["cfg_scc_size"],
            "payload": _loads_json_object(row["payload_json"]),
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
    add_output_argument(parser)


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"error: db not found: {db_path}", file=sys.stderr)
        return 2
    kind = None if args.all_kinds else args.kind
    with read_diag_db(str(db_path)) as db:
        rows = load_frontier_diagnostics(
            db.connection(),
            snapshot_id=args.snapshot_id,
            kind=kind,
        )
    if args.json_output:
        write_output(get_output(args), json.dumps(rows, indent=2, sort_keys=True))
    else:
        write_output(get_output(args), format_frontier_diagnostics(rows), end="")
    return 0


__all__ = [
    "format_frontier_diagnostics",
    "load_frontier_diagnostics",
    "register_parser",
    "run",
]
