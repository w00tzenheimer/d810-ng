"""``route`` diagnostic: BST-route provenance for a single dispatcher state.

Loads the dispatcher BST from a diag DB (the compare instructions of a
snapshot), reconstructs the portable :class:`route_predicate.DecisionDag`, and
routes a concrete state through the *same* router the recovery uses
(:meth:`DecisionDag.route`). It then dumps the full provenance for the state:

- the BST decision path (``blkN [op #const] -> T/F`` per node),
- the resolved handler block and its entry EA,
- the writer site(s) that produce the state (literal ``mov #const``; opaque /
  XOR-computed states have no literal writer and are flagged),
- whether the handler reaches a ``BLT_STOP`` (the exit routine) and the chain,
- the target the *recovery* recorded for the state (``dag_edges`` /
  ``state_dispatcher_rows``) and a DISAGREEMENT flag when it differs from the
  authoritative ``route_predicate`` result -- the half-open-vs-inclusive seam
  bug (``0x1A9A9DD9`` routes to blk207 by route_predicate but the recovery may
  resolve the inclusive ``<=`` interval to a different block).

Offline + portable: reads only the diag DB and ``d810.analyses`` (no IDA).
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field

from d810.analyses.control_flow.route_predicate import (
    RouteComparison,
    DecisionDag,
    _evaluate,
)
from d810.diagnostics.output import get_output, write_output

# A dispatcher BST node is ``<op> <operand>, #0x<const>.<size>, @<taken>``.
# Handler-internal conditionals compare small DECIMAL consts (e.g. ``#3.8``)
# and are excluded -- only state-sized hex consts (``#0x...``) are BST pivots.
_CMP_RE = re.compile(r"^(j\w+)\s+.*#0x([0-9A-Fa-f]+)\.\d+,\s*@(\d+)")
_DEFAULT_DB_GLOBS = (
    ".tmp/logs/d810_logs/*.diag.sqlite3",
    os.path.expanduser("~/.idapro/logs/d810_logs/*.diag.sqlite3"),
)


@dataclass(frozen=True, slots=True)
class RouteStep:
    block: int
    op: str
    const: int
    took: bool


@dataclass(slots=True)
class RouteProvenance:
    state: int
    snapshot_id: int
    root: int
    path: list[RouteStep] = field(default_factory=list)
    handler_block: int | None = None
    handler_ea: str | None = None
    literal_writers: list[tuple[int, str]] = field(default_factory=list)
    reaches_stop: bool = False
    stop_chain: list[int] = field(default_factory=list)
    recovery_target: int | None = None
    recovery_source: str | None = None
    disagreement: bool = False


def _parse_succs(value: str) -> list[int]:
    try:
        return [int(x) for x in re.findall(r"-?\d+", value or "")]
    except Exception:
        return []


def build_decision_dag_from_diag(
    conn: sqlite3.Connection, snapshot_id: int, root: int, width: int = 32
) -> DecisionDag:
    """Reconstruct the dispatcher :class:`DecisionDag` from a snapshot's compares.

    ``true_target`` is the ``@N`` jump; ``false_target`` is the block's other
    live successor (fallthrough).
    """
    succs: dict[int, list[int]] = {
        int(s): _parse_succs(v)
        for s, v in conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id=?", (snapshot_id,)
        )
    }
    nodes: dict[int, RouteComparison] = {}
    for blk, dstr in conn.execute(
        "SELECT block_serial, trim(dstr) FROM instructions WHERE snapshot_id=? "
        "AND trim(dstr) LIKE 'j%' AND dstr LIKE '%#0x%@%'",
        (snapshot_id,),
    ):
        m = _CMP_RE.match(dstr)
        if not m:
            continue
        op, const, taken = m.group(1), int(m.group(2), 16), int(m.group(3))
        false_target = taken
        for s in succs.get(int(blk), ()):
            if s != taken:
                false_target = s
                break
        nodes[int(blk)] = RouteComparison(
            serial=int(blk), op=op, const=const,
            true_target=taken, false_target=false_target,
        )
    return DecisionDag(width, nodes, root)


def _block_entry_ea(conn: sqlite3.Connection, snapshot_id: int, block: int) -> str | None:
    row = conn.execute(
        "SELECT ea_hex FROM instructions WHERE snapshot_id=? AND block_serial=? "
        "ORDER BY ea_hex LIMIT 1",
        (snapshot_id, block),
    ).fetchone()
    if row and row[0]:
        return str(row[0])
    row = conn.execute(
        "SELECT start_ea_hex FROM blocks WHERE snapshot_id=? AND serial=?",
        (snapshot_id, block),
    ).fetchone()
    return str(row[0]) if row and row[0] else None


def _reaches_stop(
    conn: sqlite3.Connection, snapshot_id: int, start: int, dag: DecisionDag
) -> tuple[bool, list[int]]:
    """Forward-walk from ``start`` (excluding dispatcher nodes) to a BLT_STOP."""
    succs: dict[int, list[int]] = {
        int(s): _parse_succs(v)
        for s, v in conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id=?", (snapshot_id,)
        )
    }
    types: dict[int, str] = {
        int(s): str(t or "")
        for s, t in conn.execute(
            "SELECT serial, type_name FROM blocks WHERE snapshot_id=?", (snapshot_id,)
        )
    }
    dispatcher = set(dag.nodes) | {dag.root}
    seen: set[int] = set()
    chain: list[int] = []
    cur = start
    # Single-successor forward walk (handler corridor); stop at STOP or a
    # branch/dispatcher re-entry.
    while cur is not None and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        if "STOP" in types.get(cur, ""):
            return True, chain
        nxt = succs.get(cur, [])
        nxt = [s for s in nxt if s not in dispatcher]
        if len(nxt) != 1:
            break
        cur = nxt[0]
    return False, chain


def _recovery_target(
    conn: sqlite3.Connection, snapshot_id: int, state: int
) -> tuple[int | None, str | None]:
    """What the recovery recorded for ``state`` (dag_edges, then dispatcher rows)."""
    for snap in (6, 7, snapshot_id):
        try:
            row = conn.execute(
                "SELECT target_entry FROM dag_edges WHERE snapshot_id=? "
                "AND target_state_i64=? AND target_entry IS NOT NULL LIMIT 1",
                (snap, state),
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row and row[0] is not None:
            return int(row[0]), f"dag_edges(snap{snap})"
    try:
        row = conn.execute(
            "SELECT target_block FROM state_dispatcher_rows WHERE snapshot_id=? "
            "AND state_const_i64=? LIMIT 1",
            (snapshot_id, state),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row and row[0] is not None:
        return int(row[0]), "state_dispatcher_rows"
    return None, None


def route_state(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state: int,
    *,
    slot: int = 52,
    root: int = 3,
    width: int = 32,
) -> RouteProvenance:
    """Route ``state`` through the reconstructed DecisionDag and gather provenance."""
    dag = build_decision_dag_from_diag(conn, snapshot_id, root, width)
    prov = RouteProvenance(state=state, snapshot_id=snapshot_id, root=root)

    cur, seen = root, set()
    while cur in dag.nodes and cur not in seen:
        seen.add(cur)
        node = dag.nodes[cur]
        took = _evaluate(node.op, state, node.const, width)
        prov.path.append(RouteStep(cur, node.op, node.const, took))
        cur = node.true_target if took else node.false_target
    prov.handler_block = cur
    prov.handler_ea = _block_entry_ea(conn, snapshot_id, cur)

    for blk, ea in conn.execute(
        "SELECT block_serial, ea_hex FROM instructions WHERE snapshot_id=? "
        "AND dest_stkoff=? AND src_l_value_i64=?",
        (snapshot_id, slot, state),
    ):
        prov.literal_writers.append((int(blk), str(ea)))

    prov.reaches_stop, prov.stop_chain = _reaches_stop(conn, snapshot_id, cur, dag)
    prov.recovery_target, prov.recovery_source = _recovery_target(
        conn, snapshot_id, state
    )
    prov.disagreement = (
        prov.recovery_target is not None
        and prov.handler_block is not None
        and int(prov.recovery_target) != int(prov.handler_block)
    )
    return prov


def format_provenance(prov: RouteProvenance) -> str:
    out: list[str] = []
    out.append(f"state 0x{prov.state:08X}  (snapshot {prov.snapshot_id}, root blk{prov.root})")
    out.append("-" * 72)
    out.append("BST route path:")
    if prov.path:
        for st in prov.path:
            out.append(
                f"  blk{st.block} [{st.op} #0x{st.const:X}] -> {'T' if st.took else 'F'}"
            )
    else:
        out.append("  (root is a leaf -- no comparisons)")
    out.append(
        f"route_predicate handler: blk{prov.handler_block}"
        + (f" @ {prov.handler_ea}" if prov.handler_ea else "")
    )
    if prov.literal_writers:
        w = ", ".join(f"blk{b}@{ea}" for b, ea in prov.literal_writers)
        out.append(f"literal writer(s) (mov #const -> state var): {w}")
    else:
        out.append("literal writer(s): none (opaque / computed state, e.g. XOR fold)")
    if prov.reaches_stop:
        chain = " -> ".join(f"blk{b}" for b in prov.stop_chain)
        out.append(f"terminal: YES -> exit routine via {chain}")
    else:
        chain = " -> ".join(f"blk{b}" for b in prov.stop_chain)
        out.append(f"terminal: no (corridor: {chain})")
    if prov.recovery_target is not None:
        flag = "  <<< DISAGREEMENT" if prov.disagreement else "  (agrees)"
        out.append(
            f"recovery recorded target: blk{prov.recovery_target} "
            f"[{prov.recovery_source}]{flag}"
        )
    else:
        out.append("recovery recorded target: (none found in dag_edges / dispatcher rows)")
    return "\n".join(out)


def _resolve_db(db_arg: str | None) -> str | None:
    if db_arg and os.path.exists(db_arg):
        return db_arg
    candidates: list[str] = []
    for pat in _DEFAULT_DB_GLOBS:
        candidates.extend(glob.glob(pat))
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def _latest_snapshot_with_compares(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT snapshot_id, COUNT(*) n FROM instructions "
        "WHERE trim(dstr) LIKE 'j%' AND dstr LIKE '%#0x%@%' "
        "GROUP BY snapshot_id ORDER BY n DESC, snapshot_id ASC LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else 5


def run(args: argparse.Namespace) -> int:
    db = _resolve_db(getattr(args, "db", None))
    if db is None:
        print("route: no diag DB found (pass --db)", file=sys.stderr)
        return 2
    conn = sqlite3.connect(db)
    try:
        snap = getattr(args, "snapshot", -1)
        if snap is None or int(snap) < 0:
            snap = _latest_snapshot_with_compares(conn)
        prov = route_state(
            conn,
            int(snap),
            int(args.state, 0),
            slot=int(args.slot, 0) if isinstance(args.slot, str) else int(args.slot),
            root=int(args.root),
            width=int(args.width),
        )
    finally:
        conn.close()
    out = get_output(args)
    write_output(out, f"DB={os.path.basename(db)}")
    write_output(out, format_provenance(prov))
    return 0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("state", help="State value (hex, e.g. 0x1A9A9DD9)")
    parser.add_argument("--root", type=int, default=3, help="Dispatcher root block (default 3)")
    parser.add_argument("--slot", default="52", help="State-var diag stkoff (default 52)")
    parser.add_argument("--width", type=int, default=32, help="State-var bit width (default 32)")


__all__ = [
    "RouteStep",
    "RouteProvenance",
    "build_decision_dag_from_diag",
    "route_state",
    "format_provenance",
    "run",
    "add_arguments",
]
