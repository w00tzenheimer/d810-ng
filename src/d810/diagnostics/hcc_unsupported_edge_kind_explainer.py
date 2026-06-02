"""Read-only explainer for HCC ``unsupported_edge_kind`` rejections.

For every byte the byte-cascade trace marks with
``candidate_rejection=unsupported_edge_kind``, this module lists the
exact outgoing DAG edges that triggered the rejection, the actual edge
kind HCC observed, the kinds the check accepts, and whether existing
TerminalByteEmitterFact rows on the rejected target make the edge
"byte-cascade safe" -- so we can say either:

    "rejected because edge kind X is not accepted by check Y, despite
     facts Z" (likely safe to allow)

or

    "rejected correctly; byte N needs a different path" (no byte
     facts on the target state).

This is the gate before any HCC behavior change to the
``candidate_build`` edge-kind check. It never imports ``ida_hexrays``.

Source of the rejection (single point in the codebase):

- ``src/d810/recon/flow/reconstruction_candidate_builder.py``
  ``build_reconstruction_candidate``: ``edge.kind not in
  (SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION)``
- ``src/d810/recon/flow/reconstruction_discovery.py``
  ``discover_reconstruction_candidate_seed``: same check.

Both return ``rejection_reason="unsupported_edge_kind"``. So the
"allowed kinds" set is ``{TRANSITION, CONDITIONAL_TRANSITION}`` and
the "first responsible check" is ``build_reconstruction_candidate``.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from d810._vendor.peewee import fn
from d810.core.diag import open_diag_database
from d810.core.diag.models import (
    Block,
    FactObservation,
    StateCfgEdge,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.core.typing import Any, Iterable, Sequence
from d810.diagnostics.hcc_byte_cascade_trace import (
    ByteCascadeRow,
    parse_trace_log,
)


# Mirrors SemanticEdgeKind.{TRANSITION, CONDITIONAL_TRANSITION}.name in
# d810.analyses.control_flow.linearized_state_dag. Keep this in sync if the enum
# names change.
ALLOWED_EDGE_KINDS: frozenset[str] = frozenset({
    "TRANSITION",
    "CONDITIONAL_TRANSITION",
})

# Hardcoded attribution to the rejection check in the codebase. If the
# check ever moves, update both this string and the module docstring.
REJECTION_CHECK_LABEL = (
    "d810.analyses.control_flow.reconstruction_candidate_builder."
    "build_reconstruction_candidate (edge_kind gate)"
)

# Default scope per the user's spec: "bytes 0, 2, 3 first; byte 2 is
# the primary target".
DEFAULT_SCOPE_BYTES: tuple[int, ...] = (0, 2, 3)


@dataclass(frozen=True, slots=True)
class RejectedEdgeRow:
    """One outgoing DAG edge that was rejected as ``unsupported_edge_kind``."""

    edge_id: int | None
    source_block: int | None
    source_state_hex: str
    target_state_hex: str | None
    target_entry_block: int | None
    edge_kind: str
    ordered_path: tuple[int, ...]
    target_block_serials: tuple[int, ...]
    target_byte_facts: tuple[int, ...]  # byte_indices on the target state
    target_has_same_byte_fact: bool
    cfg_source_succs: tuple[int, ...]
    cfg_source_preds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class EdgeKindExplanation:
    """Per-byte verdict + the exact rejected edges responsible."""

    byte: int
    block_ea: str
    block_serial: int | None
    state_hex: str | None
    snapshot_id: int | None
    rejected_edges: tuple[RejectedEdgeRow, ...]
    verdict: str
    narrative: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte": self.byte,
            "block_ea": self.block_ea,
            "block_serial": self.block_serial,
            "state_hex": self.state_hex,
            "snapshot_id": self.snapshot_id,
            "verdict": self.verdict,
            "narrative": self.narrative,
            "rejected_edges": [
                {
                    "edge_id": e.edge_id,
                    "source_block": e.source_block,
                    "source_state_hex": e.source_state_hex,
                    "target_state_hex": e.target_state_hex,
                    "target_entry_block": e.target_entry_block,
                    "edge_kind": e.edge_kind,
                    "ordered_path": list(e.ordered_path),
                    "target_block_serials": list(e.target_block_serials),
                    "target_byte_facts": list(e.target_byte_facts),
                    "target_has_same_byte_fact": e.target_has_same_byte_fact,
                    "cfg_source_succs": list(e.cfg_source_succs),
                    "cfg_source_preds": list(e.cfg_source_preds),
                }
                for e in self.rejected_edges
            ],
        }


# ---------------------------------------------------------------------------
# DB joins
# ---------------------------------------------------------------------------


def _latest_dag_snapshot_id(conn: sqlite3.Connection) -> int | None:
    try:
        value = StateCfgNode.select(fn.MAX(StateCfgNode.snapshot)).scalar()
    except sqlite3.OperationalError:
        return None
    if value is None:
        return None
    return int(value)


def _resolve_state_hex_for_block(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serial: int | None,
) -> str | None:
    if block_serial is None:
        return None
    # raw-SQL: role-priority CASE-WHEN ORDER BY picks the most-specific
    # owning node for a block; a custom rank expression reads more clearly
    # as SQL (§3 complex-SQL policy).
    try:
        row = conn.execute(
            """
            SELECT state_hex FROM state_cfg_node_blocks
            WHERE snapshot_id=? AND block_serial=?
            ORDER BY CASE role
                WHEN 'exclusive' THEN 0
                WHEN 'owned' THEN 1
                WHEN 'shared_suffix' THEN 2
                ELSE 3
            END, block_index
            LIMIT 1
            """,
            (snapshot_id, int(block_serial)),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return str(row[0]) if row else None


def _outgoing_edges(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_hex: str,
) -> list[tuple[int, str | None, str | None, str, int | None, str]]:
    """Return outgoing edges from *state_hex*: (edge_id, src_state, tgt_state, kind, source_block, ordered_path_str)."""
    try:
        rows = (
            StateCfgEdge.select(
                StateCfgEdge.edge_id,
                StateCfgEdge.source_state_hex,
                StateCfgEdge.target_state_hex,
                StateCfgEdge.edge_kind,
                StateCfgEdge.source_block,
                StateCfgEdge.ordered_path,
            )
            .where(
                (StateCfgEdge.snapshot == snapshot_id)
                & (StateCfgEdge.source_state_hex == state_hex)
            )
            .tuples()
        )
    except sqlite3.OperationalError:
        return []
    return [
        (
            int(e_id) if e_id is not None else 0,
            str(src) if src else None,
            str(tgt) if tgt else None,
            str(kind),
            int(sb) if sb is not None else None,
            str(op or ""),
        )
        for e_id, src, tgt, kind, sb, op in rows
    ]


def _entry_block_for_state(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_hex: str,
) -> int | None:
    try:
        row = (
            StateCfgNode.select(StateCfgNode.entry_block)
            .where(
                (StateCfgNode.snapshot == snapshot_id)
                & (StateCfgNode.state_hex == state_hex)
            )
            .tuples()
            .first()
        )
    except sqlite3.OperationalError:
        return None
    return int(row[0]) if row else None


def _blocks_owned_by_state(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_hex: str,
) -> list[int]:
    try:
        rows = (
            StateCfgNodeBlock.select(StateCfgNodeBlock.block_serial)
            .where(
                (StateCfgNodeBlock.snapshot == snapshot_id)
                & (StateCfgNodeBlock.state_hex == state_hex)
            )
            .distinct()
            .tuples()
        )
    except sqlite3.OperationalError:
        return []
    return sorted({int(r[0]) for r in rows if r[0] is not None})


def _byte_facts_on_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serials: Sequence[int],
) -> set[int]:
    """Return distinct ``byte_index`` values for TerminalByteEmitterFact rows
    whose ``source_block`` is in *block_serials*. Reads the byte index out
    of the JSON ``payload`` field.
    """
    if not block_serials:
        return set()
    try:
        rows = (
            FactObservation.select(FactObservation.payload)
            .where(
                (FactObservation.snapshot == snapshot_id)
                & (FactObservation.kind == "TerminalByteEmitterFact")
                & FactObservation.source_block.in_(
                    [int(s) for s in block_serials]
                )
            )
            .tuples()
        )
    except sqlite3.OperationalError:
        return set()
    out: set[int] = set()
    for (payload_json,) in rows:
        if not payload_json:
            continue
        try:
            payload = json.loads(payload_json)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        idx = payload.get("byte_index")
        if idx is None:
            continue
        try:
            out.add(int(idx))
        except (TypeError, ValueError):
            continue
    return out


def _block_succs_preds(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serial: int | None,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Best-effort CFG shape: parse blocks.succs (whitespace ints) +
    derive preds by scanning blocks in this snapshot.
    """
    if block_serial is None:
        return (), ()
    try:
        row = (
            Block.select(Block.succs)
            .where(
                (Block.snapshot == snapshot_id)
                & (Block.serial == int(block_serial))
            )
            .tuples()
            .first()
        )
    except sqlite3.OperationalError:
        return (), ()
    succs: tuple[int, ...] = ()
    if row and row[0]:
        succs = _parse_int_list(str(row[0]))
    try:
        pred_rows = (
            Block.select(Block.serial, Block.succs)
            .where(Block.snapshot == snapshot_id)
            .tuples()
        )
    except sqlite3.OperationalError:
        return succs, ()
    preds: list[int] = []
    for serial, succs_text in pred_rows:
        if not succs_text:
            continue
        if int(block_serial) in _parse_int_list(str(succs_text)):
            preds.append(int(serial))
    return succs, tuple(sorted(set(preds)))


def _parse_int_list(text: str) -> tuple[int, ...]:
    out: list[int] = []
    for token in text.replace(",", " ").split():
        try:
            out.append(int(token, 0))
        except ValueError:
            try:
                out.append(int(token))
            except ValueError:
                continue
    return tuple(out)


def _parse_ordered_path(text: str) -> tuple[int, ...]:
    if not text:
        return ()
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return _parse_int_list(text)
        if isinstance(data, list):
            out: list[int] = []
            for item in data:
                try:
                    out.append(int(item))
                except (TypeError, ValueError):
                    continue
            return tuple(out)
        return ()
    return _parse_int_list(text)


# ---------------------------------------------------------------------------
# Per-byte explanation
# ---------------------------------------------------------------------------


def _verdict_for(rejected_edges: Sequence[RejectedEdgeRow]) -> tuple[str, str]:
    """Decide overall verdict + narrative for one byte's rejected edges."""
    if not rejected_edges:
        return (
            "no_outgoing_rejected_edges",
            "no outgoing state_cfg_edges have a rejected edge_kind for this byte's"
            " state; the trace's `unsupported_edge_kind` rejection points at"
            " a different state or snapshot",
        )
    safe_edges = [e for e in rejected_edges if e.target_has_same_byte_fact]
    if safe_edges:
        kinds = sorted({e.edge_kind for e in safe_edges})
        return (
            "rejection_appears_safe_to_allow",
            f"rejected edge kind(s) {kinds} carry the same byte's"
            " TerminalByteEmitterFact on the target state -- allowing these"
            " edges through `build_reconstruction_candidate` would NOT lose"
            " byte-cascade evidence; gated by"
            " call-barrier/carrier/return-frontier vetoes still firing.",
        )
    kinds = sorted({e.edge_kind for e in rejected_edges})
    return (
        "rejection_appears_correct",
        f"rejected edge kind(s) {kinds} have no TerminalByteEmitterFact on"
        " the target state for this byte; the rejection is acting on a"
        " genuine non-byte-cascade target, byte needs a different path.",
    )


def explain_byte(
    conn: sqlite3.Connection,
    row: ByteCascadeRow,
) -> EdgeKindExplanation:
    snap_id = _latest_dag_snapshot_id(conn)
    if snap_id is None:
        return EdgeKindExplanation(
            byte=row.byte,
            block_ea=row.block_ea or "?",
            block_serial=row.block_serial,
            state_hex=None,
            snapshot_id=None,
            rejected_edges=(),
            verdict="no_dag_snapshot",
            narrative="diag DB has no state_cfg_nodes rows; cannot resolve edges",
        )
    state_hex = _resolve_state_hex_for_block(
        conn, snap_id, row.block_serial,
    )
    if state_hex is None:
        return EdgeKindExplanation(
            byte=row.byte,
            block_ea=row.block_ea or "?",
            block_serial=row.block_serial,
            state_hex=None,
            snapshot_id=snap_id,
            rejected_edges=(),
            verdict="no_state_for_block",
            narrative=(
                "no state_cfg_node_blocks row joins this byte's block to a state;"
                " cannot diagnose the rejection edge"
            ),
        )
    edges = _outgoing_edges(conn, snap_id, state_hex)
    rejected_rows: list[RejectedEdgeRow] = []
    for edge_id, src_state, tgt_state, kind, src_block, ordered_path_str in edges:
        if kind in ALLOWED_EDGE_KINDS:
            continue
        target_blocks: list[int] = []
        target_byte_facts: set[int] = set()
        target_entry: int | None = None
        if tgt_state:
            target_blocks = _blocks_owned_by_state(conn, snap_id, tgt_state)
            target_byte_facts = _byte_facts_on_blocks(
                conn, snap_id, target_blocks,
            )
            target_entry = _entry_block_for_state(conn, snap_id, tgt_state)
        succs, preds = _block_succs_preds(conn, snap_id, src_block)
        rejected_rows.append(RejectedEdgeRow(
            edge_id=edge_id,
            source_block=src_block,
            source_state_hex=src_state or state_hex,
            target_state_hex=tgt_state,
            target_entry_block=target_entry,
            edge_kind=kind,
            ordered_path=_parse_ordered_path(ordered_path_str),
            target_block_serials=tuple(target_blocks),
            target_byte_facts=tuple(sorted(target_byte_facts)),
            target_has_same_byte_fact=row.byte in target_byte_facts,
            cfg_source_succs=succs,
            cfg_source_preds=preds,
        ))
    verdict, narrative = _verdict_for(rejected_rows)
    return EdgeKindExplanation(
        byte=row.byte,
        block_ea=row.block_ea or "?",
        block_serial=row.block_serial,
        state_hex=state_hex,
        snapshot_id=snap_id,
        rejected_edges=tuple(rejected_rows),
        verdict=verdict,
        narrative=narrative,
    )


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------


def select_target_rows(
    rows: Sequence[ByteCascadeRow],
    explicit_bytes: Sequence[int] | None,
) -> list[ByteCascadeRow]:
    """Filter trace rows to the bytes the explainer should report on.

    Default: every row whose ``candidate_rejection == unsupported_edge_kind``.
    """
    if explicit_bytes:
        wanted = {int(b) for b in explicit_bytes}
        return [r for r in rows if r.byte in wanted]
    return [
        r for r in rows
        if (r.candidate_rejection or "").strip() == "unsupported_edge_kind"
    ]


def explain(
    rows: Sequence[ByteCascadeRow],
    db_path: Path,
    *,
    bytes_filter: Sequence[int] | None = None,
) -> list[EdgeKindExplanation]:
    targets = select_target_rows(rows, bytes_filter)
    if not targets:
        return []
    if not db_path.exists():
        return [
            EdgeKindExplanation(
                byte=r.byte,
                block_ea=r.block_ea or "?",
                block_serial=r.block_serial,
                state_hex=None,
                snapshot_id=None,
                rejected_edges=(),
                verdict="no_db",
                narrative=f"diag DB not found at {db_path}",
            )
            for r in targets
        ]
    db = open_diag_database(str(db_path))
    try:
        conn = db.connection()
        return [explain_byte(conn, r) for r in targets]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def format_report(
    explanations: Sequence[EdgeKindExplanation],
    *,
    func_label: str | None = None,
) -> str:
    title = "## HCC unsupported_edge_kind Explainer"
    if func_label:
        title = f"## HCC unsupported_edge_kind Explainer for {func_label}"
    if not explanations:
        return (
            f"{title}\n\n"
            "(no `unsupported_edge_kind` rows found in the trace log; nothing"
            " to explain.)\n"
        )
    allowed = ", ".join(sorted(ALLOWED_EDGE_KINDS))
    lines: list[str] = [
        title,
        "",
        f"Allowed edge kinds at the rejection check: {allowed}",
        f"First responsible check: `{REJECTION_CHECK_LABEL}`",
        "",
    ]
    for ex in explanations:
        header = (
            f"### byte {ex.byte} (`{ex.block_ea}`, blk[{ex.block_serial}],"
            f" state={ex.state_hex or '?'}, snap={ex.snapshot_id})"
        )
        lines.append(header)
        lines.append("")
        lines.append(f"- verdict: `{ex.verdict}`")
        lines.append(f"- narrative: {ex.narrative}")
        if not ex.rejected_edges:
            lines.append("")
            continue
        lines.append("")
        lines.append(
            "| edge_id | source_blk | edge_kind | target_state | target_entry"
            " | target_byte_facts | same_byte_on_target | source_succs |"
            " source_preds |"
        )
        lines.append("|-|-|-|-|-|-|-|-|-|")
        for e in ex.rejected_edges:
            lines.append(
                "| "
                + " | ".join([
                    str(e.edge_id),
                    str(e.source_block) if e.source_block is not None else "?",
                    e.edge_kind,
                    e.target_state_hex or "?",
                    str(e.target_entry_block) if e.target_entry_block is not None else "?",
                    ",".join(str(b) for b in e.target_byte_facts) or "-",
                    "yes" if e.target_has_same_byte_fact else "no",
                    ",".join(str(s) for s in e.cfg_source_succs) or "-",
                    ",".join(str(p) for p in e.cfg_source_preds) or "-",
                ])
                + " |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def format_report_json(
    explanations: Sequence[EdgeKindExplanation],
) -> str:
    return json.dumps([ex.to_dict() for ex in explanations], indent=2)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(
    log_path: Path,
    db_path: Path,
    *,
    bytes_filter: Sequence[int] | None = None,
    func_label: str | None = None,
    as_json: bool = False,
) -> str:
    if not log_path.exists():
        return f"Error: log not found: {log_path}\n"
    rows = parse_trace_log(
        log_path.read_text(encoding="utf-8", errors="replace"),
    )
    explanations = explain(rows, db_path, bytes_filter=bytes_filter)
    if as_json:
        return format_report_json(explanations) + "\n"
    return format_report(explanations, func_label=func_label)
