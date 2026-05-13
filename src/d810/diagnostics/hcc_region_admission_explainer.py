"""Read-only HCC Region Admission Explainer.

For every byte that the HCC byte-cascade trace classifies as
``region_detection_gap`` (DAG-visible but never picked up as part of any
HCC raw region or ``InsertBlock`` body), this module attributes the gap
to a *single* named admission-failure bucket plus the first HCC stage
responsible.

Buckets (priority order, first match wins):

1. ``candidate_rejected_pre_raw_region`` -- the trace recorded a
   non-empty ``candidate_rejection`` for the byte's chain edge; HCC
   rejected the candidate before any raw region was built.
2. ``call_barrier_collision`` -- ``first_dropped_stage`` is the call
   barrier collision filter.
3. ``payload_or_intermediate_filter`` -- ``first_dropped_stage`` is one
   of the payload/intermediate/corridor/carrier/region filters.
4. ``region_table_merge_loss`` -- HCC accepted the byte through a
   *fallback* path (``postprocess`` / ``fallback_execution`` /
   ``frontier_overrides`` / ``late_shared_fallback``) but never admitted
   it to the raw region table; the raw region merge dropped/missed it.
5. ``not_in_chain`` -- DB join shows the byte's ``dag_node`` has no
   incoming or outgoing ``dag_edges`` rows; HCC saw the state but no
   chain to admit.
6. ``chain_too_short`` -- chain (BFS along ``dag_edges``) is below
   ``MIN_ADMISSIBLE_CHAIN_LEN`` nodes; too short to bootstrap a region.
7. ``no_accepted_pred_or_succ`` -- chain exists but no neighbor's
   block ever made it into the raw region table either; the entire
   neighborhood was passed over.

The explainer never imports ``ida_hexrays``, runs entirely from the
diag SQLite + ``d810.log`` produced by an earlier dump, and is fully
unit-testable.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from d810.core.typing import Any, Iterable, Sequence
from d810.diagnostics.hcc_byte_cascade_trace import (
    ByteCascadeRow,
    parse_trace_log,
)


MIN_ADMISSIBLE_CHAIN_LEN = 3

# `first_dropped_stage` strings that map to bucket 2/3.
_CALL_BARRIER_STAGE = "call_barrier_collision"
_PAYLOAD_OR_INTERMEDIATE_STAGES = frozenset({
    "payload_intermediate_filter",
    "corridor_filter",
    "carrier_filter",
    "region_filter",
})
# `accepted_stage` strings that mean "HCC fixed it up via a fallback".
_FALLBACK_ACCEPTED_STAGES = frozenset({
    "postprocess",
    "fallback_execution",
    "frontier_overrides",
    "late_shared_fallback",
})

# Bucket -> first responsible HCC stage label, used in the report.
_BUCKET_TO_STAGE: dict[str, str] = {
    "candidate_rejected_pre_raw_region": "candidate_build",
    "call_barrier_collision": "call_barrier_collision",
    "payload_or_intermediate_filter": "filter_stage",
    "region_table_merge_loss": "raw_region_table",
    "not_in_chain": "seed_dag",
    "chain_too_short": "raw_region_table",
    "no_accepted_pred_or_succ": "raw_region_table",
}

_BUCKET_TO_NARRATIVE: dict[str, str] = {
    "candidate_rejected_pre_raw_region": (
        "HCC rejected the candidate before building any raw region;"
        " see candidate_rejection field"
    ),
    "call_barrier_collision": (
        "byte's chain collided with a call barrier and was filtered out"
    ),
    "payload_or_intermediate_filter": (
        "byte's block was filtered by a payload / intermediate / corridor /"
        " carrier filter"
    ),
    "region_table_merge_loss": (
        "HCC preserved the byte through a fallback path but the raw region"
        " table never accepted it"
    ),
    "not_in_chain": (
        "byte's DAG node has no incoming or outgoing edges; HCC saw the"
        " state but no chain to admit"
    ),
    "chain_too_short": (
        "DAG chain reachable from the byte's node has fewer than"
        f" {MIN_ADMISSIBLE_CHAIN_LEN} nodes; too short to bootstrap a region"
    ),
    "no_accepted_pred_or_succ": (
        "DAG chain exists but no chain neighbor's block was admitted to the"
        " raw region table either"
    ),
}


@dataclass(frozen=True, slots=True)
class AdmissionEvidence:
    """DB-derived evidence joined for a single byte."""

    byte: int
    block_serial: int | None
    block_ea: str
    state_hex: str | None
    snapshot_id: int | None
    dag_pred_count: int
    dag_succ_count: int
    chain_size: int
    neighbors_admitted: int
    neighbor_state_hexes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdmissionExplanation:
    """Per-byte admission verdict + supporting fields."""

    byte: int
    block_ea: str
    bucket: str
    first_responsible_stage: str
    narrative: str
    in_dag: bool
    in_corrected_dag: bool
    in_region_table: bool
    raw_candidate: bool
    candidate_rejection: str
    accepted_stage: str
    first_dropped_stage: str
    evidence: AdmissionEvidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte": self.byte,
            "block_ea": self.block_ea,
            "bucket": self.bucket,
            "first_responsible_stage": self.first_responsible_stage,
            "narrative": self.narrative,
            "in_dag": self.in_dag,
            "in_corrected_dag": self.in_corrected_dag,
            "in_region_table": self.in_region_table,
            "raw_candidate": self.raw_candidate,
            "candidate_rejection": self.candidate_rejection,
            "accepted_stage": self.accepted_stage,
            "first_dropped_stage": self.first_dropped_stage,
            "evidence": {
                "block_serial": self.evidence.block_serial,
                "state_hex": self.evidence.state_hex,
                "snapshot_id": self.evidence.snapshot_id,
                "dag_pred_count": self.evidence.dag_pred_count,
                "dag_succ_count": self.evidence.dag_succ_count,
                "chain_size": self.evidence.chain_size,
                "neighbors_admitted": self.evidence.neighbors_admitted,
                "neighbor_state_hexes": list(
                    self.evidence.neighbor_state_hexes
                ),
            },
        }


# ---------------------------------------------------------------------------
# DB joins (pure -- conn already open)
# ---------------------------------------------------------------------------


def _latest_dag_snapshot_id(conn: sqlite3.Connection) -> int | None:
    """Return the snapshot id of the latest non-empty dag_nodes row."""
    try:
        row = conn.execute(
            "SELECT MAX(snapshot_id) FROM dag_nodes"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None or row[0] is None:
        return None
    return int(row[0])


def _resolve_state_hex_for_block(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serial: int | None,
) -> str | None:
    """Best-effort: find a dag_node state_hex that owns *block_serial*."""
    if block_serial is None:
        return None
    try:
        row = conn.execute(
            """
            SELECT state_hex FROM dag_node_blocks
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


def _dag_neighbor_counts(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_hex: str,
) -> tuple[int, int, list[str]]:
    """Return (#preds, #succs, distinct neighbor state_hexes)."""
    try:
        pred_rows = conn.execute(
            """
            SELECT DISTINCT source_state_hex FROM dag_edges
            WHERE snapshot_id=? AND target_state_hex=?
              AND source_state_hex IS NOT NULL
            """,
            (snapshot_id, state_hex),
        ).fetchall()
        succ_rows = conn.execute(
            """
            SELECT DISTINCT target_state_hex FROM dag_edges
            WHERE snapshot_id=? AND source_state_hex=?
              AND target_state_hex IS NOT NULL
            """,
            (snapshot_id, state_hex),
        ).fetchall()
    except sqlite3.OperationalError:
        return 0, 0, []
    preds = {str(r[0]) for r in pred_rows if r[0]}
    succs = {str(r[0]) for r in succ_rows if r[0]}
    neighbors = sorted(preds | succs)
    return len(preds), len(succs), neighbors


def _bfs_chain_size(
    conn: sqlite3.Connection,
    snapshot_id: int,
    seed_state_hex: str,
    max_nodes: int = 64,
) -> int:
    """Count distinct dag nodes reachable from *seed_state_hex* (undirected)."""
    visited: set[str] = {seed_state_hex}
    frontier: list[str] = [seed_state_hex]
    while frontier and len(visited) < max_nodes:
        next_frontier: list[str] = []
        try:
            placeholders = ",".join("?" for _ in frontier)
            rows = conn.execute(
                f"""
                SELECT source_state_hex, target_state_hex FROM dag_edges
                WHERE snapshot_id=?
                  AND (source_state_hex IN ({placeholders})
                       OR target_state_hex IN ({placeholders}))
                """,
                (snapshot_id, *frontier, *frontier),
            ).fetchall()
        except sqlite3.OperationalError:
            break
        for src, tgt in rows:
            for hex_value in (src, tgt):
                if not hex_value:
                    continue
                key = str(hex_value)
                if key in visited:
                    continue
                visited.add(key)
                next_frontier.append(key)
                if len(visited) >= max_nodes:
                    return len(visited)
        frontier = next_frontier
    return len(visited)


def _count_neighbors_admitted_to_region(
    conn: sqlite3.Connection,
    snapshot_id: int,
    neighbor_state_hexes: Sequence[str],
) -> int:
    """Best-effort: count neighbors whose blocks have any region_shape feature.

    The diag DB does not snapshot HCC's raw_region_table directly, so we use
    ``region_shape_features`` as the closest available proxy: neighbors whose
    state's owned blocks appear in any region feature value are treated as
    "admitted".

    This is a lower bound -- a 0 here is a strong signal that the whole
    chain neighborhood was passed over by HCC's region detection. A
    non-zero value still does not prove admission of the queried byte,
    only of its neighbors.
    """
    if not neighbor_state_hexes:
        return 0
    try:
        placeholders = ",".join("?" for _ in neighbor_state_hexes)
        rows = conn.execute(
            f"""
            SELECT DISTINCT block_serial FROM dag_node_blocks
            WHERE snapshot_id=? AND state_hex IN ({placeholders})
            """,
            (snapshot_id, *neighbor_state_hexes),
        ).fetchall()
    except sqlite3.OperationalError:
        return 0
    neighbor_blocks = {int(r[0]) for r in rows if r[0] is not None}
    if not neighbor_blocks:
        return 0
    try:
        feat_rows = conn.execute(
            "SELECT value_text FROM region_shape_features"
        ).fetchall()
    except sqlite3.OperationalError:
        return 0
    admitted = 0
    for serial in neighbor_blocks:
        needle = str(int(serial))
        for (value_text,) in feat_rows:
            if value_text and needle in str(value_text).split():
                admitted += 1
                break
            if value_text and f"blk[{needle}]" in str(value_text):
                admitted += 1
                break
    return admitted


def gather_evidence(
    conn: sqlite3.Connection,
    row: ByteCascadeRow,
) -> AdmissionEvidence:
    """Run all DB joins for one byte and return :class:`AdmissionEvidence`."""
    snap_id = _latest_dag_snapshot_id(conn)
    if snap_id is None:
        return AdmissionEvidence(
            byte=row.byte,
            block_serial=row.block_serial,
            block_ea=row.block_ea or "?",
            state_hex=None,
            snapshot_id=None,
            dag_pred_count=0,
            dag_succ_count=0,
            chain_size=0,
            neighbors_admitted=0,
            neighbor_state_hexes=(),
        )
    state_hex = _resolve_state_hex_for_block(
        conn, snap_id, row.block_serial,
    )
    if state_hex is None:
        return AdmissionEvidence(
            byte=row.byte,
            block_serial=row.block_serial,
            block_ea=row.block_ea or "?",
            state_hex=None,
            snapshot_id=snap_id,
            dag_pred_count=0,
            dag_succ_count=0,
            chain_size=0,
            neighbors_admitted=0,
            neighbor_state_hexes=(),
        )
    pred_n, succ_n, neighbors = _dag_neighbor_counts(conn, snap_id, state_hex)
    chain_size = _bfs_chain_size(conn, snap_id, state_hex)
    admitted = _count_neighbors_admitted_to_region(conn, snap_id, neighbors)
    return AdmissionEvidence(
        byte=row.byte,
        block_serial=row.block_serial,
        block_ea=row.block_ea or "?",
        state_hex=state_hex,
        snapshot_id=snap_id,
        dag_pred_count=pred_n,
        dag_succ_count=succ_n,
        chain_size=chain_size,
        neighbors_admitted=admitted,
        neighbor_state_hexes=tuple(neighbors),
    )


# ---------------------------------------------------------------------------
# Classifier (pure -- evidence + trace fields in, bucket out)
# ---------------------------------------------------------------------------


def classify(
    row: ByteCascadeRow,
    evidence: AdmissionEvidence,
) -> AdmissionExplanation:
    """Apply the bucket priority list and return the verdict."""
    rejection = (row.candidate_rejection or "-").strip()
    dropped = (row.first_dropped_stage or "-").strip()
    accepted = (row.accepted_stage or "-").strip()

    if rejection not in ("", "-"):
        bucket = "candidate_rejected_pre_raw_region"
    elif dropped == _CALL_BARRIER_STAGE:
        bucket = "call_barrier_collision"
    elif dropped in _PAYLOAD_OR_INTERMEDIATE_STAGES:
        bucket = "payload_or_intermediate_filter"
    elif (
        accepted in _FALLBACK_ACCEPTED_STAGES
        and not row.raw_candidate
    ):
        bucket = "region_table_merge_loss"
    elif (
        evidence.dag_pred_count == 0
        and evidence.dag_succ_count == 0
    ):
        bucket = "not_in_chain"
    elif evidence.chain_size < MIN_ADMISSIBLE_CHAIN_LEN:
        bucket = "chain_too_short"
    else:
        bucket = "no_accepted_pred_or_succ"

    stage = _BUCKET_TO_STAGE.get(bucket, "unknown")
    if bucket == "payload_or_intermediate_filter" and dropped:
        stage = dropped
    return AdmissionExplanation(
        byte=row.byte,
        block_ea=row.block_ea or "?",
        bucket=bucket,
        first_responsible_stage=stage,
        narrative=_BUCKET_TO_NARRATIVE.get(bucket, bucket),
        in_dag=row.in_dag,
        in_corrected_dag=row.in_corrected_dag,
        in_region_table=row.in_region_table,
        raw_candidate=row.raw_candidate,
        candidate_rejection=rejection,
        accepted_stage=accepted,
        first_dropped_stage=dropped,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Top-level pipeline (parse log -> filter -> join -> classify -> render)
# ---------------------------------------------------------------------------


def select_target_rows(
    rows: Sequence[ByteCascadeRow],
    explicit_bytes: Sequence[int] | None,
) -> list[ByteCascadeRow]:
    """Filter trace rows to the bytes the explainer should report on."""
    if explicit_bytes:
        wanted = {int(b) for b in explicit_bytes}
        return [r for r in rows if r.byte in wanted]
    return [
        r for r in rows
        if r.final_status_refined == "region_detection_gap"
        or r.final_status == "region_detection_gap"
    ]


def explain(
    rows: Sequence[ByteCascadeRow],
    db_path: Path,
    *,
    bytes_filter: Sequence[int] | None = None,
) -> list[AdmissionExplanation]:
    """Run the full pipeline against an open trace + diag DB."""
    targets = select_target_rows(rows, bytes_filter)
    if not targets:
        return []
    if not db_path.exists():
        # No DB -- evidence will be empty; classifier still runs on trace
        # fields and will likely return ``not_in_chain`` for every row.
        return [
            classify(r, gather_evidence_no_db(r))
            for r in targets
        ]
    conn = sqlite3.connect(str(db_path))
    try:
        return [classify(r, gather_evidence(conn, r)) for r in targets]
    finally:
        conn.close()


def gather_evidence_no_db(row: ByteCascadeRow) -> AdmissionEvidence:
    """Construct an empty evidence record for the no-DB fallback."""
    return AdmissionEvidence(
        byte=row.byte,
        block_serial=row.block_serial,
        block_ea=row.block_ea or "?",
        state_hex=None,
        snapshot_id=None,
        dag_pred_count=0,
        dag_succ_count=0,
        chain_size=0,
        neighbors_admitted=0,
        neighbor_state_hexes=(),
    )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def format_report(
    explanations: Sequence[AdmissionExplanation],
    *,
    func_label: str | None = None,
) -> str:
    """Render markdown for a list of explanations."""
    title = "## HCC Region Admission Explainer"
    if func_label:
        title = f"## HCC Region Admission Explainer for {func_label}"
    if not explanations:
        return (
            f"{title}\n\n"
            "(no `region_detection_gap` rows found in the trace log -- "
            "either the byte-cascade trace was not produced, or all bytes"
            " were admitted to a raw region or InsertBlock body.)\n"
        )
    header = (
        "| byte | block_ea | bucket | first_responsible_stage |"
        " in_dag | in_corr | in_region | preds | succs | chain |"
        " neighbors_admitted | candidate_rejection | accepted_stage |"
        " first_dropped_stage |"
    )
    sep = "|-|-|-|-|-|-|-|-|-|-|-|-|-|-|"
    lines: list[str] = [title, "", header, sep]
    for ex in explanations:
        ev = ex.evidence
        lines.append(
            "| "
            + " | ".join([
                str(ex.byte),
                ex.block_ea,
                ex.bucket,
                ex.first_responsible_stage,
                "1" if ex.in_dag else "0",
                "1" if ex.in_corrected_dag else "0",
                "1" if ex.in_region_table else "0",
                str(ev.dag_pred_count),
                str(ev.dag_succ_count),
                str(ev.chain_size),
                str(ev.neighbors_admitted),
                ex.candidate_rejection or "-",
                ex.accepted_stage or "-",
                ex.first_dropped_stage or "-",
            ])
            + " |"
        )
    lines.extend(["", "### Verdict per byte", ""])
    for ex in explanations:
        ev = ex.evidence
        lines.append(
            f"- byte {ex.byte} (`{ex.block_ea}`): `{ex.bucket}`"
            f" -- {ex.narrative}; first responsible stage:"
            f" `{ex.first_responsible_stage}`"
        )
        if ex.candidate_rejection and ex.candidate_rejection != "-":
            lines.append(
                f"  - candidate_rejection: `{ex.candidate_rejection}`"
            )
        if ev.state_hex:
            lines.append(
                f"  - state_hex: `{ev.state_hex}` (snapshot"
                f" {ev.snapshot_id}); chain size {ev.chain_size};"
                f" {ev.dag_pred_count} preds, {ev.dag_succ_count} succs;"
                f" {ev.neighbors_admitted}/{len(ev.neighbor_state_hexes)}"
                f" neighbors admitted to region features"
            )
        else:
            lines.append(
                "  - no `dag_node_blocks` row joined for this byte's block;"
                " admission verdict relies on trace fields only"
            )
    return "\n".join(lines) + "\n"


def format_report_json(
    explanations: Sequence[AdmissionExplanation],
) -> str:
    return json.dumps([ex.to_dict() for ex in explanations], indent=2)


# ---------------------------------------------------------------------------
# Public entry point used by `python -m d810.diagnostics admission-explain`
# ---------------------------------------------------------------------------


def run(
    log_path: Path,
    db_path: Path,
    *,
    bytes_filter: Sequence[int] | None = None,
    func_label: str | None = None,
    as_json: bool = False,
) -> str:
    """Parse the log, run joins against the DB, and return a formatted report.

    Returns ``Error: ...`` when the log file is missing so callers can use
    the ``Error:`` sentinel to set a non-zero exit code (mirrors
    ``cascade_egress_plan.run_plan``).
    """
    if not log_path.exists():
        return f"Error: log not found: {log_path}\n"
    rows = parse_trace_log(log_path.read_text(encoding="utf-8", errors="replace"))
    explanations = explain(rows, db_path, bytes_filter=bytes_filter)
    if as_json:
        return format_report_json(explanations) + "\n"
    return format_report(explanations, func_label=func_label)
