"""``unflat-why`` diagnostics command (ticket d81-k1ct).

Renders, in causal order, why an unflatten candidate for one function ended
the way it did: the terminal outcome record(s) from
``unflatten_candidate_outcomes`` (schema v13+, ticket d81-rhu6), the evidence
each disposition points at, and one dense "what to do next" line.

This module owns every SQL statement issued for this command; it reads only
the diag DB (§3.5/§5.1 of the 2026-09-02 unflat-diagnostics-legibility plan).
Absent evidence is always printed as ``not recorded`` and names the fact
kind or table it looked for -- it is never silently skipped, because the
plan documents a live regression (ticket aa-8v89) where the corridor
coverage / preflight-proof facts go missing and the gap needs to stay
visible rather than collapse into an empty report.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from d810.diagnostics.output import get_output, write_output

#: Facts named by the legibility plan that are not currently emitted by any
#: known-good run (ticket aa-8v89 regression); rendered generically since no
#: verified real payload shape exists to format precisely.
_PREFLIGHT_AND_COVERAGE_FACT_KINDS = (
    "UnflattenDispatcherRemovalPreflightProof",
    "UnflattenDispatcherCorridorCoverageSummary",
)

_RECOVERY_STATUS_KIND = "UnflattenRecoveryStatus"
_DIAGNOSTICS_INCOMPLETE_KIND = "UnflattenDiagnosticsIncomplete"

_NEXT_STEP_TEMPLATES = {
    "not_submitted_safe_bail": (
        "safe bail: inspect the residual dispatcher corridor / unresolved "
        "state-write anchor named in the coverage evidence above for the "
        "block that kept this candidate's plan from being submitted."
    ),
    "rejected_preflight": (
        "rejected at preflight: check the PreflightProof / "
        "CorridorCoverageSummary evidence above for the obligation that "
        "rejected this plan."
    ),
    "applied_observed": (
        "applied: this plan committed cleanly; nothing further to check "
        "unless a later attempt on the same graph reopened it."
    ),
    "exhausted": (
        "exhausted: recovery excluded this exact candidate identity for "
        "this graph fingerprint; check the coverage evidence above for why."
    ),
}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--func",
        type=lambda value: int(value, 0),
        required=True,
        help="Function EA in hex (for example 0x7FFB0EB06E50)",
    )


def run(args: argparse.Namespace) -> int:
    func_ea = int(getattr(args, "func", 0))
    conn_path = Path(str(getattr(args, "db", ".tmp/diag.sqlite3")))
    if not conn_path.exists():
        print(f"unflat-why: diag DB not found: {conn_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(conn_path))
    conn.row_factory = sqlite3.Row
    out = get_output(args)
    try:
        for line in render_unflat_why(conn, func_ea):
            write_output(out, line)
    finally:
        conn.close()
    return 0


# ---------------------------------------------------------------------------
# Rendering (pure over an already-open connection; unit-testable directly)
# ---------------------------------------------------------------------------


def render_unflat_why(conn: sqlite3.Connection, func_ea: int) -> list[str]:
    """Render the full causal-order report for ``func_ea``."""
    func_ea_i64 = int(func_ea)
    lines: list[str] = [f"unflat-why func=0x{func_ea_i64:x}"]

    if not _table_exists(conn, "unflatten_candidate_outcomes"):
        lines.append(
            "unflatten_candidate_outcomes: not recorded (schema predates "
            "ticket d81-rhu6 slice 1; this diag DB has no terminal outcome "
            "table)"
        )
        _render_fallback_cfg_transactions(lines, conn, func_ea_i64)
        return lines

    rows = _fetch_outcome_rows(conn, func_ea_i64)
    if not rows:
        lines.append("unflatten_candidate_outcomes: no rows for this function")
        _render_fallback_cfg_transactions(lines, conn, func_ea_i64)
        return lines

    groups = _build_groups(rows)
    for group_rows in groups.values():
        deciding_row = _render_group(lines, group_rows)
        _render_group_evidence(lines, conn, func_ea_i64, deciding_row)
        lines.append(f"  next: {_next_step(deciding_row)}")
        lines.append("")

    _render_state_write_resolutions(lines, conn, func_ea_i64)
    _render_emulator_gaps(lines, conn, func_ea_i64)
    _render_recovery_search(lines, conn, func_ea_i64)
    return lines


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _pair(left: object, right: object) -> str:
    return f"{'?' if left is None else left}/{'?' if right is None else right}"


def _safe_json(text: object) -> dict:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Terminal outcome records (§1)
# ---------------------------------------------------------------------------


def _fetch_outcome_rows(
    conn: sqlite3.Connection, func_ea_i64: int
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT maturity, graph_fingerprint, candidate_identity, attempt,
               disposition, reason, plan_id, handlers_recovered,
               handlers_total, dag_nodes, dag_edges, coverage_covered,
               coverage_residual, committed_batches_before,
               unresolved_anchors_json, next_hint
        FROM unflatten_candidate_outcomes
        WHERE func_ea_i64 = ?
        ORDER BY rowid
        """,
        (int(func_ea_i64),),
    ).fetchall()


def _group_key(row: sqlite3.Row) -> tuple[str, str, str]:
    return (row["maturity"], row["candidate_identity"], row["graph_fingerprint"])


def _build_groups(
    rows: list[sqlite3.Row],
) -> dict[tuple[str, str, str], list[sqlite3.Row]]:
    groups: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(_group_key(row), []).append(row)
    return groups


def _build_runs(rows: list[sqlite3.Row]) -> list[dict]:
    """Collapse consecutive attempts sharing (disposition, reason) into a run."""
    ordered = sorted(rows, key=lambda row: int(row["attempt"]))
    runs: list[dict] = []
    for row in ordered:
        sig = (row["disposition"], row["reason"])
        if runs and runs[-1]["sig"] == sig:
            runs[-1]["rows"].append(row)
        else:
            runs.append({"sig": sig, "rows": [row]})
    return runs


def _format_run(run: dict) -> str:
    rows = run["rows"]
    disposition, reason = run["sig"]
    attempts = [int(row["attempt"]) for row in rows]
    if len(rows) > 1:
        attempt_desc = f"attempts {attempts[0]}-{attempts[-1]} ({len(rows)} identical attempts)"
    else:
        attempt_desc = f"attempt {attempts[0]}"
    row = rows[-1]
    plan_id = row["plan_id"] or "-"
    handlers = _pair(row["handlers_recovered"], row["handlers_total"])
    dag = _pair(row["dag_nodes"], row["dag_edges"])
    coverage = _pair(row["coverage_covered"], row["coverage_residual"])
    return (
        f"{attempt_desc}: disposition={disposition} reason={reason} "
        f"plan_id={plan_id} handlers={handlers} dag={dag} coverage={coverage}"
    )


def _render_group(lines: list[str], group_rows: list[sqlite3.Row]) -> sqlite3.Row:
    """Render one (maturity, candidate, graph) group; return the deciding row."""
    maturity, candidate_identity, graph_fingerprint = _group_key(group_rows[0])
    lines.append(
        f"outcome maturity={maturity} candidate={candidate_identity} "
        f"graph={graph_fingerprint}"
    )
    runs = _build_runs(group_rows)
    deciding_run = runs[-1]
    earlier_runs = runs[:-1]
    lines.append(f"  {_format_run(deciding_run)}  <- deciding")
    for run in earlier_runs:
        lines.append(f"  {_format_run(run)}")
    return deciding_run["rows"][-1]


# ---------------------------------------------------------------------------
# Evidence (§2)
# ---------------------------------------------------------------------------


def _fetch_fact_rows(
    conn: sqlite3.Connection, func_ea_i64: int, maturity: str, kind: str
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT payload FROM fact_observations
        WHERE func_ea_i64 = ? AND maturity = ? AND kind = ?
        ORDER BY rowid
        """,
        (int(func_ea_i64), str(maturity), str(kind)),
    ).fetchall()


def _format_recovery_status(payload: dict) -> str:
    state_var = (
        f"stkoff={payload.get('state_var_stkoff')}"
        if payload.get("state_var_stkoff") is not None
        else f"reg={payload.get('state_var_reg')}"
    )
    return (
        f"map_rows={payload.get('map_rows')} "
        f"dispatcher_entry={payload.get('dispatcher_entry')} "
        f"state_var={state_var} "
        f"recovery_present={payload.get('recovery_present')}"
    )


def _format_diagnostics_incomplete(payload: dict) -> str:
    return (
        f"budget={payload.get('budget')} consumed={payload.get('consumed_units')} "
        f"reason={payload.get('reason')} phase={payload.get('phase')} "
        f"capture_scope={payload.get('capture_scope')}"
    )


def _fetch_cfg_transaction_attempt(
    conn: sqlite3.Connection, plan_id: str, attempt_id: str
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT plan_id, attempt_id, current_phase, first_failure_obligation,
               first_failure_phase, first_failure_reason, interr_code
        FROM cfg_transaction_attempts
        WHERE plan_id = ? AND attempt_id = ?
        """,
        (str(plan_id), str(attempt_id)),
    ).fetchone()


def _count_committed_before(
    conn: sqlite3.Connection, func_ea_i64: int, attempt_row: sqlite3.Row
) -> int:
    """Count committed batches that precede ``attempt_row`` (rowid order)."""
    poisoned_rowid = conn.execute(
        "SELECT rowid FROM cfg_transaction_attempts WHERE plan_id=? AND attempt_id=?",
        (attempt_row["plan_id"], attempt_row["attempt_id"]),
    ).fetchone()[0]
    count_row = conn.execute(
        """
        SELECT count(*) FROM cfg_transaction_attempts
        WHERE func_ea_i64 = ? AND current_phase = 'committed' AND rowid < ?
        """,
        (int(func_ea_i64), poisoned_rowid),
    ).fetchone()
    return int(count_row[0])


def _fetch_snapshots(conn: sqlite3.Connection, func_ea_i64: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, label, maturity, phase FROM snapshots WHERE func_ea_i64=? ORDER BY id",
        (int(func_ea_i64),),
    ).fetchall()


def _render_snapshot_list(
    lines: list[str], conn: sqlite3.Connection, func_ea_i64: int, maturity: str
) -> None:
    rows = _fetch_snapshots(conn, func_ea_i64)
    if not rows:
        lines.append("    snapshots: not recorded")
        return
    lines.append("    snapshots:")
    for row in rows:
        lines.append(
            f"      id={row['id']} label={row['label']} "
            f"maturity={row['maturity']} phase={row['phase']}"
        )
    expected_label = f"maturity_{maturity}_pre_d810"
    if not any(row["label"] == expected_label for row in rows):
        lines.append(
            f"    missing: {expected_label} (Hex-Rays delivered no block "
            "callback at this maturity)"
        )


def _render_group_evidence(
    lines: list[str],
    conn: sqlite3.Connection,
    func_ea_i64: int,
    deciding_row: sqlite3.Row,
) -> None:
    maturity = deciding_row["maturity"]
    disposition = deciding_row["disposition"]

    for kind in _PREFLIGHT_AND_COVERAGE_FACT_KINDS:
        rows = _fetch_fact_rows(conn, func_ea_i64, maturity, kind)
        if not rows:
            lines.append(f"    {kind}: not recorded")
            continue
        for row in rows:
            lines.append(
                f"    {kind}: {json.dumps(_safe_json(row['payload']), sort_keys=True)}"
            )

    recovery_rows = _fetch_fact_rows(
        conn, func_ea_i64, maturity, _RECOVERY_STATUS_KIND
    )
    if not recovery_rows:
        lines.append(f"    {_RECOVERY_STATUS_KIND}: not recorded")
    else:
        for row in recovery_rows:
            lines.append(
                f"    {_RECOVERY_STATUS_KIND}: "
                f"{_format_recovery_status(_safe_json(row['payload']))}"
            )

    incomplete_rows = _fetch_fact_rows(
        conn, func_ea_i64, maturity, _DIAGNOSTICS_INCOMPLETE_KIND
    )
    if not incomplete_rows:
        lines.append(f"    {_DIAGNOSTICS_INCOMPLETE_KIND}: not recorded")
    else:
        for row in incomplete_rows:
            lines.append(
                f"    {_DIAGNOSTICS_INCOMPLETE_KIND}: "
                f"{_format_diagnostics_incomplete(_safe_json(row['payload']))}"
            )

    if disposition == "poisoned_restart_required":
        attempt_row = None
        if _table_exists(conn, "cfg_transaction_attempts"):
            attempt_row = _fetch_cfg_transaction_attempt(
                conn, deciding_row["graph_fingerprint"], deciding_row["candidate_identity"]
            )
        if attempt_row is None:
            lines.append("    cfg_transaction_attempts: not recorded")
        else:
            committed_before = _count_committed_before(conn, func_ea_i64, attempt_row)
            lines.append(
                "    cfg_transaction_attempts: "
                f"first_failure_phase={attempt_row['first_failure_phase']} "
                f"first_failure_obligation={attempt_row['first_failure_obligation']} "
                f"first_failure_reason={attempt_row['first_failure_reason']} "
                f"committed_before={committed_before}"
            )

    if disposition == "maturity_no_callbacks":
        _render_snapshot_list(lines, conn, func_ea_i64, maturity)


def _next_step(row: sqlite3.Row) -> str:
    disposition = row["disposition"]
    if disposition == "poisoned_restart_required":
        return (
            "poisoned: the rejecting obligation is named in the "
            "cfg_transaction_attempts row above for "
            f"attempt={row['candidate_identity']}; batches already "
            "committed before it stay applied under quarantine."
        )
    if disposition == "maturity_no_callbacks":
        return (
            "no callbacks (d81-lbe8 class): Hex-Rays delivered no optblock "
            f"callback at {row['maturity']}; check the snapshot list above "
            f"for the missing maturity_{row['maturity']}_pre_d810 marker."
        )
    template = _NEXT_STEP_TEMPLATES.get(disposition)
    if template:
        return template
    return f"disposition={disposition}: no next-step guidance recorded for this disposition."


#: How many unresolved corridors the report lists before it truncates.
_TOP_UNRESOLVED_CORRIDORS = 10


def _render_state_write_resolutions(
    lines: list[str], conn: sqlite3.Connection, func_ea_i64: int
) -> None:
    """Decompose the residual dispatcher corridors by cause (ticket d81-qt4v).

    A residual count on its own says nothing an operator can act on; the
    per-cause split names which evaluator gap to close first, and the
    contributor listing names the exact corridors blocked on each one.
    """
    if not _table_exists(conn, "state_write_resolutions"):
        lines.append(
            "state_write_resolutions: not recorded (schema predates ticket "
            "d81-qt4v slice 4; this diag DB carries no StateWriteResolutionFact)"
        )
        return
    rows = conn.execute(
        """
        SELECT block_serial, block_ea_hex, corridor, outcome, cause, reason,
               store_cells, folded_value_hex, def_sites_json,
               contributed_to_unresolved_transition
        FROM state_write_resolutions
        WHERE func_ea_i64 = ?
        ORDER BY block_serial, corridor, rowid
        """,
        (int(func_ea_i64),),
    ).fetchall()
    if not rows:
        lines.append(
            "state_write_resolutions: not recorded (no StateWriteResolutionFact "
            "for this function)"
        )
        return

    counts: dict[str, int] = {}
    for row in rows:
        cause = row["cause"]
        counts[cause] = counts.get(cause, 0) + 1
    decomposition = " ".join(
        f"{cause}={count}"
        for cause, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    contributors = [
        row for row in rows if row["contributed_to_unresolved_transition"]
    ]
    lines.append(
        f"state_write_resolutions: {len(rows)} corridor consult(s); "
        f"{decomposition}"
    )
    for row in rows:
        folded = row["folded_value_hex"]
        value = "" if folded is None else f" value=0x{int(folded, 16):x}"
        lines.append(
            f"  blk{row['block_serial']}@{row['block_ea_hex']} "
            f"corridor={row['corridor']} outcome={row['outcome']} "
            f"cause={row['cause']} store_cells={row['store_cells']}{value}"
        )
    if not contributors:
        lines.append(
            "  unresolved corridors: none (no consult fed an unresolved "
            "transition)"
        )
        return
    shown = contributors[:_TOP_UNRESOLVED_CORRIDORS]
    truncated = len(contributors) - len(shown)
    header = f"  top unresolved corridors ({len(contributors)} contributor(s))"
    if truncated > 0:
        header += f", {truncated} more not shown"
    lines.append(header + ":")
    for row in shown:
        def_sites = _safe_def_sites(row["def_sites_json"])
        sites = (
            ""
            if not def_sites
            else " defs=" + ",".join(f"blk{blk}@0x{ea:x}" for blk, ea in def_sites)
        )
        reason = f" reason={row['reason']}" if row["reason"] else ""
        lines.append(
            f"    blk{row['block_serial']} corridor={row['corridor']} "
            f"cause={row['cause']}{sites}{reason}"
        )


def _safe_def_sites(text: object) -> list[tuple[int, int]]:
    """Parse a ``def_sites_json`` column; a malformed value renders as empty."""
    if not text:
        return []
    try:
        loaded = json.loads(str(text))
    except (TypeError, ValueError):
        return []
    sites: list[tuple[int, int]] = []
    if not isinstance(loaded, list):
        return []
    for entry in loaded:
        try:
            blk, ea = entry
            sites.append((int(blk), int(ea)))
        except (TypeError, ValueError):
            continue
    return sites


#: How many gap sites the report lists before it truncates.
_TOP_EMULATOR_GAP_SITES = 20


def _render_emulator_gaps(
    lines: list[str], conn: sqlite3.Connection, func_ea_i64: int
) -> None:
    """List the evaluator gaps this function hit, by cause (ticket d81-c6n7).

    The emulator's WARNINGs are a worklist: each cause is a real, individually
    fixable gap, and the count says which one to close first.  ``occurrences``
    is the pre-dedupe sighting count, so a single-site gap that fired 2,000
    times is still visible as such.
    """
    if not _table_exists(conn, "emulator_gaps"):
        lines.append(
            "emulator_gaps: not recorded (schema predates ticket d81-c6n7 "
            "slice 5; this diag DB carries no EmulatorGapFact)"
        )
        return
    rows = conn.execute(
        """
        SELECT attempt, cause, site_ea_hex, block_serial, occurrences, detail,
               def_sites_json
        FROM emulator_gaps
        WHERE func_ea_i64 = ?
        ORDER BY attempt, cause, site_ea_i64, rowid
        """,
        (int(func_ea_i64),),
    ).fetchall()
    if not rows:
        lines.append(
            "emulator_gaps: not recorded (no EmulatorGapFact for this function)"
        )
        return

    counts: dict[str, int] = {}
    for row in rows:
        cause = row["cause"]
        counts[cause] = counts.get(cause, 0) + int(row["occurrences"])
    decomposition = " ".join(
        f"{cause}={count}"
        for cause, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    total = sum(counts.values())
    lines.append(
        f"emulator_gaps: {len(rows)} site(s), {total} sighting(s); "
        f"{decomposition}"
    )
    shown = rows[:_TOP_EMULATOR_GAP_SITES]
    truncated = len(rows) - len(shown)
    for row in shown:
        def_sites = _safe_def_sites(row["def_sites_json"])
        sites = (
            ""
            if not def_sites
            else " defs=" + ",".join(f"blk{blk}@0x{ea:x}" for blk, ea in def_sites)
        )
        detail = f" detail={row['detail']}" if row["detail"] else ""
        lines.append(
            f"  attempt{row['attempt']} cause={row['cause']} "
            f"blk{row['block_serial']}@{row['site_ea_hex']} "
            f"x{row['occurrences']}{sites}{detail}"
        )
    if truncated > 0:
        lines.append(f"  ... {truncated} more gap site(s) not shown")


def _render_recovery_search(
    lines: list[str], conn: sqlite3.Connection, func_ea_i64: int
) -> None:
    if not _table_exists(conn, "recovery_search_outcomes"):
        lines.append("recovery_search_outcomes: not recorded (table absent)")
        return
    rows = conn.execute(
        """
        SELECT provider, outcome, budget, consumed, reason
        FROM recovery_search_outcomes
        WHERE func_ea_i64 = ?
        ORDER BY rowid
        """,
        (int(func_ea_i64),),
    ).fetchall()
    if not rows:
        lines.append("recovery_search_outcomes: not recorded")
        return
    counts: dict[tuple, int] = {}
    for row in rows:
        key = (row["provider"], row["outcome"], row["budget"], row["consumed"], row["reason"])
        counts[key] = counts.get(key, 0) + 1
    lines.append("recovery_search_outcomes:")
    for (provider, outcome, budget, consumed, reason), count in counts.items():
        suffix = f" (x{count})" if count > 1 else ""
        lines.append(
            f"  provider={provider} outcome={outcome} budget={budget} "
            f"consumed={consumed} reason={reason}{suffix}"
        )


# ---------------------------------------------------------------------------
# Degraded path: no unflatten_candidate_outcomes table (pre-d81-rhu6 DBs)
# ---------------------------------------------------------------------------


def _render_fallback_cfg_transactions(
    lines: list[str], conn: sqlite3.Connection, func_ea_i64: int
) -> None:
    if not _table_exists(conn, "cfg_transaction_attempts"):
        lines.append("cfg_transaction_attempts: not recorded (table absent)")
        return
    rows = conn.execute(
        """
        SELECT plan_id, attempt_id, current_phase, mutation_started, poisoned,
               first_failure_obligation, first_failure_phase,
               first_failure_reason, interr_code
        FROM cfg_transaction_attempts
        WHERE func_ea_i64 = ?
        ORDER BY rowid
        """,
        (int(func_ea_i64),),
    ).fetchall()
    if not rows:
        lines.append("cfg_transaction_attempts: no rows for this function")
        return

    lines.append("cfg_transaction_attempts:")
    committed_before = 0
    for row in rows:
        if row["current_phase"] == "committed":
            committed_before += 1
            lines.append(
                f"  plan_id={row['plan_id']} attempt_id={row['attempt_id']} "
                f"phase={row['current_phase']}"
            )
            continue
        lines.append(
            f"  plan_id={row['plan_id']} attempt_id={row['attempt_id']} "
            f"phase={row['current_phase']} "
            f"first_failure_obligation={row['first_failure_obligation']} "
            f"first_failure_phase={row['first_failure_phase']} "
            f"first_failure_reason={row['first_failure_reason']} "
            f"committed_before={committed_before}"
        )
        if row["poisoned"]:
            lines.append(
                "  next: poisoned: the rejecting obligation is named above "
                f"for attempt={row['attempt_id']}; {committed_before} "
                "batch(es) committed before it stay applied under "
                "quarantine."
            )
