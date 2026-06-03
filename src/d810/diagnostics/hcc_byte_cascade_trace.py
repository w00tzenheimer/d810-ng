"""Parser + report for HCC byte-cascade trace rows.

Consumes ``HCC_BYTE_CASCADE_TRACE_ROW byte=N k=v ...`` lines emitted by
``byte_cascade_coverage_tracer.ByteCascadeCoverageTracer`` and produces a
report suitable for terminal display or downstream JSON consumption.

When a diag DB path is provided, the report is optionally enriched with the
``%var_190.8+#k.8`` reference count per snapshot, so the per-byte HCC
trajectory can be cross-referenced against the snap17 -> snap18 IDA
optimize_global drop documented in the byte-cascade verdict.

Pure module, no ``ida_hexrays`` import, fully unit-testable.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from d810.core.diag import read_diag_db
from d810.core.diag.models import Snapshot
from d810.core.typing import Any, Iterable, Sequence


ROW_LOG_PREFIX = "HCC_BYTE_CASCADE_TRACE_ROW"

# Match ``key=value`` where value is either quoted ('...' or "...") or a
# whitespace-delimited bareword.
_KV_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"
    r"'(?:\\.|[^'\\])*'|"  # single-quoted
    r'"(?:\\.|[^"\\])*"|'  # double-quoted
    r"[^\s]+"               # bareword
    r")"
)

# Fields the tracer emits with integer-like values.
_INT_FIELDS = frozenset({"byte", "block_serial", "entry_anchor"})
# Fields the tracer emits as 0/1 booleans.
_BOOL_FIELDS = frozenset(
    {"in_dag", "in_corrected_dag", "in_region_table",
     "raw_candidate", "preserved_in_insertblock"}
)


@dataclass(frozen=True, slots=True)
class ByteCascadeRow:
    """One parsed trace row + optional DB enrichment."""

    byte: int
    block_ea: str
    block_serial: int | None
    entry_anchor: int | None
    dag_node: str
    in_dag: bool
    in_corrected_dag: bool
    in_region_table: bool
    raw_candidate: bool
    candidate_rejection: str
    accepted_stage: str
    emitted_mod: str
    preserved_in_insertblock: bool
    first_dropped_stage: str
    final_status: str
    source_eas: tuple[str, ...] = ()
    raw_fields: dict[str, str] = field(default_factory=dict)
    db_var190_refs: dict[str, int] = field(default_factory=dict)
    db_source_ea_survival: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def final_status_refined(self) -> str:
        """Refine ``preserved_redirect`` using **source-EA-level** snap-18 survival.

        The byte-wide ``%var_190.8+#k.8`` LIKE count is too coarse to drive
        the decision -- it can promote a row to ``with_evidence`` because
        SOME ``var_190+#k`` ref survives in a live block, even when the
        specific m_stx EA that the byte's HCC redirect points at is gone.
        So the refinement requires evidence on :attr:`source_eas`:

        - For each finalization snapshot (see
          :func:`_is_finalization_evidence_label`), look up the per-EA
          count in :attr:`db_source_ea_survival`.
        - ``preserved_redirect_with_evidence`` when *any* of the byte's
          source EAs survives in *any* finalization snapshot.
        - ``redirect_only_finalization_loss`` when *every* source EA is
          dead in *every* finalization snapshot.
        - Stay ``preserved_redirect`` when the row has no source EAs, no
          source-EA DB enrichment, or no finalization snapshots in the DB.
          We must not promote on insufficient evidence.

        Non-``preserved_redirect`` statuses pass through unchanged.
        ``db_var190_refs`` is retained for informational cross-reference
        rendering only; it no longer drives the refinement.
        """
        if self.final_status != "preserved_redirect":
            return self.final_status
        if not self.source_eas or not self.db_source_ea_survival:
            return self.final_status
        finalization_per_ea = [
            per_ea
            for label, per_ea in self.db_source_ea_survival.items()
            if _is_finalization_evidence_label(label)
        ]
        if not finalization_per_ea:
            return self.final_status
        any_survives = any(
            count > 0
            for per_ea in finalization_per_ea
            for count in per_ea.values()
        )
        if any_survives:
            return "preserved_redirect_with_evidence"
        return "redirect_only_finalization_loss"

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte": self.byte,
            "block_ea": self.block_ea,
            "block_serial": self.block_serial,
            "entry_anchor": self.entry_anchor,
            "dag_node": self.dag_node,
            "in_dag": self.in_dag,
            "in_corrected_dag": self.in_corrected_dag,
            "in_region_table": self.in_region_table,
            "raw_candidate": self.raw_candidate,
            "candidate_rejection": self.candidate_rejection,
            "accepted_stage": self.accepted_stage,
            "emitted_mod": self.emitted_mod,
            "preserved_in_insertblock": self.preserved_in_insertblock,
            "first_dropped_stage": self.first_dropped_stage,
            "final_status": self.final_status,
            "final_status_refined": self.final_status_refined,
            "source_eas": list(self.source_eas),
            "db_var190_refs": dict(self.db_var190_refs),
            "db_source_ea_survival": {
                label: dict(per_ea)
                for label, per_ea in self.db_source_ea_survival.items()
            },
        }


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _coerce_int(value: str) -> int | None:
    text = _strip_quotes(value).strip()
    if text in ("", "-", "?", "None"):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _coerce_bool(value: str) -> bool:
    text = _strip_quotes(value).strip()
    return text in ("1", "true", "True", "yes")


def _coerce_ea_list(value: str) -> tuple[str, ...]:
    """Parse a ``0xA,0xB,0xC`` (or single ``-``) comma-separated EA list."""
    text = _strip_quotes(value).strip()
    if text in ("", "-"):
        return ()
    return tuple(item.strip() for item in text.split(",") if item.strip())


def _is_finalization_evidence_label(label: str) -> bool:
    """Return True if *label* is downstream of GLBOPT1 finalization.

    The diag DB also contains early ``LOCOPT_post_d810`` and
    ``CALLS_post_d810`` captures. Those are before HCC and before the
    snap17 -> snap18 ``optimize_global`` loss we are classifying, so they
    must not promote a redirect-only row to "with evidence".
    """
    text = str(label or "")
    if text == "post_d810":
        return True
    if text.startswith("dump_raw_"):
        return False
    if text.startswith("dump_d810_"):
        return True
    if "MMAT_LVARS" in text:
        return True
    if "MMAT_GLBOPT1" in text:
        return "post_d810" in text
    if "MMAT_GLBOPT2" in text or "MMAT_GLBOPT3" in text:
        return True
    if "GLBOPT" in text and "post_d810" in text:
        return True
    return False


def parse_trace_line(line: str) -> ByteCascadeRow | None:
    """Parse a single ``HCC_BYTE_CASCADE_TRACE_ROW`` line, or return ``None``.

    Tolerates leading log prefixes such as ``"... INFO HCC_BYTE_CASCADE_..."``.
    """
    marker = line.find(ROW_LOG_PREFIX)
    if marker < 0:
        return None
    body = line[marker + len(ROW_LOG_PREFIX):].strip()
    raw_fields: dict[str, str] = {}
    for match in _KV_RE.finditer(body):
        raw_fields[match.group("key")] = match.group("value")
    if "byte" not in raw_fields:
        return None
    byte_index = _coerce_int(raw_fields["byte"])
    if byte_index is None:
        return None
    return ByteCascadeRow(
        byte=byte_index,
        block_ea=_strip_quotes(raw_fields.get("block_ea", "?")),
        block_serial=_coerce_int(raw_fields.get("block_serial", "?")),
        entry_anchor=_coerce_int(raw_fields.get("entry_anchor", "?")),
        dag_node=_strip_quotes(raw_fields.get("dag_node", "?")),
        in_dag=_coerce_bool(raw_fields.get("in_dag", "0")),
        in_corrected_dag=_coerce_bool(raw_fields.get("in_corrected_dag", "0")),
        in_region_table=_coerce_bool(raw_fields.get("in_region_table", "0")),
        raw_candidate=_coerce_bool(raw_fields.get("raw_candidate", "0")),
        candidate_rejection=_strip_quotes(
            raw_fields.get("candidate_rejection", "-")
        ),
        accepted_stage=_strip_quotes(raw_fields.get("accepted_stage", "-")),
        emitted_mod=_strip_quotes(raw_fields.get("emitted_mod", "-")),
        preserved_in_insertblock=_coerce_bool(
            raw_fields.get("preserved_in_insertblock", "0")
        ),
        first_dropped_stage=_strip_quotes(
            raw_fields.get("first_dropped_stage", "-")
        ),
        final_status=_strip_quotes(raw_fields.get("final_status", "unknown")),
        source_eas=_coerce_ea_list(raw_fields.get("source_eas", "-")),
        raw_fields=dict(raw_fields),
    )


def parse_trace_log(log_text: str) -> list[ByteCascadeRow]:
    """Parse all trace rows in *log_text*.

    Later occurrences of the same byte index overwrite earlier ones, so
    multi-decompile logs return the LAST observed state per byte.
    """
    by_byte: dict[int, ByteCascadeRow] = {}
    for line in log_text.splitlines():
        row = parse_trace_line(line)
        if row is None:
            continue
        by_byte[row.byte] = row
    return [by_byte[k] for k in sorted(by_byte.keys())]


# ---------------------------------------------------------------------------
# DB enrichment (optional)
# ---------------------------------------------------------------------------


_SNAP_LABEL_PRIORITIES: tuple[tuple[str, str], ...] = (
    ("pre_d810", "snap_pre_d810"),
    ("post_bundle_stabilize", "snap_post_bundle_stabilize"),
    ("post_d810", "snap_post_d810"),
    ("MMAT_LVARS", "snap_mmat_lvars"),
)


def _count_var190_refs_per_snapshot(
    conn: sqlite3.Connection,
    byte_index: int,
) -> dict[str, int]:
    """Count instructions referencing ``%var_190.8+#<byte>.8`` per snapshot.

    Returns a mapping of human-readable label -> count. Robust to schemas
    that lack one of the columns; returns ``{}`` on any error.
    """
    if byte_index == 0:
        # Byte 0 has no offset form and is not informative here; skip it.
        return {}
    pattern = f"%var_190.8+#{byte_index}.8%"
    # raw-SQL: LEFT JOIN + COUNT aggregate grouped per snapshot, gated by a
    # dstr LIKE pattern in the JOIN condition (LIKE maps to GLOB on SQLite
    # under the ORM); a per-snapshot conditional-count is a natural SQL
    # aggregate, not a query-builder fit (§3 complex-SQL policy).
    try:
        cursor = conn.execute(
            """
            SELECT s.id, s.label, COUNT(i.dstr) AS n
            FROM snapshots s
            LEFT JOIN instructions i
              ON i.snapshot_id = s.id
             AND i.dstr LIKE ?
            GROUP BY s.id, s.label
            ORDER BY s.id
            """,
            (pattern,),
        )
    except sqlite3.OperationalError:
        return {}
    result: dict[str, int] = {}
    for row in cursor.fetchall():
        label = str(row[1] or f"snapshot_{row[0]}")
        result[label] = int(row[2])
    return result


def _count_source_ea_survival_per_snapshot(
    conn: sqlite3.Connection,
    source_eas: Sequence[str],
) -> dict[str, dict[str, int]]:
    """For each EA in *source_eas*, count ``instructions.ea_hex`` rows per
    snapshot.

    Returns ``{snapshot_label: {ea_hex_lower: count}}`` with every
    ``(snapshot_label, ea)`` pair populated -- a missing pair would conflate
    "this snapshot doesn't exist in the DB" with "the EA is dead at this
    snapshot", which the refinement decision needs to tell apart.

    The diag writer stores ``ea_hex`` as ``0x{:016x}`` (lowercase, 16-digit
    zero-padded); the tracer emits ``source_eas`` in the same format via
    :func:`d810.analyses.control_flow.byte_cascade_coverage_tracer._format_ea_hex`
    (uppercase variant), so we normalise both sides to lowercase before
    matching.

    Returns ``{}`` on any schema mismatch or empty input.
    """
    eas_lower = [
        ea.lower() for ea in source_eas if isinstance(ea, str) and ea.strip()
    ]
    if not eas_lower:
        return {}
    try:
        snap_rows = (
            Snapshot.select(Snapshot.id, Snapshot.label)
            .order_by(Snapshot.id)
            .tuples()
        )
        placeholders = ",".join("?" for _ in eas_lower)
        # raw-SQL: GROUP BY (snapshot, LOWER(ea_hex)) COUNT aggregate with a
        # LOWER()-normalised IN filter -- a grouped survival count that an
        # ORM rewrite would not clarify (§3 complex-SQL policy).
        survival_rows = conn.execute(
            f"""
            SELECT i.snapshot_id, LOWER(i.ea_hex), COUNT(*) AS n
            FROM instructions i
            WHERE LOWER(i.ea_hex) IN ({placeholders})
            GROUP BY i.snapshot_id, LOWER(i.ea_hex)
            """,
            eas_lower,
        ).fetchall()
    except sqlite3.OperationalError:
        return {}

    counts_by_snap_ea: dict[int, dict[str, int]] = {}
    for snap_id, ea_hex, n in survival_rows:
        counts_by_snap_ea.setdefault(int(snap_id), {})[str(ea_hex or "")] = int(n)

    out: dict[str, dict[str, int]] = {}
    for snap_id, label in snap_rows:
        label_text = str(label or f"snapshot_{snap_id}")
        per_ea = counts_by_snap_ea.get(int(snap_id), {})
        out[label_text] = {ea: per_ea.get(ea, 0) for ea in eas_lower}
    return out


def enrich_rows_with_db(
    rows: Sequence[ByteCascadeRow],
    db_path: Path,
) -> list[ByteCascadeRow]:
    """Return new rows with ``db_var190_refs`` + ``db_source_ea_survival``
    populated from *db_path*.

    ``db_var190_refs`` remains a byte-wide cross-reference suitable for the
    informational ``%var_190.8+#k.8`` table in the rendered report.
    ``db_source_ea_survival`` is the per-source-EA survival map that drives
    the refined-status decision; it is only populated for rows whose
    :attr:`ByteCascadeRow.source_eas` is non-empty (newer tracer rows).
    """
    if not db_path.exists():
        return list(rows)
    with read_diag_db(str(db_path)) as db:
        conn = db.connection()
        from dataclasses import replace as _dc_replace

        out: list[ByteCascadeRow] = []
        for row in rows:
            refs = _count_var190_refs_per_snapshot(conn, row.byte)
            survival = _count_source_ea_survival_per_snapshot(
                conn, row.source_eas
            )
            out.append(
                _dc_replace(
                    row,
                    db_var190_refs=refs,
                    db_source_ea_survival=survival,
                )
            )
        return out


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def format_report(
    rows: Sequence[ByteCascadeRow],
    *,
    func_label: str | None = None,
) -> str:
    """Render a human-readable markdown report for *rows*."""
    if not rows:
        return (
            "## HCC byte-cascade trace\n\n"
            "(no `HCC_BYTE_CASCADE_TRACE_ROW` lines found -- did you run with"
            " `D810_HCC_BYTE_CASCADE_TRACE=1`?)\n"
        )
    title = "## HCC byte-cascade trace"
    if func_label:
        title = f"## HCC byte-cascade trace for {func_label}"

    header = (
        "| byte | block_ea | in_dag | in_corr | in_region | candidate |"
        " rejection | accepted | emitted | preserved | dropped | final |"
        " final_refined |"
    )
    sep = "|-|-|-|-|-|-|-|-|-|-|-|-|-|"
    lines: list[str] = [title, "", header, sep]
    for r in rows:
        refined = r.final_status_refined
        refined_cell = "(same)" if refined == r.final_status else refined
        lines.append(
            "| "
            + " | ".join(
                [
                    str(r.byte),
                    r.block_ea or "?",
                    "1" if r.in_dag else "0",
                    "1" if r.in_corrected_dag else "0",
                    "1" if r.in_region_table else "0",
                    "1" if r.raw_candidate else "0",
                    r.candidate_rejection or "-",
                    r.accepted_stage or "-",
                    r.emitted_mod or "-",
                    "1" if r.preserved_in_insertblock else "0",
                    r.first_dropped_stage or "-",
                    r.final_status,
                    refined_cell,
                ]
            )
            + " |"
        )

    if any(r.db_var190_refs for r in rows):
        lines.extend(
            ["", "### Cross-reference: `%var_190.8+#k.8` instruction count per snapshot", ""]
        )
        snap_labels: list[str] = []
        seen: set[str] = set()
        for r in rows:
            for lbl in r.db_var190_refs.keys():
                if lbl not in seen:
                    seen.add(lbl)
                    snap_labels.append(lbl)
        lines.append("| byte | " + " | ".join(snap_labels) + " |")
        lines.append("|-|" + "-|" * len(snap_labels))
        for r in rows:
            cells = [str(r.byte)]
            for lbl in snap_labels:
                cells.append(str(r.db_var190_refs.get(lbl, 0)))
            lines.append("| " + " | ".join(cells) + " |")

    summary = _summarize_drops(rows)
    if summary:
        lines.extend(["", "### Summary", ""] + summary)

    return "\n".join(lines) + "\n"


_STATUS_TO_NARRATIVE: dict[str, str] = {
    "region_detection_gap": (
        "in DAG but never picked up as part of any HCC raw region or"
        " InsertBlock body"
    ),
    "unmaterialized_original_block": (
        "in HCC raw region, but no InsertBlock body or redirect materialised"
        " the evidence; original block remains in the CFG but HCC made no"
        " positive claim on it"
    ),
    "redirected_away": (
        "block was rewired away by a redirect with no replacement"
    ),
    "redirect_only_finalization_loss": (
        "HCC redirected to/through the byte's block, but the redirect"
        " carries no byte-write evidence; IDA's snap17 -> snap18"
        " optimize_global DCE'd the read"
    ),
    "no_dag_evidence": (
        "byte's state node was never seen in HCC's dag / corrected_dag"
        " (likely a recon collector gap)"
    ),
    "unknown": "no final-stage observation recorded",
}


def _summarize_drops(rows: Iterable[ByteCascadeRow]) -> list[str]:
    """Bullet list of bytes that failed to survive, with narrative for the
    refined final-status taxonomy.

    Uses :attr:`ByteCascadeRow.final_status_refined`, so a
    ``preserved_redirect`` row that the snap17 -> snap18 cross-check
    reclassifies into ``redirect_only_finalization_loss`` appears in the
    summary as a real loss rather than a false success.
    """
    out: list[str] = []
    for r in rows:
        status = r.final_status_refined
        if status.startswith("preserved"):
            continue
        loc = (
            r.first_dropped_stage if r.first_dropped_stage and r.first_dropped_stage != "-"
            else "no_stage_recorded"
        )
        narrative = _STATUS_TO_NARRATIVE.get(status, status)
        bullet = (
            f"- byte {r.byte}: `{status}` -- {narrative}; first"
            f" dropped at `{loc}`"
        )
        if r.candidate_rejection and r.candidate_rejection not in ("-", ""):
            bullet += f" (candidate rejection: {r.candidate_rejection})"
        out.append(bullet)
    return out


def format_report_json(rows: Sequence[ByteCascadeRow]) -> str:
    return json.dumps([r.to_dict() for r in rows], indent=2)
