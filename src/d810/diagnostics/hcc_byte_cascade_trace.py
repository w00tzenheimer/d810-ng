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

    @property
    def final_status_refined(self) -> str:
        """Refine ``preserved_redirect`` using the snap18 var_190 cross-ref.

        Returns the original :attr:`final_status` unchanged for all other
        statuses, and for ``preserved_redirect`` when no DB enrichment is
        available (we cannot decide). Otherwise:

        - ``preserved_redirect_with_evidence`` when at least one snapshot
          whose label contains ``post_d810`` or ``MMAT_LVARS`` has a
          positive var_190 reference count -- the byte's m_stx read
          survived IDA's ``optimize_global`` DCE.
        - ``redirect_only_finalization_loss`` when *every* such snapshot
          shows zero references -- the redirect routes flow to/through the
          byte's block but doesn't materialise the byte-write evidence,
          and IDA finalisation drops it.
        """
        if self.final_status != "preserved_redirect":
            return self.final_status
        if not self.db_var190_refs:
            return self.final_status
        post_d810_counts = [
            count
            for label, count in self.db_var190_refs.items()
            if "post_d810" in label or "MMAT_LVARS" in label
        ]
        if not post_d810_counts:
            return self.final_status
        if any(count > 0 for count in post_d810_counts):
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
        # Byte 0 has no offset form; match the bare stack var.
        like = "%var_190.8%"
        # Subtract +#K. for K >= 1 by issuing a separate query? Simpler:
        # return 0 for byte 0 -- not informative.
        return {}
    pattern = f"%var_190.8+#{byte_index}.8%"
    try:
        cursor = conn.execute(
            """
            SELECT s.id, s.label, COUNT(*) AS n
            FROM instructions i
            JOIN snapshots s ON s.id = i.snapshot_id
            WHERE i.dstr LIKE ?
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


def enrich_rows_with_db(
    rows: Sequence[ByteCascadeRow],
    db_path: Path,
) -> list[ByteCascadeRow]:
    """Return new rows with ``db_var190_refs`` populated from *db_path*."""
    if not db_path.exists():
        return list(rows)
    conn = sqlite3.connect(str(db_path))
    try:
        from dataclasses import replace as _dc_replace

        out: list[ByteCascadeRow] = []
        for row in rows:
            refs = _count_var190_refs_per_snapshot(conn, row.byte)
            out.append(_dc_replace(row, db_var190_refs=refs))
        return out
    finally:
        conn.close()


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
