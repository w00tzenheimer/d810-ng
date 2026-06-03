"""Read-only HCC Compose Evidence Explainer.

For every byte the byte-cascade trace marks
``final_refined=unmaterialized_original_block`` -- meaning the byte's
block IS in HCC's raw region table but no HCC-emitted modification
materialises the byte's source-EA evidence -- this module attributes
the materialization gap to a single named composition-failure bucket
plus the responsible composition step.

Inputs (all read-only):

- ``HCC_BYTE_CASCADE_TRACE_ROW`` lines from a ``d810.log`` (same source
  as the byte-cascade trace), parsed via
  :mod:`d810.diagnostics.hcc_byte_cascade_trace`. Authoritative for
  ``preserved_in_insertblock`` per byte (no per-instruction body data
  exists in the diag DB; the trace's runtime predicate is the proof).
- ``modifications`` table from the diag SQLite (HCC's emitted mods at
  the ``handler_chain_composer_state_write_reconstruction_post_apply``
  snapshot).
- ``REGION_LOWERING_CANDIDATE`` log lines (optional enrichment), parsed
  for the byte's region membership and compose eligibility.

Bucket priority (first match wins):

1. ``no_mod_touches_block`` -- no row in ``modifications`` references
   the byte's block as ``source_block`` / ``target_block`` /
   ``old_target``. The byte's region was admitted but composition
   emitted mods for OTHER region members; the byte's block was left as
   a stranded interior. First responsible step: ``compose_region``.
2. ``redirect_target_only_no_evidence`` -- block appears only as the
   ``target_block`` of redirects (control-flow only); no InsertBlock
   body holds the byte source EA. First responsible step:
   ``compose_region.body_selection``.
3. ``insertblock_succ_no_byte_evidence`` -- block is the ``target_block``
   of an InsertBlock but trace's ``preserved_in_insertblock=0``; the
   InsertBlock body skipped the byte's source EA. First responsible
   step: ``compose_region.body_filter``.
4. ``redirected_away_only`` -- block appears only as ``source_block``
   of redirects (rewired away) with no InsertBlock body taking the
   evidence. First responsible step: ``compose_region.exit_wiring``.
5. ``insertblock_with_evidence_inconsistency`` -- modifications show an
   InsertBlock involving this block AND the trace claims
   ``preserved_in_insertblock=0``. Indicates a tracer/predicate
   inconsistency worth investigating; never a behavior-change cue on
   its own.
6. ``unclassified`` -- catch-all for shapes none of the above match.

Pure module; no ``ida_hexrays`` import; fully unit-testable.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from d810._vendor.peewee import fn
from d810.core.diag import read_diag_db
from d810.core.diag.models import Modification
from d810.core.typing import Any, Sequence
from d810.diagnostics.hcc_byte_cascade_trace import (
    ByteCascadeRow,
    parse_trace_log,
)


# ---------------------------------------------------------------------------
# Bucket attribution constants
# ---------------------------------------------------------------------------

_REDIRECT_KINDS: frozenset[str] = frozenset({
    "RedirectGoto",
    "RedirectBranch",
    "ConvertToGoto",
    "EdgeRedirectViaPredSplit",
    "CreateConditionalRedirect",
})
_INSERTBLOCK_KINDS: frozenset[str] = frozenset({
    "InsertBlock",
    "DuplicateBlock",
})

# Bucket -> first responsible composition step.
_BUCKET_TO_STEP: dict[str, str] = {
    "no_mod_touches_block": "compose_region",
    "redirect_target_only_no_evidence": "compose_region.body_selection",
    "insertblock_succ_no_byte_evidence": "compose_region.body_filter",
    "redirected_away_only": "compose_region.exit_wiring",
    "insertblock_with_evidence_inconsistency": "compose_region.body_filter",
    "unclassified": "unknown",
}

_BUCKET_TO_NARRATIVE: dict[str, str] = {
    "no_mod_touches_block": (
        "byte's block is in HCC's raw region table but NO emitted"
        " modification references it as source/target/old_target;"
        " composition built mods for other region members and left this"
        " block as a stranded interior"
    ),
    "redirect_target_only_no_evidence": (
        "byte's block appears only as the target of one or more"
        " redirects (control-flow only); no InsertBlock body composes"
        " the byte's source EA"
    ),
    "insertblock_succ_no_byte_evidence": (
        "byte's block is the InsertBlock target (succ) but the"
        " InsertBlock body does not include the byte's source EA;"
        " the body filter dropped it"
    ),
    "redirected_away_only": (
        "byte's block was rewired away (appears only as source_block"
        " of redirects) with no InsertBlock body taking the evidence"
    ),
    "insertblock_with_evidence_inconsistency": (
        "modifications show an InsertBlock involving this block AND the"
        " byte-cascade trace says preserved_in_insertblock=0; tracer"
        " predicate inconsistency"
    ),
    "unclassified": (
        "modifications shape did not match any known compose-failure"
        " pattern; investigate manually"
    ),
}


@dataclass(frozen=True, slots=True)
class ModRow:
    """One modification row touching the byte's block."""

    mod_index: int
    mod_type: str
    source_block: int | None
    target_block: int | None
    old_target: int | None
    status: str
    reason: str | None
    role: str  # 'source_block' | 'target_block' | 'old_target'


@dataclass(frozen=True, slots=True)
class RegionLoweringHit:
    """REGION_LOWERING_CANDIDATE log entry that mentions the byte's block."""

    head_state_hex: str
    head_entry: int | None
    tail_state_hex: str | None
    eligibility: str
    reason: str
    splice_source_block: int | None
    exit_target: str
    role: str  # how the byte's block appears in this candidate


@dataclass(frozen=True, slots=True)
class ComposeEvidenceExplanation:
    """Per-byte compose-evidence verdict."""

    byte: int
    block_ea: str
    block_serial: int | None
    snapshot_id: int | None
    bucket: str
    first_responsible_step: str
    narrative: str
    preserved_in_insertblock: bool
    mod_rows: tuple[ModRow, ...]
    region_hits: tuple[RegionLoweringHit, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte": self.byte,
            "block_ea": self.block_ea,
            "block_serial": self.block_serial,
            "snapshot_id": self.snapshot_id,
            "bucket": self.bucket,
            "first_responsible_step": self.first_responsible_step,
            "narrative": self.narrative,
            "preserved_in_insertblock": self.preserved_in_insertblock,
            "mod_rows": [
                {
                    "mod_index": m.mod_index,
                    "mod_type": m.mod_type,
                    "source_block": m.source_block,
                    "target_block": m.target_block,
                    "old_target": m.old_target,
                    "status": m.status,
                    "reason": m.reason,
                    "role": m.role,
                }
                for m in self.mod_rows
            ],
            "region_hits": [
                {
                    "head_state_hex": r.head_state_hex,
                    "head_entry": r.head_entry,
                    "tail_state_hex": r.tail_state_hex,
                    "eligibility": r.eligibility,
                    "reason": r.reason,
                    "splice_source_block": r.splice_source_block,
                    "exit_target": r.exit_target,
                    "role": r.role,
                }
                for r in self.region_hits
            ],
        }


# ---------------------------------------------------------------------------
# DB joins
# ---------------------------------------------------------------------------


def _latest_modifications_snapshot_id(conn: sqlite3.Connection) -> int | None:
    """Return the snapshot id of the latest modifications row, or ``None``."""
    try:
        value = Modification.select(
            fn.MAX(Modification.snapshot)
        ).scalar()
    except sqlite3.OperationalError:
        return None
    if value is None:
        return None
    return int(value)


def _mods_touching_block(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serial: int,
) -> list[ModRow]:
    """Return all modifications that reference *block_serial* as
    source/target/old_target. Annotates each row with the role.
    """
    try:
        rows = (
            Modification.select(
                Modification.mod_index,
                Modification.mod_type,
                Modification.source_block,
                Modification.target_block,
                Modification.old_target,
                Modification.status,
                Modification.reason,
            )
            .where(
                (Modification.snapshot == snapshot_id)
                & (
                    (Modification.source_block == block_serial)
                    | (Modification.target_block == block_serial)
                    | (Modification.old_target == block_serial)
                )
            )
            .order_by(Modification.mod_index)
            .tuples()
        )
    except sqlite3.OperationalError:
        return []
    out: list[ModRow] = []
    for mod_index, mod_type, src, tgt, old_t, status, reason in rows:
        if src is not None and int(src) == block_serial:
            role = "source_block"
        elif tgt is not None and int(tgt) == block_serial:
            role = "target_block"
        elif old_t is not None and int(old_t) == block_serial:
            role = "old_target"
        else:
            role = "unknown"
        out.append(ModRow(
            mod_index=int(mod_index),
            mod_type=str(mod_type),
            source_block=int(src) if src is not None else None,
            target_block=int(tgt) if tgt is not None else None,
            old_target=int(old_t) if old_t is not None else None,
            status=str(status),
            reason=str(reason) if reason else None,
            role=role,
        ))
    return out


# ---------------------------------------------------------------------------
# Log parsing (REGION_LOWERING_CANDIDATE)
# ---------------------------------------------------------------------------


_REGION_LOWERING_RE = re.compile(
    r"REGION_LOWERING_CANDIDATE\s*\n"
    r"\s*phase=(?P<phase>\S+)\s*\n"
    r"\s*head_state=(?P<head_state>\S+)\s+head_entry=blk\[(?P<head_entry>\d+)\]\s*\n"
    r"\s*tail_state=(?P<tail_state>\S+)\s+exit_target=(?P<exit_target>\S+)\s*\n"
    r"\s*old_physical_pred=(?P<old_pred>\S+)\s*\n"
    r"\s*transition_sources=(?P<transition_sources>.+?)\s*\n"
    r"\s*nontransition_sources=(?P<nontransition_sources>.+?)\s*\n"
    r"\s*splice_source_block=(?P<splice_source>\S+)\s*\n"
    r"\s*splice_old_target=(?P<splice_old>\S+)\s*\n"
    r"\s*proposed_splice=(?P<proposed>.+?)\s*\n"
    r"\s*eligibility=(?P<eligibility>\S+)\s*\n"
    r"\s*reason=(?P<reason>.+?)\s*\n",
    re.MULTILINE,
)
_BLK_RE = re.compile(r"blk\[(\d+)\]")


def _parse_region_lowering_log(log_text: str) -> list[dict[str, Any]]:
    """Parse all ``REGION_LOWERING_CANDIDATE`` log entries into dicts."""
    out: list[dict[str, Any]] = []
    for match in _REGION_LOWERING_RE.finditer(log_text):
        groups = match.groupdict()
        out.append({
            "head_state": groups.get("head_state", "?"),
            "head_entry": _safe_int(groups.get("head_entry")),
            "tail_state": groups.get("tail_state", "?"),
            "exit_target": groups.get("exit_target", "?"),
            "transition_sources": _extract_blk_serials(
                groups.get("transition_sources", "")
            ),
            "nontransition_sources": _extract_blk_serials(
                groups.get("nontransition_sources", "")
            ),
            "splice_source_block": _extract_first_blk(
                groups.get("splice_source", "")
            ),
            "exit_target_blocks": _extract_blk_serials(
                groups.get("exit_target", "")
            ),
            "eligibility": groups.get("eligibility", "?"),
            "reason": _strip_quotes(groups.get("reason", "")),
        })
    return out


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_blk_serials(text: str) -> tuple[int, ...]:
    return tuple(int(m.group(1)) for m in _BLK_RE.finditer(text))


def _extract_first_blk(text: str) -> int | None:
    match = _BLK_RE.search(text)
    return int(match.group(1)) if match else None


def _strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    return text


def _region_hits_for_block(
    region_entries: Sequence[dict[str, Any]],
    block_serial: int,
) -> list[RegionLoweringHit]:
    """For each region candidate that mentions *block_serial*, return a
    typed hit describing how the block appears in that candidate.
    """
    hits: list[RegionLoweringHit] = []
    for entry in region_entries:
        roles: list[str] = []
        if entry["head_entry"] == block_serial:
            roles.append("head_entry")
        if entry["splice_source_block"] == block_serial:
            roles.append("splice_source_block")
        if block_serial in entry["transition_sources"]:
            roles.append("transition_source")
        if block_serial in entry["nontransition_sources"]:
            roles.append("nontransition_source")
        if block_serial in entry["exit_target_blocks"]:
            roles.append("exit_target")
        if not roles:
            continue
        hits.append(RegionLoweringHit(
            head_state_hex=str(entry["head_state"]),
            head_entry=entry["head_entry"],
            tail_state_hex=entry["tail_state"],
            eligibility=str(entry["eligibility"]),
            reason=str(entry["reason"]),
            splice_source_block=entry["splice_source_block"],
            exit_target=str(entry["exit_target"]),
            role=",".join(roles),
        ))
    return hits


# ---------------------------------------------------------------------------
# Classifier (pure)
# ---------------------------------------------------------------------------


def classify(
    row: ByteCascadeRow,
    mod_rows: Sequence[ModRow],
    region_hits: Sequence[RegionLoweringHit],
    snapshot_id: int | None,
) -> ComposeEvidenceExplanation:
    """Apply the bucket priority and return a verdict."""
    if not mod_rows:
        bucket = "no_mod_touches_block"
    elif row.preserved_in_insertblock:
        # InsertBlock-style mods reference the block AND trace says the
        # body carries the EA -> would normally NOT show as
        # unmaterialized. Flag the inconsistency.
        bucket = "insertblock_with_evidence_inconsistency"
    else:
        roles = {m.role for m in mod_rows}
        kinds = {m.mod_type for m in mod_rows}
        only_redirects = kinds.issubset(_REDIRECT_KINDS)
        has_insertblock = bool(kinds & _INSERTBLOCK_KINDS)
        if has_insertblock:
            # InsertBlock touches the block but body filter dropped the
            # byte's source EA.
            bucket = "insertblock_succ_no_byte_evidence"
        elif only_redirects and roles == {"source_block"}:
            # Block appears only as redirect source -> rewired away.
            bucket = "redirected_away_only"
        elif only_redirects and {"target_block", "old_target"} & roles:
            # Block appears as redirect target / old_target -> control
            # flow only, no body claim.
            bucket = "redirect_target_only_no_evidence"
        else:
            bucket = "unclassified"
    return ComposeEvidenceExplanation(
        byte=row.byte,
        block_ea=row.block_ea or "?",
        block_serial=row.block_serial,
        snapshot_id=snapshot_id,
        bucket=bucket,
        first_responsible_step=_BUCKET_TO_STEP.get(bucket, "unknown"),
        narrative=_BUCKET_TO_NARRATIVE.get(bucket, bucket),
        preserved_in_insertblock=row.preserved_in_insertblock,
        mod_rows=tuple(mod_rows),
        region_hits=tuple(region_hits),
    )


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------


def select_target_rows(
    rows: Sequence[ByteCascadeRow],
    explicit_bytes: Sequence[int] | None,
) -> list[ByteCascadeRow]:
    """Default scope: every byte whose ``final_refined`` (or ``final_status``)
    equals ``unmaterialized_original_block``.
    """
    if explicit_bytes:
        wanted = {int(b) for b in explicit_bytes}
        return [r for r in rows if r.byte in wanted]
    return [
        r for r in rows
        if r.final_status_refined == "unmaterialized_original_block"
        or r.final_status == "unmaterialized_original_block"
    ]


def explain_byte(
    conn: sqlite3.Connection,
    row: ByteCascadeRow,
    region_entries: Sequence[dict[str, Any]],
) -> ComposeEvidenceExplanation:
    snap_id = _latest_modifications_snapshot_id(conn)
    if snap_id is None or row.block_serial is None:
        return ComposeEvidenceExplanation(
            byte=row.byte,
            block_ea=row.block_ea or "?",
            block_serial=row.block_serial,
            snapshot_id=snap_id,
            bucket="no_mod_touches_block",
            first_responsible_step=_BUCKET_TO_STEP["no_mod_touches_block"],
            narrative=_BUCKET_TO_NARRATIVE["no_mod_touches_block"],
            preserved_in_insertblock=row.preserved_in_insertblock,
            mod_rows=(),
            region_hits=(),
        )
    mods = _mods_touching_block(conn, snap_id, int(row.block_serial))
    region_hits = _region_hits_for_block(
        region_entries, int(row.block_serial),
    )
    return classify(row, mods, region_hits, snap_id)


def explain(
    rows: Sequence[ByteCascadeRow],
    db_path: Path,
    log_text: str,
    *,
    bytes_filter: Sequence[int] | None = None,
) -> list[ComposeEvidenceExplanation]:
    targets = select_target_rows(rows, bytes_filter)
    if not targets:
        return []
    region_entries = _parse_region_lowering_log(log_text)
    if not db_path.exists():
        # Without the DB we can still classify against trace-only signals.
        return [
            classify(
                r,
                mod_rows=(),
                region_hits=tuple(
                    _region_hits_for_block(
                        region_entries,
                        r.block_serial if r.block_serial is not None else -1,
                    )
                ),
                snapshot_id=None,
            )
            for r in targets
        ]
    with read_diag_db(str(db_path)) as db:
        conn = db.connection()
        return [explain_byte(conn, r, region_entries) for r in targets]


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def format_report(
    explanations: Sequence[ComposeEvidenceExplanation],
    *,
    func_label: str | None = None,
) -> str:
    title = "## HCC Compose Evidence Explainer"
    if func_label:
        title = f"## HCC Compose Evidence Explainer for {func_label}"
    if not explanations:
        return (
            f"{title}\n\n"
            "(no `unmaterialized_original_block` rows in the trace -- either"
            " the byte-cascade trace was not produced, or every byte was"
            " materialised by a positive HCC modification.)\n"
        )
    lines: list[str] = [
        title,
        "",
        f"Modifications source: snapshot"
        f" {explanations[0].snapshot_id} (HCC post-apply).",
        "",
        "| byte | block_ea | bucket | first_step | preserved_in_insertblock |"
        " #mods | #region_hits |",
        "|-|-|-|-|-|-|-|",
    ]
    for ex in explanations:
        lines.append(
            "| "
            + " | ".join([
                str(ex.byte),
                ex.block_ea,
                ex.bucket,
                ex.first_responsible_step,
                "1" if ex.preserved_in_insertblock else "0",
                str(len(ex.mod_rows)),
                str(len(ex.region_hits)),
            ])
            + " |"
        )
    lines.extend(["", "### Verdict per byte", ""])
    for ex in explanations:
        lines.append(
            f"- byte {ex.byte} (`{ex.block_ea}`, blk[{ex.block_serial}]):"
            f" `{ex.bucket}` -- {ex.narrative}; first responsible step:"
            f" `{ex.first_responsible_step}`"
        )
        if ex.mod_rows:
            lines.append("  - modifications touching this block:")
            for m in ex.mod_rows:
                lines.append(
                    f"    - mod[{m.mod_index}] {m.mod_type} role={m.role}"
                    f" src={m.source_block} tgt={m.target_block}"
                    f" old_target={m.old_target} status={m.status}"
                )
        else:
            lines.append("  - no modifications row references this block")
        if ex.region_hits:
            lines.append("  - REGION_LOWERING_CANDIDATE membership:")
            for h in ex.region_hits:
                lines.append(
                    f"    - head_state={h.head_state_hex}"
                    f" head_entry=blk[{h.head_entry}]"
                    f" eligibility={h.eligibility}"
                    f" splice_src=blk[{h.splice_source_block}]"
                    f" role={h.role} reason={h.reason!r}"
                )
        else:
            lines.append(
                "  - no REGION_LOWERING_CANDIDATE log entries mention this"
                " block (either the log lacked PRE_COMPOSE entries or the"
                " parser didn't match)"
            )
    return "\n".join(lines) + "\n"


def format_report_json(
    explanations: Sequence[ComposeEvidenceExplanation],
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
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    rows = parse_trace_log(log_text)
    explanations = explain(rows, db_path, log_text, bytes_filter=bytes_filter)
    if as_json:
        return format_report_json(explanations) + "\n"
    return format_report(explanations, func_label=func_label)
