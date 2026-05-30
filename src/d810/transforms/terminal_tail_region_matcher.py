"""Terminal-tail region matcher (read-only).

Maps D810 snapshots into REF-like terminal-tail roles and identifies
where byte_emit[k] candidates disappear across the maturity/phase
timeline. Pure-algorithm consumer of the existing
``TerminalByteEmitterFact`` stream — no IDA dependency, no CFG edits,
no behavior changes.

Roles mirror the REF source's terminal byte-tail structure (see
``tools/equivalence/ref.c`` lines 466-549):

- ``TAIL_INIT`` — entry to the terminal-tail region (counter set up).
- ``BYTE_EMIT`` — one of 7 byte-emit blocks; ``byte_index`` ∈ {0..6}.
- ``EARLY_RETURN_GUARD`` — ``if (v53 == k) return ...`` guard before
  the next ``BYTE_EMIT``.
- ``CLEANUP_ZERO_STORE16`` — one of the 8 ``STORE_OWORD_N(...,
  &D810_ZERO_OWORD)`` clears.
- ``REAL_LOOP_BLOCK`` — classified as REAL_LOOP by the back-edge
  classifier (head-byte stride / chunk-emit / block-emit).
- ``RESIDUAL_SCC_BACKEDGE`` — classified as SPURIOUS by the back-edge
  classifier.
- ``UNKNOWN`` — none of the above match.

The matcher's primary deliverable is a **byte_emit[k] timeline**:
which of the 7 byte emitters are present at each snapshot, when each
disappears, and (where attributable) what caused the loss.

Acceptance contract for ticket uee-32r3 Piece N:

- We can answer "are byte_emit[2..5] present at the last D810-controlled
  point before collapse?" by reading the ``current_glbopt1_post_d810``
  field.
- We can answer "where do they disappear?" by reading the
  ``first_losses`` tuple.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable

logger = getLogger(__name__)


class TailRegionRole(str, Enum):
    """Roles a block can play in the terminal-tail region."""

    TAIL_INIT = "TAIL_INIT"
    BYTE_EMIT = "BYTE_EMIT"
    EARLY_RETURN_GUARD = "EARLY_RETURN_GUARD"
    CLEANUP_ZERO_STORE16 = "CLEANUP_ZERO_STORE16"
    REAL_LOOP_BLOCK = "REAL_LOOP_BLOCK"
    RESIDUAL_SCC_BACKEDGE = "RESIDUAL_SCC_BACKEDGE"
    UNKNOWN = "UNKNOWN"


class ByteEmitSourceForm(str, Enum):
    """How the source byte is read in a ``BYTE_EMIT`` block."""

    INDEXED = "indexed"        # v52[k] — explicit constant index
    BASE_ONLY = "base_only"    # *v52  (only k==0)
    FOLDED = "folded"          # k folded into a larger MBA expression
    ABSENT = "absent"          # no byte-source operand present


@dataclass(frozen=True, slots=True)
class ByteEmitObservation:
    """One byte_emit[k] candidate captured at a single snapshot."""

    snapshot_id: int
    maturity: str
    phase: str
    label: str
    block_serial: int
    byte_index: int
    corridor_role: str
    counter_carrier: str | None
    source_form: ByteEmitSourceForm
    destination_present: bool
    counter_update_present: bool
    block_ea_hex: str | None = None


@dataclass(frozen=True, slots=True)
class SnapshotMeta:
    """Identifying info for one diag snapshot."""

    snapshot_id: int
    maturity: str
    phase: str
    label: str

    def key(self) -> tuple[str, str]:
        return (self.maturity, self.phase)


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """Per-snapshot view of which byte_emit[k] are present."""

    snapshot: SnapshotMeta
    byte_emits: dict[int, ByteEmitObservation] = field(default_factory=dict)

    def present_indices(self) -> tuple[int, ...]:
        return tuple(sorted(self.byte_emits))

    def missing_indices(self, max_index: int = 6) -> tuple[int, ...]:
        return tuple(
            k for k in range(max_index + 1) if k not in self.byte_emits
        )


@dataclass(frozen=True, slots=True)
class FirstLossEntry:
    """Earliest snapshot transition where ``byte_index`` disappears."""

    byte_index: int
    last_present_snapshot: SnapshotMeta | None
    first_absent_snapshot: SnapshotMeta | None
    inferred_cause: str

    @property
    def is_missing_throughout(self) -> bool:
        return self.last_present_snapshot is None

    @property
    def survives_pipeline(self) -> bool:
        return self.first_absent_snapshot is None


@dataclass(frozen=True, slots=True)
class TerminalTailReport:
    """Full read-only diagnostic report produced by the matcher."""

    timeline: tuple[TimelineEntry, ...]
    first_losses: tuple[FirstLossEntry, ...]
    last_d810_controlled_entry: TimelineEntry | None
    glbopt1_post_d810_entry: TimelineEntry | None


# Ordering used to walk the maturity/phase timeline.
_TIMELINE_ORDER: dict[tuple[str, str], int] = {
    ("MMAT_LOCOPT", "pre_d810"): 0,
    ("MMAT_LOCOPT", "post_d810"): 1,
    ("MMAT_CALLS", "pre_d810"): 2,
    ("MMAT_CALLS", "post_d810"): 3,
    ("MMAT_GLBOPT1", "pre_d810"): 4,
    ("MMAT_GLBOPT1", "post_apply"): 5,
    ("MMAT_GLBOPT1", "post_gut_wire"): 6,
    ("MMAT_GLBOPT1", "post_pipeline"): 7,
    ("MMAT_GLBOPT1", "post_d810"): 8,
    ("MMAT_GLBOPT2", "pre_d810"): 9,
    ("MMAT_GLBOPT2", "post_apply"): 10,
    ("MMAT_GLBOPT2", "post_d810"): 11,
    ("MMAT_GLBOPT3", "pre_d810"): 12,
    ("MMAT_GLBOPT3", "post_d810"): 13,
    ("MMAT_LVARS", "pre_d810"): 14,
    ("MMAT_LVARS", "post_d810"): 15,
}


def _timeline_rank(meta: SnapshotMeta) -> tuple[int, int]:
    """Total ordering key for snapshot timeline."""
    base = _TIMELINE_ORDER.get(meta.key(), 99)
    return (base, int(meta.snapshot_id))


def _classify_source_form(
    expression: str | None, byte_index: int
) -> ByteEmitSourceForm:
    """Heuristically classify how the source byte is read.

    Pure string analysis — caller may pass ``None`` when the fact lacks
    a source expression.
    """
    if not expression:
        return ByteEmitSourceForm.ABSENT
    text = expression.lower()
    # Indexed read: v52[k] in the source DSL prints as
    # ``[ds.2:%var_X.8].8 + #k.8`` or ``%var_X+#k.8`` style.
    if f"+#{byte_index:x}." in text or f"+#{byte_index}." in text:
        return ByteEmitSourceForm.INDEXED
    # MBA-folded: shifts and constants composed with the carrier.
    if any(op in text for op in ("<<l", "*", "&", "|", "bnot", "xor", "^")):
        return ByteEmitSourceForm.FOLDED
    return ByteEmitSourceForm.BASE_ONLY


def aggregate_byte_emit_timeline(
    observations: Iterable[ByteEmitObservation],
) -> TerminalTailReport:
    """Aggregate raw observations into a timeline + first-loss report.

    Inputs may include MULTIPLE observations per (snapshot, byte_index)
    pair (e.g., when a maturity has multiple replays). The aggregator
    keeps the FIRST observation seen for each (snapshot_id, byte_index)
    so the report stays deterministic across re-runs.
    """
    by_snapshot: dict[int, TimelineEntry] = {}
    snapshot_meta: dict[int, SnapshotMeta] = {}

    for obs in observations:
        meta = SnapshotMeta(
            snapshot_id=obs.snapshot_id,
            maturity=obs.maturity,
            phase=obs.phase,
            label=obs.label,
        )
        snapshot_meta[obs.snapshot_id] = meta
        entry = by_snapshot.get(obs.snapshot_id)
        if entry is None:
            entry = TimelineEntry(snapshot=meta, byte_emits={})
            by_snapshot[obs.snapshot_id] = entry
        # First-write-wins so deterministic across collector replays.
        if obs.byte_index not in entry.byte_emits:
            entry.byte_emits[obs.byte_index] = obs

    timeline = tuple(
        sorted(
            by_snapshot.values(),
            key=lambda e: _timeline_rank(e.snapshot),
        )
    )

    # Compute first-loss for each byte_index.
    first_losses: list[FirstLossEntry] = []
    for k in range(7):
        last_present: SnapshotMeta | None = None
        first_absent: SnapshotMeta | None = None
        for entry in timeline:
            if k in entry.byte_emits:
                last_present = entry.snapshot
                first_absent = None  # re-appearance resets
            elif last_present is not None and first_absent is None:
                first_absent = entry.snapshot
        if last_present is None:
            cause = "missing_throughout"
        elif first_absent is None:
            cause = "survives_pipeline"
        else:
            cause = _infer_cause(last_present, first_absent)
        first_losses.append(
            FirstLossEntry(
                byte_index=k,
                last_present_snapshot=last_present,
                first_absent_snapshot=first_absent,
                inferred_cause=cause,
            )
        )

    last_d810: TimelineEntry | None = None
    glbopt1_post: TimelineEntry | None = None
    for entry in timeline:
        if entry.snapshot.phase == "post_d810":
            last_d810 = entry
        if entry.snapshot.maturity == "MMAT_GLBOPT1" and entry.snapshot.phase == "post_d810":
            glbopt1_post = entry

    return TerminalTailReport(
        timeline=timeline,
        first_losses=tuple(first_losses),
        last_d810_controlled_entry=last_d810,
        glbopt1_post_d810_entry=glbopt1_post,
    )


def _infer_cause(
    last_present: SnapshotMeta, first_absent: SnapshotMeta,
) -> str:
    """Heuristic cause classification from the snapshot pair.

    Without per-mod attribution this is best-effort. The bucketing
    distinguishes D810-controlled losses (within a single maturity,
    pre→post or intermediate apply phases) from IDA-native maturity
    folds (between maturities, pre_d810 → pre_d810).
    """
    if last_present.maturity == first_absent.maturity:
        return f"d810_apply_within_{last_present.maturity}"
    if last_present.phase == "post_d810" and first_absent.phase == "pre_d810":
        return f"ida_native_fold_{last_present.maturity}_to_{first_absent.maturity}"
    return f"unattributed_{last_present.maturity}/{last_present.phase}_to_{first_absent.maturity}/{first_absent.phase}"


def format_report(report: TerminalTailReport) -> str:
    """Render a markdown-style report of the timeline + first-loss table."""
    lines: list[str] = []
    lines.append("## Byte-emit timeline\n")
    lines.append("| snapshot | maturity / phase | label | present indices |")
    lines.append("|-|-|-|-|")
    for e in report.timeline:
        idx = ",".join(str(k) for k in e.present_indices()) or "(none)"
        lines.append(
            f"| {e.snapshot.snapshot_id} | "
            f"{e.snapshot.maturity}/{e.snapshot.phase} | "
            f"{e.snapshot.label} | {idx} |"
        )

    lines.append("\n## First-loss report\n")
    lines.append("| byte_index | last present (snap/maturity) | first absent | inferred cause |")
    lines.append("|-|-|-|-|")
    for fl in report.first_losses:
        lp = (
            f"snap{fl.last_present_snapshot.snapshot_id}/"
            f"{fl.last_present_snapshot.maturity}/{fl.last_present_snapshot.phase}"
            if fl.last_present_snapshot
            else "—"
        )
        fa = (
            f"snap{fl.first_absent_snapshot.snapshot_id}/"
            f"{fl.first_absent_snapshot.maturity}/{fl.first_absent_snapshot.phase}"
            if fl.first_absent_snapshot
            else "(survives)"
        )
        lines.append(f"| {fl.byte_index} | {lp} | {fa} | {fl.inferred_cause} |")

    if report.glbopt1_post_d810_entry is not None:
        e = report.glbopt1_post_d810_entry
        lines.append(
            "\n## GLBOPT1 post-D810 (last D810-controlled snapshot)\n"
        )
        lines.append(f"- snapshot: {e.snapshot.snapshot_id} ({e.snapshot.label})")
        lines.append(f"- present byte_emits: {list(e.present_indices())}")
        lines.append(f"- missing byte_emits: {list(e.missing_indices())}")

    return "\n".join(lines)


__all__ = [
    "ByteEmitObservation",
    "ByteEmitSourceForm",
    "FirstLossEntry",
    "SnapshotMeta",
    "TailRegionRole",
    "TerminalTailReport",
    "TimelineEntry",
    "_classify_source_form",
    "aggregate_byte_emit_timeline",
    "format_report",
]
