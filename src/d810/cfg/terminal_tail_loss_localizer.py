"""Terminal-tail loss localizer (read-only).

Companion to ``terminal_tail_region_matcher``. Where the matcher uses
``TerminalByteEmitterFact`` rows to report byte_emit[k] presence at
each maturity boundary (pre_d810 / post_d810), the localizer walks
**intermediate** snapshots — the per-strategy ``post_apply`` /
``post_pipeline`` / ``post_bundle_stabilize`` snapshots captured during
D810's GLBOPT1 work — and tracks each byte_emit block FORWARD by its
``start_ea_hex``. The output identifies the precise snapshot transition
where each byte's block disappears, distinguishing:

- **D810-strategy-caused loss** — block absent during D810's pipeline
  (snap 8..17). Look for matching modifications in the ``modifications``
  table to attribute the responsible strategy.
- **IDA-native maturity fold** — block present at the LAST D810
  snapshot (post_bundle_stabilize) but absent at the post_d810
  snapshot. This is IDA's ``mba_t.optimize_global()`` /
  finalization DCE running between D810 finishing the maturity and
  the post_d810 capture.

The localizer is pure-algorithm and namespace-agnostic. Inputs are
plain dictionaries keyed by snapshot_id; the CLI tool builds them
from the diag DB.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Iterable, Mapping

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SnapshotBlockView:
    """Per-snapshot view of one block (or its absence).

    ``fact_detected`` is a separate dimension from ``present``:
    - ``present=True, fact_detected=True``  — block exists AND collector
      sees a byte_emit there (full preservation).
    - ``present=True, fact_detected=False`` — block survives but the
      byte_emit pattern no longer matches (D810 modifications changed
      the block's instruction sequence; collector limitation may also
      apply).
    - ``present=False`` — block is gone (DCE / fold / merge).
    """

    snapshot_id: int
    snapshot_label: str
    snapshot_phase: str
    block_serial: int | None
    npred: int | None
    nsucc: int | None
    insn_count: int | None
    fact_detected: bool = False

    @property
    def present(self) -> bool:
        return self.block_serial is not None


@dataclass(frozen=True, slots=True)
class ByteEmitInitialState:
    """A byte_emit candidate captured at the initial (pre-D810) snapshot."""

    byte_index: int
    snapshot_id: int
    block_serial: int
    start_ea_hex: str


@dataclass(frozen=True, slots=True)
class ByteEmitSurvival:
    """Cross-snapshot timeline for one byte_emit candidate.

    ``timeline`` is the per-snapshot block view in chronological order.
    ``first_loss_snapshot`` and ``last_present_snapshot`` summarize
    where the block disappears.
    """

    byte_index: int
    initial: ByteEmitInitialState
    timeline: tuple[SnapshotBlockView, ...]

    @property
    def last_present(self) -> SnapshotBlockView | None:
        last = None
        for entry in self.timeline:
            if entry.present:
                last = entry
        return last

    @property
    def first_loss(self) -> SnapshotBlockView | None:
        seen_present = False
        for entry in self.timeline:
            if entry.present:
                seen_present = True
            elif seen_present:
                return entry
        return None

    @property
    def survives_pipeline(self) -> bool:
        return self.first_loss is None

    @property
    def fact_first_loss(self) -> SnapshotBlockView | None:
        """Last snapshot in the timeline where the BLOCK is present but
        the byte_emit FACT does not fire — only meaningful when
        compared against an earlier snapshot where the fact DID fire.

        The collector only runs at maturity boundaries (pre_d810 /
        post_d810), so intermediate snapshots have ``fact_detected =
        False`` simply because the collector didn't run there. To avoid
        over-flagging, this property only inspects the FINAL snapshot
        in the timeline; intermediate fact-detection state is ignored.
        """
        if not self.timeline:
            return None
        # Look for any earlier snapshot where the fact DID fire.
        had_fact = any(
            e.present and e.fact_detected for e in self.timeline[:-1]
        )
        if not had_fact:
            return None
        last = self.timeline[-1]
        if last.present and not last.fact_detected:
            return last
        return None

    @property
    def inferred_cause(self) -> str:
        """Heuristic cause classification.

        - ``survives_pipeline`` — block + fact present at every snapshot.
        - ``ida_native_maturity_fold`` — block disappears at post_d810
          after surviving every D810-controlled snapshot. IDA's
          ``mba_t.optimize_global()`` finalization DCE.
        - ``d810_strategy_phase_<phase>`` — block disappears at a
          per-strategy ``post_apply`` snapshot.
        - ``fact_collector_lost_pattern`` — block survives but the
          byte_emit FACT stops firing. Collector limitation or content
          change.
        - ``unattributed`` — no clear pattern.
        """
        if self.survives_pipeline and self.fact_first_loss is None:
            return "survives_pipeline"
        loss = self.first_loss
        last = self.last_present
        if loss is None and self.fact_first_loss is not None:
            return "fact_collector_lost_pattern"
        if loss is None or last is None:
            return "unattributed"
        if loss.snapshot_phase == "post_d810" and last.snapshot_phase != "post_d810":
            return "ida_native_maturity_fold"
        return f"d810_strategy_phase_{loss.snapshot_phase}"


def build_block_survival(
    initial: ByteEmitInitialState,
    snapshots: Iterable[tuple[int, str, str]],
    block_lookup: Mapping[tuple[int, str], tuple[int, int, int, int]],
    fact_lookup: Mapping[tuple[int, int], bool] | None = None,
) -> ByteEmitSurvival:
    """Compose one byte_emit's cross-snapshot timeline.

    Parameters
    ----------
    initial : ByteEmitInitialState
        The byte_emit's identity at the initial snapshot.
    snapshots : Iterable[tuple[snapshot_id, label, phase]]
        Snapshots to walk in chronological order.
    block_lookup : Mapping[(snapshot_id, start_ea_hex), (serial, npred, nsucc, insn_count)]
        For each (snapshot_id, start_ea_hex), the corresponding block's
        metadata. Missing keys mean the block was absent at that snapshot.
    fact_lookup : Mapping[(snapshot_id, byte_index), bool], optional
        Per-snapshot byte_emit fact detection. Missing keys default to
        False (no fact detected at that snapshot).
    """
    fact_lookup = fact_lookup or {}
    timeline: list[SnapshotBlockView] = []
    for snapshot_id, label, phase in snapshots:
        info = block_lookup.get((int(snapshot_id), initial.start_ea_hex))
        fact_detected = bool(
            fact_lookup.get((int(snapshot_id), initial.byte_index), False)
        )
        if info is None:
            timeline.append(
                SnapshotBlockView(
                    snapshot_id=int(snapshot_id),
                    snapshot_label=label,
                    snapshot_phase=phase,
                    block_serial=None,
                    npred=None,
                    nsucc=None,
                    insn_count=None,
                    fact_detected=fact_detected,
                )
            )
            continue
        serial, npred, nsucc, insn_count = info
        timeline.append(
            SnapshotBlockView(
                snapshot_id=int(snapshot_id),
                snapshot_label=label,
                snapshot_phase=phase,
                block_serial=int(serial),
                npred=int(npred),
                nsucc=int(nsucc),
                insn_count=int(insn_count),
                fact_detected=fact_detected,
            )
        )
    return ByteEmitSurvival(
        byte_index=initial.byte_index,
        initial=initial,
        timeline=tuple(timeline),
    )


@dataclass(frozen=True, slots=True)
class LossLocalizationReport:
    """Aggregated per-byte survival report."""

    survivals: tuple[ByteEmitSurvival, ...]

    def cause_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.survivals:
            out[s.inferred_cause] = out.get(s.inferred_cause, 0) + 1
        return out


def localize_byte_emit_loss(
    initial_states: Iterable[ByteEmitInitialState],
    snapshots: Iterable[tuple[int, str, str]],
    block_lookup: Mapping[tuple[int, str], tuple[int, int, int, int]],
    fact_lookup: Mapping[tuple[int, int], bool] | None = None,
) -> LossLocalizationReport:
    """Build the full localization report.

    ``snapshots`` is materialized once; ``initial_states`` may yield in
    any order — the report preserves byte_index ordering.
    """
    snaps = list(snapshots)
    out: list[ByteEmitSurvival] = []
    for state in sorted(initial_states, key=lambda s: s.byte_index):
        out.append(build_block_survival(state, snaps, block_lookup, fact_lookup))
    return LossLocalizationReport(survivals=tuple(out))


def format_localization_report(report: LossLocalizationReport) -> str:
    """Render a markdown table of per-byte timelines."""
    if not report.survivals:
        return "(no byte_emit candidates)"
    lines: list[str] = []
    lines.append("## Byte-emit block survival across snapshots\n")
    lines.append(
        "Cell legend: ``blk[N]/Pp{F|b}`` where N=block_serial, P=npred, "
        "F=byte_emit fact detected at this snapshot, b=block survives but "
        "fact NOT detected. ``X``=block absent.\n"
    )
    snaps = report.survivals[0].timeline
    header = ["byte", "EA"] + [str(s.snapshot_id) for s in snaps]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("-" for _ in header) + "|")
    for surv in report.survivals:
        cells: list[str] = [str(surv.byte_index), surv.initial.start_ea_hex]
        for entry in surv.timeline:
            if entry.present:
                marker = "F" if entry.fact_detected else "b"
                cells.append(f"blk[{entry.block_serial}]/{entry.npred}p{marker}")
            else:
                cells.append("X")
        lines.append("| " + " | ".join(cells) + " |")

    lines.append("\n## First-loss localization\n")
    lines.append("| byte | last present | first loss | inferred cause |")
    lines.append("|-|-|-|-|")
    for surv in report.survivals:
        last = surv.last_present
        loss = surv.first_loss
        last_s = (
            f"snap{last.snapshot_id} ({last.snapshot_label})" if last else "—"
        )
        loss_s = (
            f"snap{loss.snapshot_id} ({loss.snapshot_label})"
            if loss
            else "(survives)"
        )
        lines.append(
            f"| {surv.byte_index} | {last_s} | {loss_s} | {surv.inferred_cause} |"
        )

    counts = report.cause_counts()
    lines.append("\n## Cause summary\n")
    for cause, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"- **{cause}**: {n}")

    return "\n".join(lines)


__all__ = [
    "ByteEmitInitialState",
    "ByteEmitSurvival",
    "LossLocalizationReport",
    "SnapshotBlockView",
    "build_block_survival",
    "format_localization_report",
    "localize_byte_emit_loss",
]
