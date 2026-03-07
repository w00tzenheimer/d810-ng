"""Terminal return valrange diagnostics.

This module compares terminal predecessor blocks against the shared epilogue
entry/stop blocks using IDA's native ``get_valranges()`` API. It is strictly
read-only and intended for debugging terminal-return ambiguity, especially in
cases like ``sub_7FFD3338C040`` where multiple terminal handlers merge into a
shared epilogue and the decompiler collapses return-carrier precision.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum

from d810.cfg.flow.terminal_return import (
    TerminalCfgSuffixFrontier,
    TerminalLoweringAction,
    TerminalSemanticLoweringFrontier,
    TerminalReturnAuditReport,
    TerminalReturnSourceKind,
    compute_terminal_cfg_suffix_frontier,
)
from d810.core.typing import Iterable, Optional
from d810.evaluator.hexrays_microcode.valranges import (
    ValrangeLocation,
    ValrangeLocationKind,
    ValrangeRecord,
    collect_block_valrange_record_for_location,
    collect_block_valrange_records,
    collect_instruction_valrange_record_for_location,
    collect_instruction_valrange_records,
)


class TerminalValrangeMergeKind(str, Enum):
    """Heuristic classification of where return-carrier ambiguity appears."""

    BEFORE_SHARED_ENTRY = "before_shared_entry"
    AT_SHARED_ENTRY = "at_shared_entry"
    ONLY_AT_SHARED_STOP = "only_at_shared_stop"
    NOT_AMBIGUOUS = "not_ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TerminalValrangeSnapshot:
    """Valrange view for one block, at block start and tail instruction."""

    block_serial: int
    rax_start: ValrangeRecord | None
    rax_tail: ValrangeRecord | None
    state_start: ValrangeRecord | None
    state_tail: ValrangeRecord | None
    stack_start: tuple[ValrangeRecord, ...]
    stack_tail: tuple[ValrangeRecord, ...]
    use_text: str = ""
    def_text: str = ""


@dataclass(frozen=True)
class TerminalReturnValrangeGroup:
    """One shared-terminal merge group."""

    shared_entry_serial: int
    return_block_serial: int
    handler_serials: tuple[int, ...]
    terminal_predecessor_serials: tuple[int, ...]
    current_paths: tuple[tuple[int, ...], ...]
    cfg_frontier: TerminalCfgSuffixFrontier
    semantic_frontier: TerminalSemanticLoweringFrontier
    merge_kind: TerminalValrangeMergeKind
    notes: str
    suffix_snapshots: tuple[TerminalValrangeSnapshot, ...]
    merge_snapshot: TerminalValrangeSnapshot
    return_snapshot: TerminalValrangeSnapshot
    predecessor_snapshots: tuple[TerminalValrangeSnapshot, ...]

    def summary(self) -> str:
        preds = ",".join(str(p) for p in self.terminal_predecessor_serials) or "<none>"
        handlers = ",".join(str(h) for h in self.handler_serials) or "<none>"
        return (
            f"shared_entry=blk[{self.shared_entry_serial}] return=blk[{self.return_block_serial}] "
            f"handlers=[{handlers}] preds=[{preds}] merge={self.merge_kind.value}"
        )

    def format(self) -> str:
        """Human-readable multi-line report preserving IDA-like range text."""
        lines = [self.summary()]
        if self.notes:
            lines.append(f"  note: {self.notes}")
        lines.append(f"  cfg frontier: {self.cfg_frontier.summary()}")
        lines.append(f"  semantic frontier: {self.semantic_frontier.summary()}")
        if self.suffix_snapshots:
            lines.append(
                "  suffix snapshots: "
                + " | ".join(
                    f"blk[{snap.block_serial}] { _format_snapshot(snap) }"
                    for snap in self.suffix_snapshots
                )
            )
        lines.append(
            f"  merge start: { _format_snapshot(self.merge_snapshot) }"
        )
        lines.append(
            f"  shared stop: { _format_snapshot(self.return_snapshot) }"
        )
        for snap in self.predecessor_snapshots:
            lines.append(f"  pred blk[{snap.block_serial}]: { _format_snapshot(snap) }")
        if self.current_paths:
            path_bits = ", ".join("->".join(str(x) for x in path) for path in self.current_paths)
            lines.append(f"  current paths: {path_bits}")
        return "\n".join(lines)


@dataclass(frozen=True)
class TerminalReturnValrangeReport:
    """Aggregate valrange comparison report for terminal-return groups."""

    function_ea: int
    groups: tuple[TerminalReturnValrangeGroup, ...]

    def summary(self) -> str:
        return f"{len(self.groups)} shared-terminal group(s)"

    def format(self) -> str:
        lines = [self.summary()]
        for group in self.groups:
            lines.append("")
            lines.append(group.format())
        return "\n".join(lines)


def _is_singleton(rec: ValrangeRecord | None) -> bool | None:
    if rec is None:
        return None
    return rec.range_text.startswith("==")


def _find_path(
    mba: object,
    start_serial: int | None,
    goal_serial: int | None,
    *,
    max_depth: int = 50,
) -> tuple[int, ...]:
    """Find one successor path from *start_serial* to *goal_serial* in current MBA."""
    if start_serial is None or goal_serial is None:
        return ()
    if start_serial == goal_serial:
        return (start_serial,)

    visited = {start_serial}
    queue: deque[tuple[int, tuple[int, ...]]] = deque([(start_serial, (start_serial,))])

    while queue:
        serial, path = queue.popleft()
        if len(path) > max_depth:
            continue
        try:
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        for succ in getattr(blk, "succset", []):
            if succ == goal_serial:
                return path + (succ,)
            if succ not in visited:
                visited.add(succ)
                queue.append((succ, path + (succ,)))
    return ()


def _first_shared_entry_on_path(mba: object, path: tuple[int, ...]) -> int | None:
    for serial in path:
        try:
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if len(getattr(blk, "predset", [])) > 1:
            return int(serial)
    return None


def _build_snapshot(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    state_var_size: int,
    carrier_mreg: int,
    carrier_size: int,
) -> TerminalValrangeSnapshot:
    blk = mba.get_mblock(block_serial)  # type: ignore[attr-defined]
    tail = getattr(blk, "tail", None)
    rax_loc = ValrangeLocation(
        kind=ValrangeLocationKind.REGISTER,
        identifier=carrier_mreg,
        width=carrier_size,
    )
    state_loc = None
    if state_var_stkoff is not None:
        state_loc = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=state_var_stkoff,
            width=state_var_size,
        )

    rax_start = collect_block_valrange_record_for_location(blk, rax_loc)
    rax_tail = (
        collect_instruction_valrange_record_for_location(blk, tail, rax_loc)
        if tail is not None
        else None
    )
    state_start = (
        collect_block_valrange_record_for_location(blk, state_loc)
        if state_loc is not None
        else None
    )
    state_tail = (
        collect_instruction_valrange_record_for_location(blk, tail, state_loc)
        if tail is not None and state_loc is not None
        else None
    )
    stack_start = tuple(
        rec
        for rec in collect_block_valrange_records(blk)
        if rec.location.kind == ValrangeLocationKind.STACK
    )
    stack_tail = ()
    if tail is not None:
        stack_tail = tuple(
            rec
            for rec in collect_instruction_valrange_records(blk, tail)
            if rec.location.kind == ValrangeLocationKind.STACK
        )
    use_text = ""
    def_text = ""
    try:
        blk.make_lists_ready()
        must_use = getattr(blk, "mustbuse", None)
        must_def = getattr(blk, "mustbdef", None)
        if must_use is not None:
            use_text = must_use.dstr() or ""
        if must_def is not None:
            def_text = must_def.dstr() or ""
    except Exception:
        pass
    return TerminalValrangeSnapshot(
        block_serial=block_serial,
        rax_start=rax_start,
        rax_tail=rax_tail,
        state_start=state_start,
        state_tail=state_tail,
        stack_start=stack_start,
        stack_tail=stack_tail,
        use_text=use_text,
        def_text=def_text,
    )


def _preferred_range_text(snapshot: TerminalValrangeSnapshot, *, state_first: bool = False) -> str | None:
    candidates: list[ValrangeRecord | None] = []
    if state_first:
        candidates.extend([snapshot.state_tail, snapshot.state_start, snapshot.rax_tail, snapshot.rax_start])
    else:
        candidates.extend([snapshot.rax_tail, snapshot.rax_start, snapshot.state_tail, snapshot.state_start])
    for rec in candidates:
        if rec is not None:
            return rec.range_text
    return None


def _infer_merge_kind(
    predecessor_snapshots: Iterable[TerminalValrangeSnapshot],
    merge_snapshot: TerminalValrangeSnapshot,
    return_snapshot: TerminalValrangeSnapshot,
) -> tuple[TerminalValrangeMergeKind, str]:
    pred_texts = {
        txt
        for snap in predecessor_snapshots
        for txt in (_preferred_range_text(snap),)
        if txt is not None
    }
    merge_text = _preferred_range_text(merge_snapshot)
    return_text = _preferred_range_text(return_snapshot)

    pred_non_singleton = any(
        (_is_singleton(snap.rax_tail) is False)
        or (_is_singleton(snap.rax_start) is False)
        or (_is_singleton(snap.state_tail) is False)
        or (_is_singleton(snap.state_start) is False)
        for snap in predecessor_snapshots
    )
    if pred_non_singleton:
        return (
            TerminalValrangeMergeKind.BEFORE_SHARED_ENTRY,
            "at least one predecessor is already non-singleton",
        )
    if len(pred_texts) > 1:
        if merge_text is None:
            return (
                TerminalValrangeMergeKind.AT_SHARED_ENTRY,
                "predecessors differ and shared entry has no targeted carrier range",
            )
        if not merge_text.startswith("==") or merge_text not in pred_texts:
            return (
                TerminalValrangeMergeKind.AT_SHARED_ENTRY,
                "predecessors differ and shared entry widens or changes carrier range",
            )
    if return_text is not None and merge_text is not None:
        if return_text != merge_text and not return_text.startswith("=="):
            return (
                TerminalValrangeMergeKind.ONLY_AT_SHARED_STOP,
                "shared stop widens a carrier that was still precise at shared entry",
            )
    if len(pred_texts) <= 1 and merge_text is not None and return_text is not None:
        if merge_text == return_text:
            return (
                TerminalValrangeMergeKind.NOT_AMBIGUOUS,
                "carrier remains consistent across predecessors, shared entry, and stop",
            )
    return (
        TerminalValrangeMergeKind.UNKNOWN,
        "insufficient targeted carrier evidence to place ambiguity precisely",
    )


def _format_snapshot(snapshot: TerminalValrangeSnapshot) -> str:
    pieces: list[str] = []
    if snapshot.rax_start is not None:
        pieces.append(f"rax@start={snapshot.rax_start}")
    if snapshot.rax_tail is not None:
        pieces.append(f"rax@tail={snapshot.rax_tail}")
    if snapshot.state_start is not None:
        pieces.append(f"state@start={snapshot.state_start}")
    if snapshot.state_tail is not None:
        pieces.append(f"state@tail={snapshot.state_tail}")
    if snapshot.stack_start:
        pieces.append(
            "stack@start=[" + ", ".join(str(r) for r in snapshot.stack_start) + "]"
        )
    if snapshot.stack_tail:
        pieces.append(
            "stack@tail=[" + ", ".join(str(r) for r in snapshot.stack_tail) + "]"
        )
    if snapshot.use_text:
        pieces.append(f"USE={snapshot.use_text}")
    if snapshot.def_text:
        pieces.append(f"DEF={snapshot.def_text}")
    return "; ".join(pieces) if pieces else "<no ranges>"


def _snapshot_has_carrier_activity(snapshot: TerminalValrangeSnapshot) -> bool:
    return any(
        x is not None
        for x in (snapshot.rax_start, snapshot.rax_tail, snapshot.state_start, snapshot.state_tail)
    ) or bool(snapshot.stack_start) or bool(snapshot.stack_tail) or bool(snapshot.use_text) or bool(snapshot.def_text)


def _choose_semantic_frontier(
    cfg_frontier: TerminalCfgSuffixFrontier,
    *,
    suffix_snapshots: tuple[TerminalValrangeSnapshot, ...],
    merge_kind: TerminalValrangeMergeKind,
) -> TerminalSemanticLoweringFrontier:
    """Choose the best current semantic lowering point for a terminal group.

    The minimal CFG suffix tells us what must be privatized to break the merge.
    The semantic frontier tries to move the lowering point back only as far as
    needed to include the first shared return-carrier materialization.
    """
    if merge_kind == TerminalValrangeMergeKind.NOT_AMBIGUOUS:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.NO_ACTION,
            lowering_start_serial=None,
            unique_anchor_serials=cfg_frontier.unique_anchor_serials,
            notes="carrier remains precise across the shared suffix",
        )

    first_active_serial = next(
        (snap.block_serial for snap in suffix_snapshots if _snapshot_has_carrier_activity(snap)),
        None,
    )

    if merge_kind == TerminalValrangeMergeKind.ONLY_AT_SHARED_STOP:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.PRIVATE_RETURN_BLOCK,
            lowering_start_serial=cfg_frontier.return_block_serial,
            unique_anchor_serials=cfg_frontier.unique_anchor_serials,
            notes="ambiguity appears only at the terminal stop",
        )

    if merge_kind in {TerminalValrangeMergeKind.AT_SHARED_ENTRY, TerminalValrangeMergeKind.UNKNOWN}:
        if first_active_serial is not None:
            action = (
                TerminalLoweringAction.PRIVATE_RETURN_BLOCK
                if first_active_serial == cfg_frontier.return_block_serial
                else TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX
            )
            return TerminalSemanticLoweringFrontier(
                action=action,
                lowering_start_serial=first_active_serial,
                unique_anchor_serials=cfg_frontier.unique_anchor_serials,
                notes="shared suffix contains return-carrier materialization before the stop",
            )
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.UNRESOLVED,
            lowering_start_serial=None,
            unique_anchor_serials=cfg_frontier.unique_anchor_serials,
            notes="shared suffix has no targeted carrier evidence",
        )

    if merge_kind == TerminalValrangeMergeKind.BEFORE_SHARED_ENTRY:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.DIRECT_TERMINAL_LOWERING,
            lowering_start_serial=cfg_frontier.unique_anchor_serials[0] if cfg_frontier.unique_anchor_serials else None,
            unique_anchor_serials=cfg_frontier.unique_anchor_serials,
            notes="carrier diverges before the shared suffix; lower at per-path anchors",
        )

    return TerminalSemanticLoweringFrontier(
        action=TerminalLoweringAction.UNRESOLVED,
        lowering_start_serial=None,
        unique_anchor_serials=cfg_frontier.unique_anchor_serials,
        notes="no semantic lowering action could be chosen",
    )


def build_terminal_return_valrange_report(
    mba: object,
    audit_report: TerminalReturnAuditReport,
    *,
    state_var_stkoff: int | None = None,
    state_var_size: int = 4,
    carrier_mreg: int = 0,
    carrier_size: int = 8,
) -> TerminalReturnValrangeReport:
    """Compare terminal predecessors against shared epilogue/stop valranges.

    The report groups terminal sites by the first shared block on the current
    path to the return block. That gives a concrete answer to:
    - do predecessor carrier ranges differ?
    - does the merge begin at the shared epilogue entry or only at the stop?
    """
    grouped: dict[tuple[int, int], list[tuple[object, tuple[int, ...], int | None]]] = {}

    for site in audit_report.sites:
        if site.source_kind not in {
            TerminalReturnSourceKind.SHARED_EPILOGUE,
            TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
            TerminalReturnSourceKind.DIRECT_RETURN,
        }:
            continue
        path = _find_path(mba, site.exit_serial, site.return_block_serial)
        if not path and site.return_block_serial is not None:
            path = (site.return_block_serial,)
        shared_entry = _first_shared_entry_on_path(mba, path)
        if shared_entry is None and site.return_block_serial is not None:
            shared_entry = site.return_block_serial
        if shared_entry is None or site.return_block_serial is None:
            continue
        grouped.setdefault((shared_entry, site.return_block_serial), []).append(
            (site, path, site.exit_serial)
        )

    groups: list[TerminalReturnValrangeGroup] = []
    for (shared_entry, return_block), entries in sorted(grouped.items()):
        groups.append(
            _build_group(
                mba,
                shared_entry=shared_entry,
                return_block=return_block,
                entries=entries,
                state_var_stkoff=state_var_stkoff,
                state_var_size=state_var_size,
                carrier_mreg=carrier_mreg,
                carrier_size=carrier_size,
            )
        )

    return TerminalReturnValrangeReport(
        function_ea=audit_report.function_ea,
        groups=tuple(groups),
    )


def _build_group(
    mba: object,
    *,
    shared_entry: int,
    return_block: int,
    entries: list[tuple[object, tuple[int, ...], int | None]],
    state_var_stkoff: int | None,
    state_var_size: int,
    carrier_mreg: int,
    carrier_size: int,
) -> TerminalReturnValrangeGroup:
    """Build one grouped terminal-return valrange report entry."""
    # Prefer site exit serials that are distinct from the shared entry as terminal predecessors.
    terminal_preds = sorted(
        {
            exit_serial
            for _, _, exit_serial in entries
            if exit_serial is not None and exit_serial != shared_entry
        }
    )
    if not terminal_preds:
        # Prefer site exit serials that are distinct from the shared entry as terminal predecessors.
        try:
            shared_blk = mba.get_mblock(shared_entry)  # type: ignore[attr-defined]
            terminal_preds = sorted(int(p) for p in getattr(shared_blk, "predset", []))
        except Exception:
            terminal_preds = []

    cfg_frontier = compute_terminal_cfg_suffix_frontier(
        return_block,
        predecessors_of=lambda serial: tuple(
            int(p)
            for p in getattr(mba.get_mblock(serial), "predset", [])  # type: ignore[attr-defined]
        ),
    )

    pred_snapshots = tuple(
        _build_snapshot(
            mba,
            pred_serial,
            state_var_stkoff=state_var_stkoff,
            state_var_size=state_var_size,
            carrier_mreg=carrier_mreg,
            carrier_size=carrier_size,
        )
        for pred_serial in terminal_preds
    )
    merge_snapshot = _build_snapshot(
        mba,
        shared_entry,
        state_var_stkoff=state_var_stkoff,
        state_var_size=state_var_size,
        carrier_mreg=carrier_mreg,
        carrier_size=carrier_size,
    )
    return_snapshot = _build_snapshot(
        mba,
        return_block,
        state_var_stkoff=state_var_stkoff,
        state_var_size=state_var_size,
        carrier_mreg=carrier_mreg,
        carrier_size=carrier_size,
    )
    suffix_snapshots = tuple(
        _build_snapshot(
            mba,
            suffix_serial,
            state_var_stkoff=state_var_stkoff,
            state_var_size=state_var_size,
            carrier_mreg=carrier_mreg,
            carrier_size=carrier_size,
        )
        for suffix_serial in cfg_frontier.suffix_serials
    )
    merge_kind, notes = _infer_merge_kind(pred_snapshots, merge_snapshot, return_snapshot)
    semantic_frontier = _choose_semantic_frontier(
        cfg_frontier,
        suffix_snapshots=suffix_snapshots,
        merge_kind=merge_kind,
    )
    return TerminalReturnValrangeGroup(
        shared_entry_serial=shared_entry,
        return_block_serial=return_block,
        handler_serials=tuple(sorted(int(getattr(site, "handler_serial", -1)) for site, _, _ in entries if getattr(site, "handler_serial", None) is not None and int(getattr(site, "handler_serial", -1)) >= 0)),
        terminal_predecessor_serials=tuple(terminal_preds),
        current_paths=tuple(path for _, path, _ in entries if path),
        cfg_frontier=cfg_frontier,
        semantic_frontier=semantic_frontier,
        merge_kind=merge_kind,
        notes=notes,
        suffix_snapshots=suffix_snapshots,
        merge_snapshot=merge_snapshot,
        return_snapshot=return_snapshot,
        predecessor_snapshots=pred_snapshots,
    )


def build_terminal_return_valrange_report_from_mba(
    mba: object,
    *,
    func_ea: int = 0,
    state_var_stkoff: int | None = None,
    state_var_size: int = 4,
    carrier_mreg: int = 0,
    carrier_size: int = 8,
) -> TerminalReturnValrangeReport:
    """Discover shared terminal merges directly from the current MBA.

    This is a fallback for dump/debug paths where recon-store terminal audit
    artifacts are unavailable. It scans for:
    - BLT_STOP / no-succ blocks with multiple predecessors, or
    - BLT_STOP / no-succ blocks whose sole predecessor already has multiple
      predecessors (shared epilogue entry followed by private stop).
    """
    discovered: list[tuple[int, int]] = []
    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        succs = list(getattr(blk, "succset", []))
        preds = list(getattr(blk, "predset", []))
        block_type = int(getattr(blk, "type", getattr(blk, "block_type", -1)))
        is_terminal = block_type == 1 or not succs
        if not is_terminal:
            continue
        if len(preds) > 1:
            discovered.append((serial, serial))
            continue
        if len(preds) == 1:
            pred_blk = mba.get_mblock(preds[0])  # type: ignore[attr-defined]
            pred_preds = list(getattr(pred_blk, "predset", []))
            pred_succs = list(getattr(pred_blk, "succset", []))
            if len(pred_preds) > 1 and pred_succs == [serial]:
                discovered.append((int(pred_blk.serial), serial))

    groups = tuple(
        _build_group(
            mba,
            shared_entry=shared_entry,
            return_block=return_block,
            entries=[(object(), (shared_entry, return_block), None)],
            state_var_stkoff=state_var_stkoff,
            state_var_size=state_var_size,
            carrier_mreg=carrier_mreg,
            carrier_size=carrier_size,
        )
        for shared_entry, return_block in sorted(set(discovered))
    )
    return TerminalReturnValrangeReport(function_ea=func_ea, groups=groups)


__all__ = [
    "TerminalValrangeMergeKind",
    "TerminalValrangeSnapshot",
    "TerminalReturnValrangeGroup",
    "TerminalReturnValrangeReport",
    "build_terminal_return_valrange_report",
    "build_terminal_return_valrange_report_from_mba",
]
