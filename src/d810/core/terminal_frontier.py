"""Terminal suffix frontier models and CFG-only lowering heuristics.

These helpers are pure value objects and simple graph walkers with no IDA or
layer-specific dependencies. They live in ``d810.core`` so both recon and cfg
can consume them without creating a ``recon <- cfg`` dependency.
"""
from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass


class TerminalLoweringAction(str, enum.Enum):
    """Recommended lowering shape for a terminal return merge."""

    NO_ACTION = "no_action"
    PRIVATE_RETURN_BLOCK = "private_return_block"
    PRIVATE_TERMINAL_SUFFIX = "private_terminal_suffix"
    DIRECT_TERMINAL_LOWERING = "direct_terminal_lowering"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class TerminalCfgSuffixFrontier:
    """Minimal shared CFG suffix that must be privatized to break a merge."""

    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    unique_anchor_serials: tuple[int, ...]

    def summary(self) -> str:
        suffix = "->".join(str(x) for x in self.suffix_serials)
        anchors = ",".join(str(x) for x in self.unique_anchor_serials) or "<none>"
        return (
            f"shared_entry=blk[{self.shared_entry_serial}] "
            f"return=blk[{self.return_block_serial}] "
            f"suffix={suffix} anchors=[{anchors}]"
        )


@dataclass(frozen=True)
class TerminalSemanticLoweringFrontier:
    """Best current CFG-derived lowering point for a terminal merge."""

    action: TerminalLoweringAction
    lowering_start_serial: int | None
    unique_anchor_serials: tuple[int, ...]
    notes: str = ""

    def summary(self) -> str:
        anchors = ",".join(str(x) for x in self.unique_anchor_serials) or "<none>"
        start = f"blk[{self.lowering_start_serial}]" if self.lowering_start_serial is not None else "<none>"
        return f"action={self.action.value} start={start} anchors=[{anchors}] notes={self.notes}"


def compute_terminal_cfg_suffix_frontier(
    return_block_serial: int,
    *,
    predecessors_of: Callable[[int], tuple[int, ...] | list[int]],
) -> TerminalCfgSuffixFrontier:
    """Compute the minimal shared terminal CFG suffix for a return merge."""

    suffix_rev = [int(return_block_serial)]
    visited = {int(return_block_serial)}
    current = int(return_block_serial)

    while True:
        preds = tuple(int(p) for p in predecessors_of(current))
        if len(preds) != 1:
            break
        pred = preds[0]
        if pred in visited:
            break
        visited.add(pred)
        suffix_rev.append(pred)
        current = pred

    suffix_serials = tuple(reversed(suffix_rev))
    shared_entry_serial = suffix_serials[0]
    suffix_set = set(suffix_serials)
    unique_anchor_serials = tuple(
        sorted(int(p) for p in predecessors_of(shared_entry_serial) if int(p) not in suffix_set)
    )
    return TerminalCfgSuffixFrontier(
        shared_entry_serial=shared_entry_serial,
        return_block_serial=int(return_block_serial),
        suffix_serials=suffix_serials,
        unique_anchor_serials=unique_anchor_serials,
    )


def classify_cfg_suffix_action(
    cfg_frontier: TerminalCfgSuffixFrontier,
) -> TerminalSemanticLoweringFrontier:
    """Classify a CFG suffix frontier into a coarse lowering recommendation."""

    shared_entry = cfg_frontier.shared_entry_serial
    return_block = cfg_frontier.return_block_serial
    anchors = cfg_frontier.unique_anchor_serials
    suffix_len = len(cfg_frontier.suffix_serials)

    if shared_entry == return_block:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.NO_ACTION,
            lowering_start_serial=None,
            unique_anchor_serials=anchors,
            notes="suffix is trivial (entry == return)",
        )

    if suffix_len < 2:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.NO_ACTION,
            lowering_start_serial=None,
            unique_anchor_serials=anchors,
            notes=f"suffix too short ({suffix_len} block)",
        )

    if len(anchors) < 2:
        return TerminalSemanticLoweringFrontier(
            action=TerminalLoweringAction.NO_ACTION,
            lowering_start_serial=None,
            unique_anchor_serials=anchors,
            notes=f"insufficient anchors ({len(anchors)})",
        )

    return TerminalSemanticLoweringFrontier(
        action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
        lowering_start_serial=shared_entry,
        unique_anchor_serials=anchors,
        notes=f"corridor of {suffix_len} blocks with {len(anchors)} anchors",
    )


__all__ = [
    "TerminalCfgSuffixFrontier",
    "TerminalLoweringAction",
    "TerminalSemanticLoweringFrontier",
    "classify_cfg_suffix_action",
    "compute_terminal_cfg_suffix_frontier",
]
