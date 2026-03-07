"""Terminal return data model types -- pure value objects with no IDA dependency.

These types are shared between recon (which builds audit reports) and evaluator
(which consumes them for proof orchestration).  They live in ``d810.cfg.flow``
so both layers can import them without violating the layered architecture.
"""
from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass


class TerminalReturnSourceKind(str, enum.Enum):
    """Classification of how a terminal handler reaches a return site."""

    DIRECT_RETURN = "direct_return"
    """Handler path ends at a block with m_ret (BLT_STOP)."""

    EPILOGUE_CORRIDOR = "epilogue_corridor"
    """Handler path reaches epilogue corridor (shared return sequence) via single-pred chain."""

    SHARED_EPILOGUE = "shared_epilogue"
    """Handler path reaches shared epilogue with multiple predecessors (phi-merge point)."""

    UNREACHABLE = "unreachable"
    """No path from handler exit to any return block found."""

    UNKNOWN = "unknown"
    """Analysis could not classify."""


@dataclass(frozen=True)
class TerminalReturnSiteAudit:
    """Audit result for a single terminal handler's return path.

    Attributes:
        handler_serial: Entry block serial of the terminal handler.
        exit_serial: Exit block serial after linearization redirect (None if unknown).
        source_kind: Classification of the return path.
        return_block_serial: Serial of the BLT_STOP block if reachable (None otherwise).
        corridor_length: Number of blocks in epilogue corridor (0 if DIRECT_RETURN or UNREACHABLE).
        has_rax_write: Whether a rax.8 write was observed on the path (None if not analyzed).
        notes: Free-form diagnostic note.
    """

    handler_serial: int
    exit_serial: int | None
    source_kind: TerminalReturnSourceKind
    return_block_serial: int | None = None
    corridor_length: int = 0
    has_rax_write: bool | None = None
    notes: str = ""


@dataclass(frozen=True)
class TerminalReturnAuditReport:
    """Aggregate audit report for all terminal handlers in a function.

    Attributes:
        function_ea: Function entry address.
        total_handlers: Total handler count.
        terminal_handlers: Count of handlers marked terminal.
        sites: Per-handler audit results.
    """

    function_ea: int
    total_handlers: int
    terminal_handlers: int
    sites: tuple[TerminalReturnSiteAudit, ...]

    def summary(self) -> str:
        """One-line summary of the audit results.

        Returns:
            String of the form "N/M terminal handlers: X direct, Y corridor, Z shared, W unreachable".
        """
        counts: dict[TerminalReturnSourceKind, int] = {}
        for site in self.sites:
            counts[site.source_kind] = counts.get(site.source_kind, 0) + 1
        direct = counts.get(TerminalReturnSourceKind.DIRECT_RETURN, 0)
        corridor = counts.get(TerminalReturnSourceKind.EPILOGUE_CORRIDOR, 0)
        shared = counts.get(TerminalReturnSourceKind.SHARED_EPILOGUE, 0)
        unreachable = counts.get(TerminalReturnSourceKind.UNREACHABLE, 0)
        return (
            f"{self.terminal_handlers}/{self.total_handlers} terminal handlers: "
            f"{direct} direct, {corridor} corridor, {shared} shared, {unreachable} unreachable"
        )


class TerminalLoweringAction(str, enum.Enum):
    """Recommended lowering shape for a terminal return merge."""

    NO_ACTION = "no_action"
    PRIVATE_RETURN_BLOCK = "private_return_block"
    PRIVATE_TERMINAL_SUFFIX = "private_terminal_suffix"
    DIRECT_TERMINAL_LOWERING = "direct_terminal_lowering"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class TerminalCfgSuffixFrontier:
    """Minimal shared CFG suffix that must be privatized to break a merge.

    Attributes:
        shared_entry_serial: First block in the shared suffix.
        return_block_serial: Terminal stop/return block.
        suffix_serials: Shared suffix blocks from entry through return block.
        unique_anchor_serials: Immediate predecessors of the shared suffix entry
            that are not part of the shared suffix.
    """

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
    """Best current semantic lowering point for a terminal merge.

    Attributes:
        action: Recommended lowering action.
        lowering_start_serial: First block that should be privatized or lowered.
            ``None`` when no action is recommended.
        unique_anchor_serials: Path-unique CFG anchors feeding the lowering point.
        notes: Diagnostic rationale.
    """

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
    """Compute the minimal shared terminal CFG suffix for a return merge.

    The algorithm walks backward from the terminal stop/return block while the
    current block has exactly one predecessor. The first block whose fan-in is
    not one becomes the shared suffix entry. Its non-suffix predecessors are
    the unique anchors that distinguish the terminal paths.
    """

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


__all__ = [
    "TerminalReturnAuditReport",
    "TerminalReturnSiteAudit",
    "TerminalReturnSourceKind",
    "TerminalLoweringAction",
    "TerminalCfgSuffixFrontier",
    "TerminalSemanticLoweringFrontier",
    "compute_terminal_cfg_suffix_frontier",
]
