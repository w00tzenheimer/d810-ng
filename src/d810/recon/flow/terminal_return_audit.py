"""Terminal return audit -- pure analysis of return-site characteristics for terminal handlers.

This module analyzes which terminal handlers have provable return paths and
what kind of return source (direct, epilogue corridor, shared epilogue) each has.
It does NOT modify any CFG state -- it produces a read-only audit report.
"""
from __future__ import annotations

import enum
from collections import deque
from dataclasses import dataclass
from d810.core.typing import TYPE_CHECKING

from d810.core.logging import getLogger

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph

logger = getLogger(__name__)

# BLT_STOP = 1 in IDA's block type enum (the last block, stops execution).
_BLT_STOP: int = 1


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


def _classify_exit(
    cfg: FlowGraph,
    exit_serial: int | None,
    max_depth: int = 50,
) -> tuple[TerminalReturnSourceKind, int | None, int, tuple[int, ...]]:
    """Walk forward from *exit_serial* to classify the return path.

    Args:
        cfg: The pre-linearization FlowGraph snapshot.
        exit_serial: The exit block serial to start walking from.
        max_depth: Maximum BFS depth to prevent runaway walks.

    Returns:
        A tuple of (source_kind, return_block_serial, corridor_length, path_serials).
        *path_serials* contains the block serials visited on the path from
        exit_serial to the return block (inclusive of both endpoints).
    """
    if exit_serial is None:
        return TerminalReturnSourceKind.UNREACHABLE, None, 0, ()

    blk = cfg.get_block(exit_serial)
    if blk is None:
        return TerminalReturnSourceKind.UNREACHABLE, None, 0, ()

    # Case 1: exit block itself is BLT_STOP.
    if blk.block_type == _BLT_STOP:
        return TerminalReturnSourceKind.DIRECT_RETURN, exit_serial, 0, (exit_serial,)

    # BFS forward from exit to find BLT_STOP, tracking the path shape.
    visited: set[int] = {exit_serial}
    # Queue entries: (serial, corridor_length_so_far, all_single_pred, path_so_far)
    queue: deque[tuple[int, int, bool, tuple[int, ...]]] = deque()

    # P1-2 fix: check exit block's own predecessor count when seeding BFS.
    exit_is_single_pred = len(blk.preds) <= 1
    for succ in blk.succs:
        if succ not in visited:
            queue.append((succ, 1, exit_is_single_pred, (exit_serial,)))
            visited.add(succ)

    while queue:
        serial, corridor_len, all_single_pred, path_so_far = queue.popleft()

        if corridor_len > max_depth:
            continue

        next_blk = cfg.get_block(serial)
        if next_blk is None:
            continue

        is_single_pred = len(next_blk.preds) == 1
        current_path = path_so_far + (serial,)

        if next_blk.block_type == _BLT_STOP:
            # Found a return block. Classify based on path shape.
            if all_single_pred and is_single_pred:
                return (
                    TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
                    serial,
                    corridor_len,
                    current_path,
                )
            else:
                return (
                    TerminalReturnSourceKind.SHARED_EPILOGUE,
                    serial,
                    corridor_len,
                    current_path,
                )

        current_single = all_single_pred and is_single_pred
        for succ in next_blk.succs:
            if succ not in visited:
                visited.add(succ)
                queue.append((succ, corridor_len + 1, current_single, current_path))

    return TerminalReturnSourceKind.UNREACHABLE, None, 0, (exit_serial,)


def build_terminal_return_audit(
    cfg: FlowGraph,
    terminal_handler_serials: set[int],
    exit_map: dict[int, int | None],
    total_handlers: int | None = None,
    rax_write_serials: set[int] | None = None,
) -> TerminalReturnAuditReport:
    """Build a terminal return audit report for the given CFG and terminal handlers.

    Args:
        cfg: The pre-linearization FlowGraph snapshot.
        terminal_handler_serials: Set of handler entry block serials marked terminal.
        exit_map: Maps handler_serial to exit_block_serial (from linearization).
        total_handlers: Total handler count (defaults to len(exit_map) if not given).
        rax_write_serials: Optional set of block serials known to contain return-carrier
            (rax.8) writes. When provided, each audit row's ``has_rax_write`` is set by
            checking whether any block on the path intersects this set. When ``None``,
            ``has_rax_write`` remains ``None`` (not analyzed).

    Returns:
        A :class:`TerminalReturnAuditReport` with per-handler audit results.
    """
    if total_handlers is None:
        total_handlers = len(exit_map)

    sites: list[TerminalReturnSiteAudit] = []

    for handler_serial in sorted(terminal_handler_serials):
        exit_serial = exit_map.get(handler_serial)
        source_kind, return_serial, corridor_len, path_serials = _classify_exit(
            cfg, exit_serial
        )

        notes_parts: list[str] = []
        if source_kind == TerminalReturnSourceKind.UNREACHABLE:
            notes_parts.append("no path to BLT_STOP from exit")
        if exit_serial is not None and exit_serial not in cfg.blocks:
            notes_parts.append(f"exit block {exit_serial} not in CFG")

        # Determine has_rax_write from path intersection.
        # Include handler_serial and exit_serial in checked set -- the rax
        # write typically lives in the handler body, not just on the
        # exit-to-return corridor that _classify_exit returns.
        has_rax_write: bool | None = None
        if (
            rax_write_serials is not None
            and source_kind != TerminalReturnSourceKind.UNREACHABLE
        ):
            checked_blocks = {handler_serial}
            if exit_serial is not None:
                checked_blocks.add(exit_serial)
            checked_blocks.update(path_serials)
            has_rax_write = bool(rax_write_serials & checked_blocks)

        sites.append(
            TerminalReturnSiteAudit(
                handler_serial=handler_serial,
                exit_serial=exit_serial,
                source_kind=source_kind,
                return_block_serial=return_serial,
                corridor_length=corridor_len,
                has_rax_write=has_rax_write,
                notes="; ".join(notes_parts),
            )
        )

    report = TerminalReturnAuditReport(
        function_ea=cfg.func_ea,
        total_handlers=total_handlers,
        terminal_handlers=len(terminal_handler_serials),
        sites=tuple(sites),
    )
    logger.info("Terminal return audit: %s", report.summary())
    return report


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def to_dict(report: TerminalReturnAuditReport) -> dict:
    """Serialize a :class:`TerminalReturnAuditReport` to a JSON-compatible dict.

    Args:
        report: The report to serialize.

    Returns:
        A dict suitable for ``json.dumps``.
    """
    return {
        "function_ea": report.function_ea,
        "total_handlers": report.total_handlers,
        "terminal_handlers": report.terminal_handlers,
        "sites": [
            {
                "handler_serial": s.handler_serial,
                "exit_serial": s.exit_serial,
                "source_kind": s.source_kind.value,
                "return_block_serial": s.return_block_serial,
                "corridor_length": s.corridor_length,
                "has_rax_write": s.has_rax_write,
                "notes": s.notes,
            }
            for s in report.sites
        ],
    }


def from_dict(data: dict) -> TerminalReturnAuditReport:
    """Deserialize a :class:`TerminalReturnAuditReport` from a dict.

    Args:
        data: A dict previously produced by :func:`to_dict`.

    Returns:
        A reconstructed :class:`TerminalReturnAuditReport`.
    """
    sites = tuple(
        TerminalReturnSiteAudit(
            handler_serial=s["handler_serial"],
            exit_serial=s["exit_serial"],
            source_kind=TerminalReturnSourceKind(s["source_kind"]),
            return_block_serial=s["return_block_serial"],
            corridor_length=s["corridor_length"],
            has_rax_write=s["has_rax_write"],
            notes=s["notes"],
        )
        for s in data["sites"]
    )
    return TerminalReturnAuditReport(
        function_ea=data["function_ea"],
        total_handlers=data["total_handlers"],
        terminal_handlers=data["terminal_handlers"],
        sites=sites,
    )
