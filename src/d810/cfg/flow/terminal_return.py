"""Terminal return data model types -- pure value objects with no IDA dependency.

These types are shared between recon (which builds audit reports) and evaluator
(which consumes them for proof orchestration).  They live in ``d810.cfg.flow``
so both layers can import them without violating the layered architecture.
"""
from __future__ import annotations

import enum
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


__all__ = [
    "TerminalReturnAuditReport",
    "TerminalReturnSiteAudit",
    "TerminalReturnSourceKind",
]
