"""Shared terminal return audit model."""
from __future__ import annotations

import enum
from dataclasses import dataclass


class TerminalReturnSourceKind(str, enum.Enum):
    """Classification of how a terminal handler reaches a return site."""

    DIRECT_RETURN = "direct_return"
    EPILOGUE_CORRIDOR = "epilogue_corridor"
    SHARED_EPILOGUE = "shared_epilogue"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TerminalReturnSiteAudit:
    """Audit result for a single terminal handler's return path."""

    handler_serial: int
    exit_serial: int | None
    source_kind: TerminalReturnSourceKind
    return_block_serial: int | None = None
    corridor_length: int = 0
    has_rax_write: bool | None = None
    notes: str = ""


@dataclass(frozen=True)
class TerminalReturnAuditReport:
    """Aggregate audit report for all terminal handlers in a function."""

    function_ea: int
    total_handlers: int
    terminal_handlers: int
    sites: tuple[TerminalReturnSiteAudit, ...]

    def summary(self) -> str:
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
