"""Pure model behind the Extensions listing (ticket d81-zijs).

Fed by :meth:`d810.core.plugins.BackendRegistry.report`, so the listing shows
real load-bearing state rather than a static roster: which backends are
available, which optional ones are simply not installed, and which are actually
broken. Nothing else in the plugin surfaces that today -- a user with
``d810-cobra`` installed but failing to import currently has no way to tell.

Qt-free and IDA-free (``d810.core.plugins`` imports neither), so the table is
unit-testable; :mod:`d810.ui.extensions_dialog` renders it.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.plugins import BackendInfo, BackendStatus
from d810.core.typing import Iterable, Sequence

EXTENSION_COLUMNS: tuple[str, ...] = ("Name", "Origin", "API", "Status", "Detail")

#: Statuses that mean "someone must fix this", as opposed to the normal
#: deployment fact that an optional dependency is not installed. The registry
#: draws this distinction deliberately; the UI must not flatten it back.
_DEFECT_STATUSES = frozenset({BackendStatus.BROKEN, BackendStatus.INCOMPATIBLE})

__all__ = [
    "EXTENSION_COLUMNS",
    "ExtensionRow",
    "collect_extension_rows",
    "extension_rows",
    "has_defects",
    "summarize",
]


@dataclass(frozen=True, slots=True)
class ExtensionRow:
    """One rendered row of the Extensions table."""

    name: str
    origin: str
    api_version: str
    status: str
    detail: str
    is_defect: bool

    def cells(self) -> tuple[str, ...]:
        """Column-ordered cell text, matching :data:`EXTENSION_COLUMNS`."""
        return (self.name, self.origin, self.api_version, self.status, self.detail)


def _detail(info: BackendInfo) -> str:
    """Why this backend is in its current state, in one line."""
    parts: list[str] = []
    if info.reason:
        parts.append(str(info.reason))
    if info.shadowed:
        # Running on a fallback: something the user installed did not work and
        # an in-tree backend took over. Worth saying out loud.
        parts.append("shadowed: " + ", ".join(str(s) for s in info.shadowed))
    return "; ".join(parts)


def extension_rows(infos: Iterable[BackendInfo]) -> tuple[ExtensionRow, ...]:
    """Map registry infos to display rows, preserving registry order."""
    return tuple(
        ExtensionRow(
            name=str(info.name),
            origin=str(info.origin),
            api_version="-" if info.api_version is None else str(info.api_version),
            status=info.status.value,
            detail=_detail(info),
            is_defect=info.status in _DEFECT_STATUSES,
        )
        for info in infos
    )


def has_defects(rows: Sequence[ExtensionRow]) -> bool:
    """True when any row needs someone's attention."""
    return any(row.is_defect for row in rows)


def summarize(rows: Sequence[ExtensionRow]) -> str:
    """One-line status shown under the table.

    Backends load lazily, so a fresh session reports every one as
    ``not_loaded``. That is "not probed yet", NOT "unavailable" -- saying
    "0 of 6 available" there would read as "nothing works" when nothing has
    even been asked.
    """
    if not rows:
        return "no extensions registered"
    probed = tuple(
        row for row in rows if row.status != BackendStatus.NOT_LOADED.value
    )
    if not probed:
        return f"{len(rows)} registered, none loaded yet"
    available = sum(1 for row in rows if row.status == BackendStatus.AVAILABLE.value)
    summary = f"{available} of {len(rows)} available"
    broken = sum(1 for row in rows if row.is_defect)
    if broken:
        summary = f"{summary}, {broken} broken"
    return summary


def collect_extension_rows() -> tuple[ExtensionRow, ...]:
    """Rows for the live registry, or empty when it cannot be consulted.

    Never raises: this feeds a dialog, and an unreadable registry is worth an
    empty table plus the summary line, not a broken window.
    """
    try:
        from d810.backends import registry

        return extension_rows(registry().report())
    except Exception:  # noqa: BLE001 - a listing must not take the dialog down
        return ()
