"""Pure byte-state classification for preparation restore and recovery."""

from __future__ import annotations

import enum

from d810.capabilities.idb_preparation import PreparationByteDelta, PreparationPatchRow
from d810.core.typing import Callable

__all__ = ["PreparationBytePosition", "classify_preparation_byte"]


class PreparationBytePosition(str, enum.Enum):
    BEFORE = "before"
    AFTER = "after"
    NEITHER = "neither"


def classify_preparation_byte(
    delta: PreparationByteDelta,
    patch_rows_by_ea: dict[int, PreparationPatchRow],
    read_current_byte: Callable[[int], int | None],
) -> PreparationBytePosition:
    """Classify one live byte against exact before/after patch-layer states."""

    row = patch_rows_by_ea.get(delta.ea)
    current = read_current_byte(delta.ea)
    if current is None:
        return PreparationBytePosition.NEITHER

    is_patched = row is not None
    if row is not None:
        if row.ida_original != delta.ida_original or row.current_value != current:
            return PreparationBytePosition.NEITHER

    if is_patched == delta.before_is_patched and current == delta.before_value:
        return PreparationBytePosition.BEFORE
    if is_patched == delta.after_is_patched and current == delta.after_value:
        return PreparationBytePosition.AFTER
    return PreparationBytePosition.NEITHER
