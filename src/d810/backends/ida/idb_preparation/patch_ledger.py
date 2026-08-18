"""Capture and compare IDA's complete patched-byte ledger.

The pure diff function is usable without IDA.  :class:`IdaPatchLedger` is the
only live adapter and imports IDA lazily, preserving unit-test portability.
"""

from __future__ import annotations

from d810.capabilities.idb_preparation import PreparationByteDelta, PreparationPatchRow

__all__ = ["IdaPatchLedger", "derive_patch_delta"]


def _rows_by_ea(
    rows: tuple[PreparationPatchRow, ...],
    *,
    side: str,
) -> tuple[PreparationPatchRow, ...]:
    ordered = tuple(sorted(rows, key=lambda row: row.ea))
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if previous.ea == current.ea:
            raise ValueError(f"duplicate {side} patch EA {current.ea:#x}")
    return ordered


def derive_patch_delta(
    before: tuple[PreparationPatchRow, ...],
    after: tuple[PreparationPatchRow, ...],
) -> tuple[PreparationByteDelta, ...]:
    """Return the deterministic byte-granular difference between two ledgers.

    Missing rows represent pristine bytes whose current value is IDA's
    original byte.  The merge is linear after sorting and never scans loaded
    address space.
    """

    before_rows = _rows_by_ea(before, side="before")
    after_rows = _rows_by_ea(after, side="after")
    before_index = 0
    after_index = 0
    deltas: list[PreparationByteDelta] = []

    while before_index < len(before_rows) or after_index < len(after_rows):
        before_row = (
            before_rows[before_index] if before_index < len(before_rows) else None
        )
        after_row = after_rows[after_index] if after_index < len(after_rows) else None

        if after_row is None or (
            before_row is not None and before_row.ea < after_row.ea
        ):
            assert before_row is not None
            deltas.append(
                PreparationByteDelta(
                    ea=before_row.ea,
                    ida_original=before_row.ida_original,
                    before_is_patched=True,
                    before_value=before_row.current_value,
                    after_is_patched=False,
                    after_value=before_row.ida_original,
                )
            )
            before_index += 1
            continue

        if before_row is None or after_row.ea < before_row.ea:
            deltas.append(
                PreparationByteDelta(
                    ea=after_row.ea,
                    ida_original=after_row.ida_original,
                    before_is_patched=False,
                    before_value=after_row.ida_original,
                    after_is_patched=True,
                    after_value=after_row.current_value,
                )
            )
            after_index += 1
            continue

        if before_row.ida_original != after_row.ida_original:
            raise ValueError(
                f"original byte changed at {before_row.ea:#x}: "
                f"{before_row.ida_original:#x} -> {after_row.ida_original:#x}"
            )
        if before_row.current_value != after_row.current_value:
            deltas.append(
                PreparationByteDelta(
                    ea=before_row.ea,
                    ida_original=before_row.ida_original,
                    before_is_patched=True,
                    before_value=before_row.current_value,
                    after_is_patched=True,
                    after_value=after_row.current_value,
                )
            )
        before_index += 1
        after_index += 1

    return tuple(deltas)


class IdaPatchLedger:
    """Read-only adapter over :func:`ida_bytes.visit_patched_bytes`."""

    def capture(self) -> tuple[PreparationPatchRow, ...]:
        import ida_bytes
        import ida_idaapi

        rows: list[PreparationPatchRow] = []

        def _visit(ea: int, file_position: int, original: int, current: int) -> int:
            rows.append(
                PreparationPatchRow(
                    ea=int(ea),
                    file_position=int(file_position),
                    ida_original=int(original) & 0xFF,
                    current_value=int(current) & 0xFF,
                )
            )
            return 0

        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, _visit)
        return _rows_by_ea(tuple(rows), side="captured")
