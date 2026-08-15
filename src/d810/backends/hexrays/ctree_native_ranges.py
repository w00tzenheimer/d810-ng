"""Freeze live Hex-Rays C-tree address maps into portable range relations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from d810.ir.native_range_projection import (
    CtreeNativeRangeProjection,
    CtreeStatementNativeRanges,
    NativeRange,
)

__all__ = [
    "CtreeNativeRangeCaptureError",
    "capture_ctree_native_ranges",
]


class CtreeNativeRangeCaptureError(ValueError):
    """The live C-tree did not expose a complete portable mapping."""


def _badaddr() -> int:
    try:
        import ida_idaapi
    except ImportError:
        return (1 << 64) - 1
    return int(ida_idaapi.BADADDR)


def _is_epilog(insn: object) -> bool:
    predicate = getattr(insn, "is_epilog", None)
    if not callable(predicate):
        return False
    try:
        return bool(predicate())
    except (TypeError, ValueError) as exc:
        raise CtreeNativeRangeCaptureError(
            "could not classify a C-tree boundary key"
        ) from exc


def _mapping_items(value: object, field_name: str) -> list[tuple[object, object]]:
    if value is None:
        raise CtreeNativeRangeCaptureError(f"{field_name} mapping is unavailable")
    items = getattr(value, "items", None)
    if callable(items):
        return list(items())
    if isinstance(value, Mapping):
        return list(value.items())
    raise CtreeNativeRangeCaptureError(f"{field_name} mapping is not iterable")


def _iter_ranges(value: object) -> Iterable[object]:
    nranges = getattr(value, "nranges", None)
    getrange = getattr(value, "getrange", None)
    if callable(nranges) and callable(getrange):
        return tuple(getrange(index) for index in range(int(nranges())))
    if isinstance(value, Iterable):
        return value
    raise CtreeNativeRangeCaptureError("boundary rangeset is not iterable")


def _statement_parts(insn: object, badaddr: int) -> tuple[int, int, int | None]:
    try:
        index = int(getattr(insn, "index"))
        op = int(getattr(insn, "op"))
        ea = int(getattr(insn, "ea"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise CtreeNativeRangeCaptureError(
            "C-tree statement lacks a usable index, opcode, or EA"
        ) from exc
    return index, op, None if ea == badaddr else ea


def _portable_ranges(value: object) -> tuple[NativeRange, ...]:
    ranges: list[NativeRange] = []
    for item in _iter_ranges(value):
        try:
            ranges.append(
                NativeRange(
                    start_ea=int(getattr(item, "start_ea")),
                    end_ea=int(getattr(item, "end_ea")),
                )
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise CtreeNativeRangeCaptureError(
                "boundary rangeset contains a malformed range"
            ) from exc
    return tuple(ranges)


def capture_ctree_native_ranges(
    cfunc: object,
    *,
    function_ranges: tuple[NativeRange, ...],
) -> CtreeNativeRangeProjection:
    """Capture final C-tree statement boundaries without retaining SDK objects."""
    try:
        get_pseudocode = getattr(cfunc, "get_pseudocode")
        get_pseudocode()
        boundaries = getattr(cfunc, "get_boundaries")()
        eamap = getattr(cfunc, "get_eamap")()
        function_ea = int(getattr(cfunc, "entry_ea"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise CtreeNativeRangeCaptureError(
            "cfunc does not expose final pseudocode and address mappings"
        ) from exc

    boundary_items = _mapping_items(boundaries, "boundaries")
    eamap_items = _mapping_items(eamap, "eamap")
    badaddr = _badaddr()

    rows: dict[int, CtreeStatementNativeRanges] = {}
    for insn, rangeset in boundary_items:
        if _is_epilog(insn):
            continue
        index, op, representative_ea = _statement_parts(insn, badaddr)
        row = CtreeStatementNativeRanges(
            citem_index=index,
            statement_op=op,
            representative_ea=representative_ea,
            ranges=_portable_ranges(rangeset),
        )
        previous = rows.get(index)
        if previous is not None and previous != row:
            raise CtreeNativeRangeCaptureError(
                "one C-tree item index has conflicting boundary rows"
            )
        rows[index] = row

    reverse_rows: list[tuple[int, tuple[int, ...]]] = []
    for ea_value, instructions in eamap_items:
        try:
            ea = int(ea_value)
            instruction_items = tuple(instructions)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise CtreeNativeRangeCaptureError(
                "eamap contains a malformed row"
            ) from exc
        indices: list[int] = []
        for insn in instruction_items:
            if _is_epilog(insn):
                continue
            index, op, representative_ea = _statement_parts(insn, badaddr)
            indices.append(index)
            if index not in rows:
                rows[index] = CtreeStatementNativeRanges(
                    citem_index=index,
                    statement_op=op,
                    representative_ea=representative_ea,
                    ranges=(),
                )
        reverse_rows.append((ea, tuple(indices)))

    return CtreeNativeRangeProjection(
        function_ea=function_ea,
        function_ranges=function_ranges,
        statements=tuple(rows.values()),
        ea_to_statement_indices=tuple(reverse_rows),
    )
