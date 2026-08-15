from __future__ import annotations

from dataclasses import replace

import pytest

from d810.ir.native_range_projection import (
    CtreeNativeRangeProjection,
    CtreeStatementNativeRanges,
    NativeRange,
)

pytestmark = pytest.mark.pure_python


def _statement(
    index: int,
    *,
    op: int = 71,
    representative_ea: int | None = 0x1010,
    ranges: tuple[NativeRange, ...] = (NativeRange(0x1010, 0x1018),),
) -> CtreeStatementNativeRanges:
    return CtreeStatementNativeRanges(index, op, representative_ea, ranges)


def _projection(**overrides: object) -> CtreeNativeRangeProjection:
    values: dict[str, object] = {
        "function_ea": 0x1000,
        "function_ranges": (
            NativeRange(0x1000, 0x1100),
            NativeRange(0x1200, 0x1240),
        ),
        "statements": (_statement(1),),
        "ea_to_statement_indices": ((0x1010, (1,)),),
    }
    values.update(overrides)
    return CtreeNativeRangeProjection(**values)  # type: ignore[arg-type]


def test_native_range_is_nonempty_and_half_open() -> None:
    assert NativeRange(0x1000, 0x1002).length == 2
    assert NativeRange(0x1000, 0x1002).contains(0x1001)
    assert not NativeRange(0x1000, 0x1002).contains(0x1002)
    with pytest.raises(ValueError, match="end_ea"):
        NativeRange(0x1000, 0x1000)


def test_projection_preserves_disjoint_ranges_and_shared_ownership() -> None:
    first = _statement(
        7,
        representative_ea=0x1010,
        ranges=(NativeRange(0x1020, 0x1024), NativeRange(0x1010, 0x1014)),
    )
    second = _statement(
        3,
        representative_ea=0x1010,
        ranges=(NativeRange(0x1010, 0x1014),),
    )

    projection = _projection(
        statements=(first, second),
        ea_to_statement_indices=((0x1010, (7, 3, 7)),),
    )

    assert tuple(row.citem_index for row in projection.statements) == (3, 7)
    assert projection.statements[1].ranges == (
        NativeRange(0x1010, 0x1014),
        NativeRange(0x1020, 0x1024),
    )
    assert projection.ea_to_statement_indices == ((0x1010, (3, 7)),)


def test_projection_retains_statement_without_representative_ea() -> None:
    statement = _statement(4, representative_ea=None, ranges=())
    projection = _projection(statements=(statement,), ea_to_statement_indices=())

    assert projection.statements == (statement,)


def test_projection_rejects_statement_range_outside_function_chunks() -> None:
    with pytest.raises(ValueError, match="function_ranges"):
        _projection(statements=(_statement(1, ranges=(NativeRange(0x10F0, 0x1210),)),))


def test_projection_rejects_conflicting_duplicate_statement_identity() -> None:
    with pytest.raises(ValueError, match="citem_index"):
        _projection(statements=(_statement(1), _statement(1, op=72)))


def test_projection_rejects_reverse_map_to_unknown_statement() -> None:
    with pytest.raises(ValueError, match="unknown statement"):
        _projection(ea_to_statement_indices=((0x1010, (99,)),))


def test_projection_fingerprint_is_deterministic_and_content_bound() -> None:
    projection = _projection()
    reordered = _projection(
        function_ranges=tuple(reversed(projection.function_ranges)),
        statements=tuple(reversed(projection.statements)),
        ea_to_statement_indices=tuple(reversed(projection.ea_to_statement_indices)),
    )

    assert projection.fingerprint == reordered.fingerprint
    assert (
        replace(
            projection,
            statements=(_statement(1, op=99),),
            fingerprint="",
        ).fingerprint
        != projection.fingerprint
    )
    assert (
        replace(
            projection,
            ea_to_statement_indices=((0x1011, (1,)),),
            fingerprint="",
        ).fingerprint
        != projection.fingerprint
    )


def test_projection_rejects_incorrect_caller_fingerprint() -> None:
    with pytest.raises(ValueError, match="fingerprint"):
        _projection(fingerprint="not-the-content-hash")
