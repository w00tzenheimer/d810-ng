from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.backends.hexrays.ctree_native_ranges import (
    CtreeNativeRangeCaptureError,
    capture_ctree_native_ranges,
)
from d810.ir.native_range_projection import NativeRange

pytestmark = pytest.mark.pure_python

BADADDR = (1 << 64) - 1


@dataclass(frozen=True)
class _Range:
    start_ea: int
    end_ea: int


@dataclass(frozen=True)
class _Insn:
    index: int
    op: int
    ea: int


class _RangeSet:
    def __init__(self, *ranges: _Range) -> None:
        self._ranges = ranges

    def nranges(self) -> int:
        return len(self._ranges)

    def getrange(self, index: int) -> _Range:
        return self._ranges[index]


class _Cfunc:
    def __init__(
        self,
        *,
        boundaries: object,
        eamap: object,
        entry_ea: int = 0x1000,
    ) -> None:
        self.entry_ea = entry_ea
        self._boundaries = boundaries
        self._eamap = eamap
        self.printed = False

    def get_pseudocode(self) -> tuple[str, ...]:
        self.printed = True
        return ("return 0;",)

    def get_boundaries(self) -> object:
        assert self.printed
        return self._boundaries

    def get_eamap(self) -> object:
        assert self.printed
        return self._eamap


class _Epilog:
    def is_epilog(self) -> bool:
        return True

    def __getattr__(self, name: str) -> object:
        raise ValueError(f"invalid INS_EPILOG access: {name}")


def _capture(cfunc: object):
    return capture_ctree_native_ranges(
        cfunc,
        function_ranges=(
            NativeRange(0x1000, 0x1100),
            NativeRange(0x1200, 0x1240),
        ),
    )


def test_capture_preserves_disjoint_ranges_and_reverse_map() -> None:
    insn = _Insn(index=7, op=71, ea=0x1010)
    cfunc = _Cfunc(
        boundaries={insn: _RangeSet(_Range(0x1010, 0x1014), _Range(0x1020, 0x1024))},
        eamap={0x1010: (insn,), 0x1020: (insn,)},
    )

    projection = _capture(cfunc)

    assert cfunc.printed is True
    assert projection.statements[0].ranges == (
        NativeRange(0x1010, 0x1014),
        NativeRange(0x1020, 0x1024),
    )
    assert projection.ea_to_statement_indices == (
        (0x1010, (7,)),
        (0x1020, (7,)),
    )


def test_capture_preserves_shared_statement_ownership() -> None:
    first = _Insn(index=3, op=71, ea=0x1010)
    second = _Insn(index=4, op=72, ea=0x1010)
    shared = _RangeSet(_Range(0x1010, 0x1014))

    projection = _capture(
        _Cfunc(
            boundaries={first: shared, second: shared},
            eamap={0x1010: (second, first)},
        )
    )

    assert projection.ea_to_statement_indices == ((0x1010, (3, 4)),)
    assert tuple(item.citem_index for item in projection.statements) == (3, 4)


def test_capture_normalizes_badaddr_and_retains_eamap_only_statement() -> None:
    synthetic = _Insn(index=9, op=73, ea=BADADDR)

    projection = _capture(_Cfunc(boundaries={}, eamap={0x1010: (synthetic,)}))

    assert projection.statements[0].representative_ea is None
    assert projection.statements[0].ranges == ()
    assert projection.ea_to_statement_indices == ((0x1010, (9,)),)


def test_capture_excludes_hexrays_epilog_sentinel() -> None:
    insn = _Insn(index=1, op=71, ea=0x1010)
    projection = _capture(
        _Cfunc(
            boundaries={
                _Epilog(): _RangeSet(_Range(0x10F0, 0x1100)),
                insn: _RangeSet(_Range(0x1010, 0x1014)),
            },
            eamap={0x1010: (insn,)},
        )
    )

    assert tuple(row.citem_index for row in projection.statements) == (1,)


def test_capture_rejects_boundary_outside_function_chunks() -> None:
    insn = _Insn(index=1, op=71, ea=0x1010)
    with pytest.raises(ValueError, match="function_ranges"):
        _capture(
            _Cfunc(
                boundaries={insn: _RangeSet(_Range(0x10F0, 0x1210))},
                eamap={0x1010: (insn,)},
            )
        )


@pytest.mark.parametrize("field", ["boundaries", "eamap"])
def test_capture_rejects_missing_mapping(field: str) -> None:
    values = {"boundaries": {}, "eamap": {}}
    values[field] = None

    with pytest.raises(CtreeNativeRangeCaptureError, match=field):
        _capture(_Cfunc(**values))


def test_capture_returns_only_portable_values() -> None:
    insn = _Insn(index=1, op=71, ea=0x1010)
    projection = _capture(
        _Cfunc(
            boundaries={insn: [_Range(0x1010, 0x1014)]},
            eamap={0x1010: [insn]},
        )
    )

    assert projection.statements[0].__class__.__module__ == (
        "d810.ir.native_range_projection"
    )
    assert not hasattr(projection, "cfunc")
