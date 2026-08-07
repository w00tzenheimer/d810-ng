"""``safe_make_number`` must never hand Hex-Rays a size it cannot store.

``mop_t::make_number`` keeps the constant in a 64-bit ``mnumber_t`` and accepts
only 1/2/4/8 (hexrays.hpp:2755). A larger size makes Hex-Rays clamp to 8 and
widen through a synthesized ``m_xds`` sub-instruction, which needs a real
instruction address; with the default ``BADADDR`` it raises INTERR 51617. This
lives in system/runtime because ``mop_utils`` imports ``ida_hexrays``.
"""

from __future__ import annotations

import pytest

from d810.hexrays.ir.mop_utils import safe_make_number


class _RecordingMop:
    """Capture what would reach the real ``mop_t::make_number``."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def make_number(self, value, size, *rest) -> None:
        self.calls.append((value, size, *rest))


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_storable_sizes_pass_through_untouched(size: int) -> None:
    mop = _RecordingMop()

    safe_make_number(mop, 0xDEADBEEFCAFEBABE, size)

    value, applied_size = mop.calls[0][:2]
    assert applied_size == size
    assert value == 0xDEADBEEFCAFEBABE & ((1 << (size * 8)) - 1)


def test_size_16_without_an_anchor_is_clamped_not_forwarded() -> None:
    """The INTERR 51617 regression: 16 with no ea used to reach make_number."""
    mop = _RecordingMop()

    safe_make_number(mop, 0xFFFFFFFFFFFFFFFFFFFF, 16)

    assert len(mop.calls) == 1
    value, applied_size = mop.calls[0][:2]
    assert applied_size == 8
    assert value == 0xFFFFFFFFFFFFFFFF
    assert len(mop.calls[0]) == 2, "clamped call must not invent an anchor ea"


def test_size_16_with_an_anchor_keeps_the_width_and_passes_the_ea() -> None:
    mop = _RecordingMop()

    safe_make_number(mop, 0x11112222333344445555, 16, ea=0x7FFFBD0ABF40)

    value, applied_size, anchor = mop.calls[0]
    assert applied_size == 16
    assert anchor == 0x7FFFBD0ABF40
    assert value == 0x11112222333344445555 & ((1 << 128) - 1)


def test_badaddr_anchor_is_treated_as_no_anchor() -> None:
    mop = _RecordingMop()

    safe_make_number(mop, 1, 16, ea=0xFFFFFFFFFFFFFFFF)

    assert mop.calls[0][1] == 8
    assert len(mop.calls[0]) == 2


def test_invalid_size_still_falls_back_to_four() -> None:
    mop = _RecordingMop()

    safe_make_number(mop, 0xAABBCCDD, 0)

    assert mop.calls[0][1] == 4


def test_return_value_reports_whether_the_requested_width_survived() -> None:
    """Callers emitting m_ldc rely on this to abstain instead of malforming.

    The live case: a peephole folded `xds #0.8, xmm6.16` into
    `ldc #0.8, xmm6.16`, whose operand sizes disagree, because the clamp was
    silent. m_ldc's l operand must be a real mop_n and make_number cannot build
    one wider than 8 bytes, so the rule has to decline.
    """
    assert safe_make_number(_RecordingMop(), 0xFF, 4) is True
    assert safe_make_number(_RecordingMop(), 0xFF, 8) is True
    assert safe_make_number(_RecordingMop(), 0xFF, 16) is False
    assert safe_make_number(_RecordingMop(), 0xFF, 16, ea=0x401000) is True


def test_an_invalid_size_that_falls_back_to_four_is_not_reported_as_honored() -> None:
    assert safe_make_number(_RecordingMop(), 0xFF, 0) is False


def test_no_size_above_eight_can_ever_reach_make_number_unanchored() -> None:
    """Guard the whole class, not just 16, in case _VALID_MOP_SIZES grows."""
    for size in (1, 2, 4, 8, 16, 32, 64, 0, -1, 3):
        mop = _RecordingMop()
        safe_make_number(mop, 0x1234, size)
        applied_size = mop.calls[0][1]
        assert applied_size <= 8, f"size {size} forwarded {applied_size} unanchored"
