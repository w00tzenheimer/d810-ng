from __future__ import annotations

import pytest

from d810.backends.ida.idb_preparation.patch_ledger import derive_patch_delta
from d810.capabilities.idb_preparation import PreparationByteDelta, PreparationPatchRow

pytestmark = pytest.mark.pure_python


def _row(
    ea: int,
    original: int,
    current: int,
    *,
    file_position: int = 0,
) -> PreparationPatchRow:
    return PreparationPatchRow(
        ea=ea,
        file_position=file_position,
        ida_original=original,
        current_value=current,
    )


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            (),
            (_row(0x10, 0x75, 0xEB),),
            PreparationByteDelta(0x10, 0x75, False, 0x75, True, 0xEB),
        ),
        (
            (_row(0x10, 0x75, 0x74),),
            (_row(0x10, 0x75, 0xEB),),
            PreparationByteDelta(0x10, 0x75, True, 0x74, True, 0xEB),
        ),
        (
            (_row(0x10, 0x75, 0x74),),
            (),
            PreparationByteDelta(0x10, 0x75, True, 0x74, False, 0x75),
        ),
    ],
)
def test_derive_patch_delta_covers_every_patch_state_transition(
    before: tuple[PreparationPatchRow, ...],
    after: tuple[PreparationPatchRow, ...],
    expected: PreparationByteDelta,
) -> None:
    assert derive_patch_delta(before, after) == (expected,)


def test_derive_patch_delta_omits_unchanged_patches() -> None:
    inherited = _row(0x10, 0x75, 0x74)

    assert derive_patch_delta((inherited,), (inherited,)) == ()


def test_derive_patch_delta_is_sorted_by_ea() -> None:
    after = (
        _row(0x20, 0x90, 0xCC),
        _row(0x10, 0x75, 0xEB),
    )

    assert tuple(delta.ea for delta in derive_patch_delta((), after)) == (
        0x10,
        0x20,
    )


@pytest.mark.parametrize("side", ("before", "after"))
def test_derive_patch_delta_rejects_duplicate_eas(side: str) -> None:
    duplicates = (
        _row(0x10, 0x75, 0x74),
        _row(0x10, 0x75, 0xEB),
    )

    with pytest.raises(ValueError, match=f"duplicate {side} patch EA"):
        derive_patch_delta(
            duplicates if side == "before" else (),
            duplicates if side == "after" else (),
        )


def test_derive_patch_delta_rejects_changed_original_byte() -> None:
    with pytest.raises(ValueError, match="original byte changed"):
        derive_patch_delta(
            (_row(0x10, 0x75, 0x74),),
            (_row(0x10, 0x76, 0xEB),),
        )
