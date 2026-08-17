from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_bytes = pytest.importorskip("ida_bytes")

from d810.backends.ida.idb_preparation.patch_ledger import (  # noqa: E402
    IdaPatchLedger,
    derive_patch_delta,
)


def test_patch_ledger_round_trips_pristine_and_inherited_patch_states(
    copy_of_idb,
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    inherited = original ^ 0x01
    replacement = original ^ 0x02
    ledger = IdaPatchLedger()

    before = ledger.capture()
    assert before == ()

    try:
        assert ida_bytes.patch_byte(ea, inherited)
        inherited_rows = ledger.capture()
        inherited_row = next(row for row in inherited_rows if row.ea == ea)
        assert inherited_row.ida_original == original
        assert inherited_row.current_value == inherited
        assert derive_patch_delta(before, inherited_rows)[0].restore_with_revert

        assert ida_bytes.patch_byte(ea, replacement)
        replacement_rows = ledger.capture()
        replacement_delta = derive_patch_delta(inherited_rows, replacement_rows)
        assert replacement_delta[0].before_is_patched
        assert replacement_delta[0].before_value == inherited
        assert replacement_delta[0].after_value == replacement

        assert ida_bytes.revert_byte(ea)
        reverted_rows = ledger.capture()
        assert all(row.ea != ea for row in reverted_rows)
        reverted_delta = derive_patch_delta(replacement_rows, reverted_rows)
        assert reverted_delta[0].after_is_patched is False
        assert reverted_delta[0].after_value == original
    finally:
        ida_bytes.revert_byte(ea)
