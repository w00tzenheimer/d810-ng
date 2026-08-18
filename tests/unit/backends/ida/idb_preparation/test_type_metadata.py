from __future__ import annotations

import pytest

from d810.backends.ida.idb_preparation.type_metadata import (
    IdaTypeMetadata,
    TypeMetadataInterference,
)
from d810.capabilities.idb_preparation import SerializedTypeSnapshot

pytestmark = pytest.mark.pure_python


class _Types:
    def __init__(self, snapshot: SerializedTypeSnapshot) -> None:
        self.snapshot = snapshot
        self.applied: list[SerializedTypeSnapshot] = []

    def capture(self, item_ea: int) -> SerializedTypeSnapshot:
        return self.snapshot

    def apply(self, item_ea: int, snapshot: SerializedTypeSnapshot) -> bool:
        self.applied.append(snapshot)
        self.snapshot = snapshot
        return True


def _present(tag: bytes) -> SerializedTypeSnapshot:
    return SerializedTypeSnapshot.from_parts(
        b"type-" + tag,
        b"fields-" + tag,
        b"comments-" + tag,
    )


def test_restore_deletes_d810_created_type() -> None:
    before = SerializedTypeSnapshot.absent()
    after = _present(b"const-array")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    adapter.apply(0x500000, before, after)
    adapter.restore(0x500000, after, before)

    assert adapter.capture(0x500000) == before
    assert types.applied == [after, before]


def test_existing_three_component_type_round_trips_exactly() -> None:
    before = _present(b"struct")
    after = _present(b"const-struct")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    adapter.apply(0x500000, before, after)
    adapter.restore(0x500000, after, before)

    assert adapter.capture(0x500000).parts == before.parts


def test_apply_refuses_live_type_divergence_before_writing() -> None:
    expected = _present(b"expected")
    live = _present(b"user")
    types = _Types(live)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    with pytest.raises(TypeMetadataInterference, match="before-image"):
        adapter.apply(0x500000, expected, _present(b"const"))

    assert types.applied == []


def test_restore_refuses_user_edit_after_apply() -> None:
    before = _present(b"before")
    after = _present(b"after")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )
    adapter.apply(0x500000, before, after)
    user_edit = _present(b"user-edit")
    types.snapshot = user_edit

    with pytest.raises(TypeMetadataInterference, match="after-image"):
        adapter.restore(0x500000, after, before)

    assert types.snapshot == user_edit


def test_failed_backend_apply_never_reports_success() -> None:
    before = SerializedTypeSnapshot.absent()
    after = _present(b"const")
    adapter = IdaTypeMetadata(
        capture_snapshot=lambda ea: before,
        apply_snapshot=lambda ea, snapshot: False,
    )

    with pytest.raises(RuntimeError, match="failed to apply"):
        adapter.apply(0x500000, before, after)
