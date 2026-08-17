from __future__ import annotations

import pytest

from d810.capabilities.idb_preparation import (
    IllegalPreparationTransition,
    PreparationByteDelta,
    PreparationPatchRow,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTransactionId,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
    allowed_preparation_transition,
    legal_next_preparation_states,
)

pytestmark = pytest.mark.pure_python


def test_byte_delta_preserves_inherited_patch_before_image() -> None:
    delta = PreparationByteDelta(
        ea=0x401000,
        ida_original=0x75,
        before_is_patched=True,
        before_value=0x74,
        after_is_patched=True,
        after_value=0xEB,
    )

    assert delta.restore_with_revert is False
    assert delta.restore_value == 0x74


def test_byte_delta_reverts_byte_that_was_pristine_before() -> None:
    delta = PreparationByteDelta(
        ea=0x401000,
        ida_original=0x75,
        before_is_patched=False,
        before_value=0x75,
        after_is_patched=True,
        after_value=0xEB,
    )

    assert delta.restore_with_revert is True
    assert delta.restore_value == 0x75


def test_byte_delta_rejects_inconsistent_pristine_before_value() -> None:
    with pytest.raises(ValueError, match="pristine before_value"):
        PreparationByteDelta(
            ea=0x401000,
            ida_original=0x75,
            before_is_patched=False,
            before_value=0x74,
            after_is_patched=True,
            after_value=0xEB,
        )


@pytest.mark.parametrize("field", ("ida_original", "before_value", "after_value"))
@pytest.mark.parametrize("value", (-1, 256, True))
def test_byte_delta_rejects_non_byte_values(field: str, value: object) -> None:
    values: dict[str, object] = {
        "ea": 0x401000,
        "ida_original": 0x75,
        "before_is_patched": False,
        "before_value": 0x75,
        "after_is_patched": True,
        "after_value": 0xEB,
    }
    values[field] = value

    with pytest.raises((TypeError, ValueError)):
        PreparationByteDelta(**values)  # type: ignore[arg-type]


def test_patch_row_requires_non_negative_address() -> None:
    with pytest.raises(ValueError, match="ea must be non-negative"):
        PreparationPatchRow(
            ea=-1,
            file_position=0,
            ida_original=0x75,
            current_value=0xEB,
        )


def test_absent_type_snapshot_has_no_serialized_components() -> None:
    snapshot = SerializedTypeSnapshot.absent()

    assert snapshot.present is False
    assert snapshot.parts is None


def test_present_type_snapshot_preserves_all_serialized_components() -> None:
    snapshot = SerializedTypeSnapshot.from_parts(
        b"\x0c\x70",
        b"fields",
        b"comments",
    )

    assert snapshot.present is True
    assert snapshot.parts == (b"\x0c\x70", b"fields", b"comments")


def test_absent_type_snapshot_rejects_serialized_components() -> None:
    with pytest.raises(ValueError, match="absent type"):
        SerializedTypeSnapshot(
            present=False,
            type_bytes=b"\x0c",
            field_bytes=None,
            field_comment_bytes=None,
        )


def test_present_type_snapshot_requires_nonempty_type_bytes() -> None:
    with pytest.raises(ValueError, match="non-empty type_bytes"):
        SerializedTypeSnapshot(
            present=True,
            type_bytes=b"",
            field_bytes=None,
            field_comment_bytes=None,
        )


def test_type_delta_rejects_identical_before_and_after() -> None:
    snapshot = SerializedTypeSnapshot.from_parts(b"\x0c", None, None)

    with pytest.raises(ValueError, match="must change the type"):
        PreparationTypeDelta(item_ea=0x500000, before=snapshot, after=snapshot)


def test_script_descriptor_validates_sha256() -> None:
    with pytest.raises(ValueError, match="source_sha256"):
        PreparationScriptDescriptor(
            script_id="normalize",
            display_name="Normalize dispatcher",
            path="scripts/normalize.py",
            source_sha256="not-a-hash",
            enabled=True,
            portable=True,
        )


def test_transaction_identity_is_nonempty_and_unique() -> None:
    first = PreparationTransactionId.new()
    second = PreparationTransactionId.new()

    assert first.value
    assert second.value
    assert first != second


def test_idb_prepared_may_only_enter_restore_lane() -> None:
    assert allowed_preparation_transition(
        PreparationState.IDB_PREPARED,
        PreparationState.RESTORING,
    )
    assert not allowed_preparation_transition(
        PreparationState.IDB_PREPARED,
        PreparationState.SCRIPT_RUNNING,
    )
    assert legal_next_preparation_states(PreparationState.IDB_PREPARED) == frozenset(
        {PreparationState.RESTORING}
    )


def test_script_running_can_enter_capture_or_rollback_lanes() -> None:
    assert legal_next_preparation_states(PreparationState.SCRIPT_RUNNING) == frozenset(
        {
            PreparationState.CAPTURE_PENDING,
            PreparationState.ROLLING_BACK,
            PreparationState.RECOVERY_REQUIRED,
        }
    )


def test_illegal_transition_names_both_states() -> None:
    error = IllegalPreparationTransition(
        PreparationState.IDB_PREPARED,
        PreparationState.SCRIPT_RUNNING,
    )

    assert "idb_prepared" in str(error)
    assert "script_running" in str(error)
