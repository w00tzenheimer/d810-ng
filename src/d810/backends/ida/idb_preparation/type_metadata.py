"""Interference-safe exact type apply/restore for preparation transactions."""

from __future__ import annotations

from d810.backends.ida.type_serialization import (
    SerializedTinfoParts,
    apply_serialized_tinfo,
    capture_serialized_tinfo,
)
from d810.capabilities.idb_preparation import SerializedTypeSnapshot
from d810.core.typing import Callable

__all__ = ["IdaTypeMetadata", "TypeMetadataInterference"]

SnapshotCapture = Callable[[int], SerializedTypeSnapshot]
SnapshotApply = Callable[[int, SerializedTypeSnapshot], bool]


class TypeMetadataInterference(RuntimeError):
    """The live type no longer equals the transaction's expected image."""


def _capture_snapshot(item_ea: int) -> SerializedTypeSnapshot:
    parts = capture_serialized_tinfo(item_ea)
    if parts is None:
        return SerializedTypeSnapshot.absent()
    return SerializedTypeSnapshot.from_parts(
        parts.type_bytes,
        parts.field_bytes,
        parts.field_comment_bytes,
    )


def _apply_snapshot(item_ea: int, snapshot: SerializedTypeSnapshot) -> bool:
    parts = None
    if snapshot.present:
        assert snapshot.type_bytes is not None
        parts = SerializedTinfoParts(
            snapshot.type_bytes,
            snapshot.field_bytes,
            snapshot.field_comment_bytes,
        )
    return apply_serialized_tinfo(item_ea, parts)


class IdaTypeMetadata:
    """Exact type adapter with injectable pure functions for unit tests."""

    def __init__(
        self,
        *,
        capture_snapshot: SnapshotCapture = _capture_snapshot,
        apply_snapshot: SnapshotApply = _apply_snapshot,
    ) -> None:
        self._capture_snapshot = capture_snapshot
        self._apply_snapshot = apply_snapshot

    def capture(self, item_ea: int) -> SerializedTypeSnapshot:
        return self._capture_snapshot(int(item_ea))

    def _replace(
        self,
        item_ea: int,
        expected: SerializedTypeSnapshot,
        replacement: SerializedTypeSnapshot,
        *,
        expected_label: str,
    ) -> None:
        live = self.capture(item_ea)
        if live != expected:
            raise TypeMetadataInterference(
                f"type {expected_label} mismatch at {item_ea:#x}"
            )
        if not self._apply_snapshot(int(item_ea), replacement):
            raise RuntimeError(f"failed to apply exact type at {item_ea:#x}")
        if self.capture(item_ea) != replacement:
            raise RuntimeError(f"type readback mismatch at {item_ea:#x}")

    def apply(
        self,
        item_ea: int,
        expected_before: SerializedTypeSnapshot,
        replacement: SerializedTypeSnapshot,
    ) -> None:
        self._replace(
            item_ea,
            expected_before,
            replacement,
            expected_label="before-image",
        )

    def restore(
        self,
        item_ea: int,
        expected_after: SerializedTypeSnapshot,
        original: SerializedTypeSnapshot,
    ) -> None:
        self._replace(
            item_ea,
            expected_after,
            original,
            expected_label="after-image",
        )
