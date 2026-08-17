"""Portable contracts for reversible pre-Hex-Rays IDB preparation.

This module deliberately contains no IDA, SQLite, or UI imports.  It defines
the immutable values shared by the preparation controller, the IDA adapters,
and the durable transaction store.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from uuid import uuid4

from d810.core.execution_journal import ExecutionAttemptId
from d810.core.typing import Protocol

__all__ = [
    "IllegalPreparationTransition",
    "PreparationDeclaredByteBaseline",
    "PreparationByteDelta",
    "PreparationPatchRow",
    "PreparationRunRequest",
    "PreparationScriptDescriptor",
    "PreparationState",
    "PreparationTransactionId",
    "PreparationTransactionRecord",
    "PreparationTransactionStore",
    "PreparationTypeDelta",
    "SerializedTypeSnapshot",
    "allowed_preparation_transition",
    "legal_next_preparation_states",
]


def _require_identifier(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


def _require_non_negative_int(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an int")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")


def _require_byte(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an int")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{label} must be in the range 0..255")


@dataclass(frozen=True, slots=True)
class PreparationTransactionId:
    """Globally unique identity for one preparation transaction."""

    value: str

    def __post_init__(self) -> None:
        _require_identifier(self.value, "value")

    @classmethod
    def new(cls) -> PreparationTransactionId:
        return cls(value=uuid4().hex)


class PreparationState(str, enum.Enum):
    """Durable lifecycle for one preparation transaction."""

    PREPARED = "prepared"
    SCRIPT_RUNNING = "script_running"
    CAPTURE_PENDING = "capture_pending"
    CAPTURED = "captured"
    ANALYSIS_PENDING = "analysis_pending"
    IDB_PREPARED = "idb_prepared"
    RESTORING = "restoring"
    ROLLING_BACK = "rolling_back"
    RESTORED = "restored"
    RESTORE_FAILED = "restore_failed"
    RECOVERY_REQUIRED = "recovery_required"
    REJECTED = "rejected"
    FAILED = "failed"


_LEGAL_TRANSITIONS: dict[PreparationState, frozenset[PreparationState]] = {
    PreparationState.PREPARED: frozenset(
        {
            PreparationState.SCRIPT_RUNNING,
            PreparationState.REJECTED,
            PreparationState.FAILED,
        }
    ),
    PreparationState.SCRIPT_RUNNING: frozenset(
        {
            PreparationState.CAPTURE_PENDING,
            PreparationState.ROLLING_BACK,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.CAPTURE_PENDING: frozenset(
        {
            PreparationState.CAPTURED,
            PreparationState.FAILED,
            PreparationState.ROLLING_BACK,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.CAPTURED: frozenset(
        {
            PreparationState.ANALYSIS_PENDING,
            PreparationState.ROLLING_BACK,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.ANALYSIS_PENDING: frozenset(
        {
            PreparationState.IDB_PREPARED,
            PreparationState.ROLLING_BACK,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.IDB_PREPARED: frozenset({PreparationState.RESTORING}),
    PreparationState.RESTORING: frozenset(
        {
            PreparationState.RESTORED,
            PreparationState.RESTORE_FAILED,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.ROLLING_BACK: frozenset(
        {
            PreparationState.RESTORED,
            PreparationState.RESTORE_FAILED,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.RESTORE_FAILED: frozenset(
        {
            PreparationState.RESTORING,
            PreparationState.RECOVERY_REQUIRED,
        }
    ),
    PreparationState.RECOVERY_REQUIRED: frozenset(
        {PreparationState.RESTORING, PreparationState.ROLLING_BACK}
    ),
    PreparationState.RESTORED: frozenset(),
    PreparationState.REJECTED: frozenset(),
    PreparationState.FAILED: frozenset(),
}


def legal_next_preparation_states(
    current: PreparationState,
) -> frozenset[PreparationState]:
    if not isinstance(current, PreparationState):
        raise TypeError("current must be a PreparationState")
    return _LEGAL_TRANSITIONS[current]


def allowed_preparation_transition(
    current: PreparationState,
    target: PreparationState,
) -> bool:
    if not isinstance(target, PreparationState):
        raise TypeError("target must be a PreparationState")
    return target in legal_next_preparation_states(current)


class IllegalPreparationTransition(ValueError):
    """Raised when a transaction attempts to cross a closed lifecycle edge."""

    def __init__(self, current: PreparationState, target: PreparationState) -> None:
        self.current = current
        self.target = target
        super().__init__(
            f"illegal preparation transition: {current.value} -> {target.value}"
        )


@dataclass(frozen=True, slots=True)
class PreparationScriptDescriptor:
    """Stable identity and source attestation for one preparation script."""

    script_id: str
    display_name: str
    path: str
    source_sha256: str
    enabled: bool
    portable: bool

    def __post_init__(self) -> None:
        _require_identifier(self.script_id, "script_id")
        _require_identifier(self.display_name, "display_name")
        _require_identifier(self.path, "path")
        if (
            not isinstance(self.source_sha256, str)
            or len(self.source_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.source_sha256
            )
        ):
            raise ValueError(
                "source_sha256 must be 64 lowercase hexadecimal characters"
            )
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a bool")
        if not isinstance(self.portable, bool):
            raise TypeError("portable must be a bool")


@dataclass(frozen=True, slots=True)
class PreparationPatchRow:
    """One row from IDA's patched-byte ledger."""

    ea: int
    file_position: int
    ida_original: int
    current_value: int

    def __post_init__(self) -> None:
        _require_non_negative_int(self.ea, "ea")
        if isinstance(self.file_position, bool) or not isinstance(
            self.file_position, int
        ):
            raise TypeError("file_position must be an int")
        if self.file_position < -1:
            raise ValueError("file_position must be -1 or non-negative")
        _require_byte(self.ida_original, "ida_original")
        _require_byte(self.current_value, "current_value")


@dataclass(frozen=True, slots=True)
class PreparationByteDelta:
    """Exact before/after patch status and values for one changed byte."""

    ea: int
    ida_original: int
    before_is_patched: bool
    before_value: int
    after_is_patched: bool
    after_value: int

    def __post_init__(self) -> None:
        _require_non_negative_int(self.ea, "ea")
        _require_byte(self.ida_original, "ida_original")
        _require_byte(self.before_value, "before_value")
        _require_byte(self.after_value, "after_value")
        if not isinstance(self.before_is_patched, bool):
            raise TypeError("before_is_patched must be a bool")
        if not isinstance(self.after_is_patched, bool):
            raise TypeError("after_is_patched must be a bool")
        if not self.before_is_patched and self.before_value != self.ida_original:
            raise ValueError("pristine before_value must equal ida_original")
        if not self.after_is_patched and self.after_value != self.ida_original:
            raise ValueError("pristine after_value must equal ida_original")
        if (
            self.before_is_patched == self.after_is_patched
            and self.before_value == self.after_value
        ):
            raise ValueError("byte delta must change patch status or value")

    @property
    def restore_with_revert(self) -> bool:
        return not self.before_is_patched

    @property
    def restore_value(self) -> int:
        return self.before_value


@dataclass(frozen=True, slots=True)
class PreparationDeclaredByteBaseline:
    """Durable before-image for one byte in a script-declared range."""

    ea: int
    ida_original: int
    before_is_patched: bool
    before_value: int

    def __post_init__(self) -> None:
        _require_non_negative_int(self.ea, "ea")
        _require_byte(self.ida_original, "ida_original")
        _require_byte(self.before_value, "before_value")
        if not isinstance(self.before_is_patched, bool):
            raise TypeError("before_is_patched must be a bool")
        if not self.before_is_patched and self.before_value != self.ida_original:
            raise ValueError("pristine before_value must equal ida_original")


@dataclass(frozen=True, slots=True)
class SerializedTypeSnapshot:
    """Lossless portable form of IDA's three-component serialized type."""

    present: bool
    type_bytes: bytes | None
    field_bytes: bytes | None
    field_comment_bytes: bytes | None

    def __post_init__(self) -> None:
        if not isinstance(self.present, bool):
            raise TypeError("present must be a bool")
        components = (self.type_bytes, self.field_bytes, self.field_comment_bytes)
        if any(
            value is not None and not isinstance(value, bytes) for value in components
        ):
            raise TypeError("serialized type components must be bytes or None")
        if not self.present:
            if any(value is not None for value in components):
                raise ValueError("absent type must not carry serialized components")
            return
        if not self.type_bytes:
            raise ValueError("present type requires non-empty type_bytes")

    @classmethod
    def absent(cls) -> SerializedTypeSnapshot:
        return cls(False, None, None, None)

    @classmethod
    def from_parts(
        cls,
        type_bytes: bytes,
        field_bytes: bytes | None,
        field_comment_bytes: bytes | None,
    ) -> SerializedTypeSnapshot:
        return cls(True, type_bytes, field_bytes, field_comment_bytes)

    @property
    def parts(self) -> tuple[bytes, bytes | None, bytes | None] | None:
        if not self.present:
            return None
        assert self.type_bytes is not None
        return (self.type_bytes, self.field_bytes, self.field_comment_bytes)


@dataclass(frozen=True, slots=True)
class PreparationTypeDelta:
    """Exact before/after serialized type for one item head."""

    item_ea: int
    before: SerializedTypeSnapshot
    after: SerializedTypeSnapshot

    def __post_init__(self) -> None:
        _require_non_negative_int(self.item_ea, "item_ea")
        if not isinstance(self.before, SerializedTypeSnapshot):
            raise TypeError("before must be a SerializedTypeSnapshot")
        if not isinstance(self.after, SerializedTypeSnapshot):
            raise TypeError("after must be a SerializedTypeSnapshot")
        if self.before == self.after:
            raise ValueError("type delta must change the type")


@dataclass(frozen=True, slots=True)
class PreparationRunRequest:
    """Portable authority required to prepare a transaction."""

    database_identity: str
    anchor_function_ea: int
    script: PreparationScriptDescriptor
    authorizing_attempt_id: ExecutionAttemptId

    def __post_init__(self) -> None:
        _require_identifier(self.database_identity, "database_identity")
        _require_non_negative_int(self.anchor_function_ea, "anchor_function_ea")
        if not isinstance(self.script, PreparationScriptDescriptor):
            raise TypeError("script must be a PreparationScriptDescriptor")
        if not isinstance(self.authorizing_attempt_id, ExecutionAttemptId):
            raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")


@dataclass(frozen=True, slots=True)
class PreparationTransactionRecord:
    """Durable portable projection of one preparation transaction."""

    transaction_id: PreparationTransactionId
    database_identity: str
    anchor_function_ea: int
    script_id: str
    script_path: str
    script_source_sha256: str
    authorizing_attempt_id: ExecutionAttemptId
    state: PreparationState
    created_at: float
    updated_at: float

    def __post_init__(self) -> None:
        if not isinstance(self.transaction_id, PreparationTransactionId):
            raise TypeError("transaction_id must be a PreparationTransactionId")
        _require_identifier(self.database_identity, "database_identity")
        _require_non_negative_int(self.anchor_function_ea, "anchor_function_ea")
        _require_identifier(self.script_id, "script_id")
        _require_identifier(self.script_path, "script_path")
        if len(self.script_source_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.script_source_sha256
        ):
            raise ValueError("script_source_sha256 must be a lowercase SHA-256")
        if not isinstance(self.authorizing_attempt_id, ExecutionAttemptId):
            raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")
        if not isinstance(self.state, PreparationState):
            raise TypeError("state must be a PreparationState")
        if isinstance(self.created_at, bool) or not isinstance(
            self.created_at, (int, float)
        ):
            raise TypeError("created_at must be numeric")
        if isinstance(self.updated_at, bool) or not isinstance(
            self.updated_at, (int, float)
        ):
            raise TypeError("updated_at must be numeric")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")


class PreparationTransactionStore(Protocol):
    """Durability boundary consumed by the preparation gateway."""

    def prepare(
        self,
        request: PreparationRunRequest,
        baseline_rows: tuple[PreparationPatchRow, ...],
    ) -> PreparationTransactionRecord: ...

    def transition(
        self,
        transaction_id: PreparationTransactionId,
        target: PreparationState,
        *,
        note: str | None = None,
    ) -> PreparationTransactionRecord: ...

    def get(
        self, transaction_id: PreparationTransactionId
    ) -> PreparationTransactionRecord | None: ...

    def baseline_rows(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationPatchRow, ...]: ...

    def record_byte_deltas(
        self,
        transaction_id: PreparationTransactionId,
        deltas: tuple[PreparationByteDelta, ...],
    ) -> None: ...

    def byte_deltas(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationByteDelta, ...]: ...

    def record_declared_byte_baselines(
        self,
        transaction_id: PreparationTransactionId,
        baselines: tuple[PreparationDeclaredByteBaseline, ...],
    ) -> None: ...

    def declared_byte_baselines(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationDeclaredByteBaseline, ...]: ...

    def record_type_deltas(
        self,
        transaction_id: PreparationTransactionId,
        deltas: tuple[PreparationTypeDelta, ...],
    ) -> None: ...

    def type_deltas(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationTypeDelta, ...]: ...

    def record_affected_functions(
        self,
        transaction_id: PreparationTransactionId,
        function_eas: tuple[int, ...],
    ) -> None: ...

    def affected_functions(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[int, ...]: ...

    def recoverable(
        self, database_identity: str
    ) -> tuple[PreparationTransactionRecord, ...]: ...

    def prepared(
        self, database_identity: str
    ) -> tuple[PreparationTransactionRecord, ...]: ...

    def transactions(
        self, database_identity: str
    ) -> tuple[PreparationTransactionRecord, ...]: ...

    def active_byte_ranges(
        self, database_identity: str
    ) -> tuple[tuple[int, int], ...]: ...

    def active_type_items(self, database_identity: str) -> tuple[int, ...]: ...
