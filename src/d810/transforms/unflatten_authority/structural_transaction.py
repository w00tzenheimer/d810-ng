"""Participant-owned structural partitions, independent of short codec sessions.

No structural comparison here grants permission. This owner exists from the
exact transaction attempt through commit/abort; observed storage is opened
only by the participant after its actual SDK lift.
"""

from __future__ import annotations

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.core.structural_identity import StructuralIdentityError, StructuralTable
from d810.core.typing import NamedTuple
from d810.ir.structural_identity import NATIVE_KEY_FIELDS
from d810.transforms.cfg_transaction import TransactionAttemptId


class StructuralTransactionCoordinates(NamedTuple):
    """Actual snapshot and gateway coordinates; absent execution epoch stays absent."""

    snapshot_id: str
    maturity: int
    gateway_generation: int
    execution_epoch: int | None
    evidence_generation: int


class StructuralTransactionContext:
    """Own source/projected/observed values for one exact attempt occurrence."""

    __slots__ = (
        "_attempt",
        "_attempt_fields",
        "_native",
        "_coordinates",
        "_source",
        "_projected",
        "_observed",
        "_closed",
    )

    def __init__(
        self,
        attempt: TransactionAttemptId,
        native: NativePreanalysisKey,
        coordinates: StructuralTransactionCoordinates,
    ) -> None:
        if type(attempt) is not TransactionAttemptId:
            raise TypeError("structural transaction requires exact attempt")
        if type(native) is not NativePreanalysisKey:
            raise TypeError("structural transaction requires exact native key")
        if type(coordinates) is not StructuralTransactionCoordinates:
            raise TypeError("structural transaction requires explicit coordinates")
        if (
            type(coordinates.snapshot_id) is not str
            or not coordinates.snapshot_id
            or type(coordinates.maturity) is not int
            or type(coordinates.gateway_generation) is not int
            or type(coordinates.evidence_generation) is not int
            or coordinates.evidence_generation < 0
            or coordinates.gateway_generation != attempt.generation
            or (
                coordinates.execution_epoch is not None
                and type(coordinates.execution_epoch) is not int
            )
        ):
            raise ValueError("invalid structural transaction coordinates")
        self._attempt = attempt
        self._attempt_fields = (
            attempt.plan_id,
            attempt.session_id,
            attempt.generation,
            attempt.attempt_id,
        )
        if (
            any(
                type(value) is not str
                for value in (attempt.plan_id, attempt.session_id, attempt.attempt_id)
            )
            or type(attempt.generation) is not int
        ):
            raise TypeError("structural attempt requires exact scalar fields")
        TransactionAttemptId(*self._attempt_fields)
        self._native = tuple(getattr(native, name) for name in NATIVE_KEY_FIELDS)
        expected_types = (str, str, int, int, str, str, str)
        if tuple(type(value) for value in self._native) != expected_types:
            raise TypeError("structural native key requires exact scalar fields")
        validated_native = NativePreanalysisKey(*self._native)
        if not _same_scalars(
            self._native,
            tuple(getattr(validated_native, name) for name in NATIVE_KEY_FIELDS),
        ):
            raise ValueError("structural native key is not normalized")
        self._coordinates = coordinates
        self._source = RuntimeAuthorityArena(RuntimeAuthorityScope("structural-source"))
        self._projected = RuntimeAuthorityArena(
            RuntimeAuthorityScope("structural-projected")
        )
        self._observed: RuntimeAuthorityArena | None = None
        self._closed = False

    def _require_open(self) -> None:
        if self._closed:
            raise StructuralIdentityError("structural transaction is closed")

    @property
    def source_arena(self) -> RuntimeAuthorityArena:
        """Use this source owner for structural values and occurrence origins."""
        self._require_open()
        return self._source

    @property
    def projected_arena(self) -> RuntimeAuthorityArena:
        """Use the separate projected owner; never substitute an observation."""
        self._require_open()
        return self._projected

    @property
    def source(self) -> StructuralTable:
        self._require_open()
        return self._source.structural

    @property
    def projected(self) -> StructuralTable:
        self._require_open()
        return self._projected.structural

    @property
    def observed(self) -> StructuralTable:
        self._require_open()
        if self._observed is None:
            raise StructuralIdentityError("structural transaction has no observation")
        return self._observed.structural

    def require_preparation(self, attempt: TransactionAttemptId, snapshot_id: str) -> None:
        """Check the exact attempt at the consuming preparation boundary.

        The native participant separately checks all live gateway coordinates
        with require_scope immediately before forwarding this owner.
        """
        self._require_open()
        if (attempt is not self._attempt or type(snapshot_id) is not str
                or snapshot_id != self._coordinates.snapshot_id
                or not _same_scalars((attempt.plan_id, attempt.session_id,
                                      attempt.generation, attempt.attempt_id),
                                     self._attempt_fields)):
            raise StructuralIdentityError("structural preparation scope differs")

    def require_native_input(self, native: NativePreanalysisKey) -> None:
        """Check the native input available at the owned consumer boundary."""
        self._require_open()
        if (type(native) is not NativePreanalysisKey or not _same_scalars(
                tuple(getattr(native, name) for name in NATIVE_KEY_FIELDS), self._native)):
            raise StructuralIdentityError("structural native input differs")

    def require_scope(
        self,
        attempt: TransactionAttemptId,
        native: NativePreanalysisKey,
        coordinates: StructuralTransactionCoordinates,
    ) -> None:
        """Reject reused attempts, native input drift, restart and epoch drift."""
        self._require_open()
        if (
            attempt is not self._attempt
            or type(native) is not NativePreanalysisKey
            or type(coordinates) is not StructuralTransactionCoordinates
            or not _same_scalars(
                (
                    attempt.plan_id,
                    attempt.session_id,
                    attempt.generation,
                    attempt.attempt_id,
                ),
                self._attempt_fields,
            )
            or not _same_scalars(
                tuple(getattr(native, name) for name in NATIVE_KEY_FIELDS), self._native
            )
            or not _same_scalars(coordinates, self._coordinates)
        ):
            raise StructuralIdentityError("structural transaction scope differs")

    def begin_observation(
        self,
        attempt: TransactionAttemptId,
        native: NativePreanalysisKey,
        coordinates: StructuralTransactionCoordinates,
    ) -> StructuralTable:
        """Allocate a fresh partition after actual observation, never projection."""
        self.require_scope(attempt, native, coordinates)
        if self._observed is not None:
            raise StructuralIdentityError("structural observation is single-use")
        self._observed = RuntimeAuthorityArena(
            RuntimeAuthorityScope("structural-observed")
        )
        return self._observed.structural

    def close(self) -> None:
        """Close all partitions on every participant exit; safe to repeat."""
        self._closed = True
        self._source.close()
        self._projected.close()
        if self._observed is not None:
            self._observed.close()


def _same_scalars(left: tuple, right: tuple) -> bool:
    """Compare the fixed scope columns without bool/int aliasing."""
    return len(left) == len(right) and all(
        type(a) is type(b) and a == b for a, b in zip(left, right)
    )
