"""Opt-in aggregate counters for authority phase-construction work."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum

from d810.core.typing import Iterator


class AuthorityWorkKind(StrEnum):
    BUILD_INVENTORY = "build_inventory"
    DERIVE_TRANSACTION_FACTS = "derive_transaction_facts"
    DERIVE_PATCH_LINEAGE = "derive_patch_lineage"
    DERIVE_INPUTS = "derive_inputs"
    BUILD_SEMANTIC_CASE = "build_semantic_case"
    BUILD_LOSS_LEDGER = "build_loss_ledger"


class AuthorityWorkPhase(StrEnum):
    PROJECTED = "projected"
    OBSERVED = "observed"


class AuthorityInputOrigin(StrEnum):
    PREPARED_SOURCE = "prepared_source"
    PROJECTED_GRAPH = "projected_graph"
    OBSERVED_GRAPH = "observed_graph"


@dataclass(frozen=True, slots=True)
class AuthorityWorkRow:
    kind: AuthorityWorkKind
    phase: AuthorityWorkPhase
    input_origin: AuthorityInputOrigin
    count: int


@dataclass(frozen=True, slots=True)
class AuthorityWorkSnapshot:
    rows: tuple[AuthorityWorkRow, ...]

    @property
    def total(self) -> int:
        return sum(row.count for row in self.rows)

    def count(
        self,
        *,
        kind: AuthorityWorkKind,
        phase: AuthorityWorkPhase,
        input_origin: AuthorityInputOrigin,
    ) -> int:
        for row in self.rows:
            if (
                row.kind is kind
                and row.phase is phase
                and row.input_origin is input_origin
            ):
                return row.count
        return 0


class AuthorityWorkRecorder:
    def __init__(self) -> None:
        self._counts: Counter[
            tuple[AuthorityWorkKind, AuthorityWorkPhase, AuthorityInputOrigin]
        ] = Counter()

    def record(
        self,
        kind: AuthorityWorkKind,
        phase: AuthorityWorkPhase,
        input_origin: AuthorityInputOrigin,
    ) -> None:
        if type(kind) is not AuthorityWorkKind:
            raise TypeError("kind must be AuthorityWorkKind")
        if type(phase) is not AuthorityWorkPhase:
            raise TypeError("phase must be AuthorityWorkPhase")
        if type(input_origin) is not AuthorityInputOrigin:
            raise TypeError("input_origin must be AuthorityInputOrigin")
        self._counts[(kind, phase, input_origin)] += 1

    def snapshot(self) -> AuthorityWorkSnapshot:
        rows = tuple(
            AuthorityWorkRow(kind, phase, origin, count)
            for (kind, phase, origin), count in sorted(
                self._counts.items(),
                key=lambda item: tuple(value.value for value in item[0]),
            )
        )
        return AuthorityWorkSnapshot(rows)


class DisabledAuthorityWorkRecorder:
    @staticmethod
    def snapshot() -> AuthorityWorkSnapshot:
        return AuthorityWorkSnapshot(())


_ACTIVE_RECORDER: ContextVar[AuthorityWorkRecorder | None] = ContextVar(
    "d810_authority_work_recorder",
    default=None,
)


@contextmanager
def authority_work_scope(
    *, enabled: bool,
) -> Iterator[AuthorityWorkRecorder | DisabledAuthorityWorkRecorder]:
    recorder: AuthorityWorkRecorder | DisabledAuthorityWorkRecorder
    recorder = AuthorityWorkRecorder() if enabled else DisabledAuthorityWorkRecorder()
    token = _ACTIVE_RECORDER.set(recorder if enabled else None)
    try:
        yield recorder
    finally:
        _ACTIVE_RECORDER.reset(token)


def record_authority_work(
    kind: AuthorityWorkKind,
    phase: AuthorityWorkPhase,
    input_origin: AuthorityInputOrigin,
) -> None:
    recorder = _ACTIVE_RECORDER.get()
    if recorder is not None:
        recorder.record(kind, phase, input_origin)


__all__ = [
    "AuthorityInputOrigin",
    "AuthorityWorkKind",
    "AuthorityWorkPhase",
    "AuthorityWorkRecorder",
    "AuthorityWorkRow",
    "AuthorityWorkSnapshot",
    "DisabledAuthorityWorkRecorder",
    "authority_work_scope",
    "record_authority_work",
]
