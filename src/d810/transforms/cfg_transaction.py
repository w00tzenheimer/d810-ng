"""Portable records and protocol for transactional CFG realization.

This module stops at the portable transaction boundary. Live CFG objects and
backend-specific bindings belong behind a participant implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import uuid4

from d810.core.typing import Protocol, TypeAlias
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import FlowGraph


def _require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _require_nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    return value


@dataclass(frozen=True, slots=True)
class PlanBlockRef:
    """Nominal identity for one block inside an immutable plan."""

    plan_id: str
    local_block_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "plan_id")
        _require_identifier(self.local_block_id, "local_block_id")


@dataclass(frozen=True, slots=True)
class PlanInsnRef:
    """Nominal identity for one instruction inside a plan-local block."""

    block: PlanBlockRef
    local_instruction_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.block, PlanBlockRef):
            raise TypeError("block must be a PlanBlockRef")
        _require_identifier(self.local_instruction_id, "local_instruction_id")


@dataclass(frozen=True, slots=True)
class NativeBlockRef:
    """Portable cross-snapshot identity for a native-derived block."""

    identity: StableBlockIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.identity, StableBlockIdentity):
            raise TypeError("identity must be a StableBlockIdentity")


@dataclass(frozen=True, slots=True)
class LogicalBlockRef:
    """Versioned proxy identity supplied by a logical CFG session."""

    session_id: str
    proxy_token: str
    version: int

    def __post_init__(self) -> None:
        _require_identifier(self.session_id, "session_id")
        _require_identifier(self.proxy_token, "proxy_token")
        _require_nonnegative_int(self.version, "version")


@dataclass(frozen=True, slots=True)
class TransactionAttemptId:
    """Authority for one realization attempt in one live generation."""

    plan_id: str
    session_id: str
    generation: int
    attempt_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "plan_id")
        _require_identifier(self.session_id, "session_id")
        _require_nonnegative_int(self.generation, "generation")
        _require_identifier(self.attempt_id, "attempt_id")

    @classmethod
    def new(
        cls,
        plan_id: str,
        session_id: str,
        generation: int,
    ) -> TransactionAttemptId:
        return cls(
            plan_id=plan_id,
            session_id=session_id,
            generation=generation,
            attempt_id=uuid4().hex,
        )


CfgBlockRef: TypeAlias = NativeBlockRef | LogicalBlockRef | PlanBlockRef
_CFG_BLOCK_REF_TYPES = (NativeBlockRef, LogicalBlockRef, PlanBlockRef)


@dataclass(frozen=True, slots=True)
class CfgProjection:
    """An immutable plan projection over a portable CFG snapshot.

    Any integers used as graph node keys are local to this projection. They are
    never live SDK block identities and cannot authorize a later mutation.
    """

    plan_id: str
    snapshot_id: str
    graph: FlowGraph
    focus_refs: tuple[CfgBlockRef, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "plan_id")
        _require_identifier(self.snapshot_id, "snapshot_id")
        if not isinstance(self.graph, FlowGraph):
            raise TypeError("graph must be a FlowGraph")
        if not isinstance(self.focus_refs, tuple):
            raise TypeError("focus_refs must be a tuple")
        for ref in self.focus_refs:
            if not isinstance(ref, _CFG_BLOCK_REF_TYPES):
                raise TypeError("focus_refs must contain CfgBlockRef values")
            if isinstance(ref, PlanBlockRef) and ref.plan_id != self.plan_id:
                raise ValueError("focus_refs plan authority must match projection")


@dataclass(frozen=True, slots=True)
class PreparedCfgTransaction:
    """A preflighted transaction with the obligations it must discharge."""

    attempt_id: TransactionAttemptId
    projection: CfgProjection
    obligation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("attempt_id must be a TransactionAttemptId")
        if not isinstance(self.projection, CfgProjection):
            raise TypeError("projection must be a CfgProjection")
        if self.attempt_id.plan_id != self.projection.plan_id:
            raise ValueError("attempt_id plan_id must match projection plan_id")
        if not isinstance(self.obligation_ids, tuple):
            raise TypeError("obligation_ids must be a tuple")
        for obligation_id in self.obligation_ids:
            _require_identifier(obligation_id, "obligation_id")
        if len(set(self.obligation_ids)) != len(self.obligation_ids):
            raise ValueError("obligation_ids must not contain duplicates")


@dataclass(frozen=True, slots=True)
class BoundCfgTransaction:
    """A prepared transaction plus backend-owned realization bindings."""

    prepared: PreparedCfgTransaction
    session_id: str
    generation: int
    bindings: tuple[tuple[CfgBlockRef, object], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.prepared, PreparedCfgTransaction):
            raise TypeError("prepared must be a PreparedCfgTransaction")
        _require_identifier(self.session_id, "session_id")
        _require_nonnegative_int(self.generation, "generation")
        attempt = self.prepared.attempt_id
        if self.session_id != attempt.session_id:
            raise ValueError("session authority must match prepared attempt")
        if self.generation != attempt.generation:
            raise ValueError("generation authority must match prepared attempt")
        if not isinstance(self.bindings, tuple):
            raise TypeError("bindings must be a tuple")
        refs: list[CfgBlockRef] = []
        for binding in self.bindings:
            if not isinstance(binding, tuple) or len(binding) != 2:
                raise TypeError("bindings must contain (CfgBlockRef, object) pairs")
            ref, _target = binding
            if not isinstance(ref, _CFG_BLOCK_REF_TYPES):
                raise TypeError("binding reference must be a CfgBlockRef")
            if (
                isinstance(ref, PlanBlockRef)
                and ref.plan_id != self.prepared.projection.plan_id
            ):
                raise ValueError("binding plan authority must match projection")
            if isinstance(ref, LogicalBlockRef) and ref.session_id != self.session_id:
                raise ValueError("binding session authority must match transaction")
            refs.append(ref)
        if len(set(refs)) != len(refs):
            raise ValueError("bindings must not contain duplicate references")


class CfgTransactionPhase(str, Enum):
    """Portable transaction lifecycle, including terminal failure states."""

    PLANNED = "planned"
    PROJECTED = "projected"
    PREFLIGHTED = "preflighted"
    BOUND = "bound"
    REALIZING = "realizing"
    OBSERVED = "observed"
    COMMITTED = "committed"
    REJECTED_CLEAN = "rejected_clean"
    POISONED_RESTART_REQUIRED = "poisoned_restart_required"


@dataclass(frozen=True, slots=True)
class CfgTransactionFailure:
    """Terminal failure evidence that records whether live mutation began."""

    attempt_id: TransactionAttemptId
    phase: CfgTransactionPhase
    reason: str
    live_mutation_started: bool
    first_failed_obligation: str | None = None
    failure_phase: str = ""
    interr_code: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("attempt_id must be a TransactionAttemptId")
        if not isinstance(self.phase, CfgTransactionPhase):
            raise TypeError("phase must be a CfgTransactionPhase")
        if self.phase not in {
            CfgTransactionPhase.REJECTED_CLEAN,
            CfgTransactionPhase.POISONED_RESTART_REQUIRED,
        }:
            raise ValueError("failure phase must be a terminal failure phase")
        _require_identifier(self.reason, "reason")
        if not isinstance(self.live_mutation_started, bool):
            raise TypeError("live_mutation_started must be a bool")
        expected_mutation_started = (
            self.phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED
        )
        if self.live_mutation_started is not expected_mutation_started:
            raise ValueError("live_mutation_started must match failure phase")
        if self.first_failed_obligation is not None:
            _require_identifier(
                self.first_failed_obligation,
                "first_failed_obligation",
            )
        if self.failure_phase:
            _require_identifier(self.failure_phase, "failure_phase")
        if self.interr_code is not None:
            if not isinstance(self.interr_code, int) or isinstance(
                self.interr_code,
                bool,
            ):
                raise TypeError("interr_code must be an integer")
            if self.interr_code <= 0:
                raise ValueError("interr_code must be positive")


class CfgGenerationPoisoned(RuntimeError):
    """Unwind a callback after an SDK write made its generation unsafe."""

    def __init__(self, failure: CfgTransactionFailure) -> None:
        if not isinstance(failure, CfgTransactionFailure):
            raise TypeError("generation poison requires a transaction failure")
        if failure.phase is not CfgTransactionPhase.POISONED_RESTART_REQUIRED:
            raise ValueError("generation poison requires a poisoned failure phase")
        self.failure = failure
        interr = (
            "" if failure.interr_code is None else f" INTERR={failure.interr_code}"
        )
        super().__init__(
            f"CFG generation poisoned during {failure.failure_phase or 'mutation'}: "
            f"{failure.reason}{interr}"
        )


class CfgTransactionParticipant(Protocol):
    """Backend-neutral participant seam for a CFG transaction lifecycle."""

    def project(self, plan: object, snapshot: object) -> CfgProjection: ...

    def preflight(self, projection: CfgProjection) -> PreparedCfgTransaction: ...

    def bind(
        self,
        prepared: PreparedCfgTransaction,
        identity_index: object,
    ) -> BoundCfgTransaction: ...

    def realize(self, bound: BoundCfgTransaction, gateway: object) -> object: ...

    def observe(self, receipt: object, live_graph: object) -> object: ...


__all__ = [
    "BoundCfgTransaction",
    "CfgBlockRef",
    "CfgGenerationPoisoned",
    "CfgProjection",
    "CfgTransactionFailure",
    "CfgTransactionParticipant",
    "CfgTransactionPhase",
    "LogicalBlockRef",
    "NativeBlockRef",
    "PlanBlockRef",
    "PlanInsnRef",
    "PreparedCfgTransaction",
    "TransactionAttemptId",
]
