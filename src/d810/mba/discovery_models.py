"""Portable models for the D810-owned MBA discovery database."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from uuid import UUID

from d810.core.function_execution_identity import MbaObservationContext
from d810.mba.provider_outcome import MbaProviderOutcome
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


_WIDTHS = frozenset({8, 16, 32, 64})


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise ValueError(f"{field} must be a canonical non-empty string")
    return value


def _uuid(value: object, field: str) -> str:
    if isinstance(value, UUID):
        return str(value)
    if type(value) is not str:
        raise TypeError(f"{field} must be a UUID")
    try:
        result = str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc
    if result != value.lower():
        raise ValueError(f"{field} must use canonical UUID spelling")
    return result


def _integer(value: object, field: str, *, non_negative: bool = True) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if non_negative and value < 0:
        raise ValueError(f"{field} must be non-negative")
    return value


class ResidualGroupState(enum.StrEnum):
    OBSERVED = "observed"
    ELIGIBLE = "eligible"
    MINING = "mining"
    NO_PROPOSAL = "no_proposal"
    PROPOSED = "proposed"
    MATERIALIZED = "materialized"
    ADMITTED = "admitted"
    REJECTED = "rejected"


class MiningRunState(enum.StrEnum):
    CLAIMED = "claimed"
    ACTIVE = "claimed"
    NO_PROPOSAL = "no_proposal"
    PROPOSED = "proposed"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    FAILED = "failed"


class ProposalState(enum.StrEnum):
    PROPOSED = "proposed"
    MATERIALIZED = "materialized"
    ADMITTED = "admitted"
    REJECTED = "rejected"


class ReceiptStatus(enum.StrEnum):
    STORED = "stored"
    DUPLICATE = "duplicate"
    REFUSED = "refused"
    CLAIMED = "claimed"
    HEARTBEATED = "heartbeated"
    FINISHED = "finished"
    PUBLISHED = "published"
    MATERIALIZED = "materialized"
    ADMITTED = "admitted"
    REJECTED = "rejected"


# The sole transition authority.  Store methods may only use transitions in
# this table; repeated operations are handled as idempotent receipts.
GROUP_TRANSITIONS: dict[ResidualGroupState, frozenset[ResidualGroupState]] = {
    ResidualGroupState.OBSERVED: frozenset({ResidualGroupState.ELIGIBLE}),
    ResidualGroupState.ELIGIBLE: frozenset({ResidualGroupState.MINING}),
    ResidualGroupState.MINING: frozenset(
        {ResidualGroupState.NO_PROPOSAL, ResidualGroupState.PROPOSED}
    ),
    ResidualGroupState.NO_PROPOSAL: frozenset({ResidualGroupState.ELIGIBLE}),
    ResidualGroupState.PROPOSED: frozenset(
        {ResidualGroupState.MATERIALIZED, ResidualGroupState.REJECTED}
    ),
    ResidualGroupState.MATERIALIZED: frozenset(
        {ResidualGroupState.ADMITTED, ResidualGroupState.REJECTED}
    ),
    ResidualGroupState.ADMITTED: frozenset(),
    ResidualGroupState.REJECTED: frozenset(),
}

PROPOSAL_TRANSITIONS: dict[ProposalState, frozenset[ProposalState]] = {
    ProposalState.PROPOSED: frozenset(
        {ProposalState.MATERIALIZED, ProposalState.REJECTED}
    ),
    ProposalState.MATERIALIZED: frozenset(
        {ProposalState.ADMITTED, ProposalState.REJECTED}
    ),
    ProposalState.ADMITTED: frozenset(),
    ProposalState.REJECTED: frozenset(),
}


def valid_group_transition(
    current: ResidualGroupState, target: ResidualGroupState
) -> bool:
    return target in GROUP_TRANSITIONS[current]


def valid_proposal_transition(current: ProposalState, target: ProposalState) -> bool:
    return target in PROPOSAL_TRANSITIONS[current]


@dataclass(frozen=True, slots=True)
class DiscoveryAttempt:
    """Strict, live-object-free input for one provider observation."""

    attempt_uuid: str
    context: MbaObservationContext
    raw_term: TypedBvTerm
    canonical_term: TypedBvTerm
    outcome: MbaProviderOutcome
    eligible_for_mining: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "attempt_uuid", _uuid(self.attempt_uuid, "attempt_uuid")
        )
        if not isinstance(self.context, MbaObservationContext):
            raise TypeError("context must be an MbaObservationContext")
        if (
            type(self.raw_term) is not TypedBvTerm
            or type(self.canonical_term) is not TypedBvTerm
        ):
            raise TypeError("terms must be TypedBvTerm values")
        if not isinstance(self.outcome, MbaProviderOutcome):
            raise TypeError("outcome must be an MbaProviderOutcome")
        if (
            self.raw_term.width not in _WIDTHS
            or self.canonical_term.width not in _WIDTHS
        ):
            raise ValueError("term width must be one of 8, 16, 32, or 64")
        if self.raw_term.width != self.canonical_term.width:
            raise ValueError("raw and canonical term widths must match")
        if term_fingerprint(self.canonical_term) != self.outcome.fingerprint:
            raise ValueError("outcome fingerprint must match canonical term")
        if type(self.eligible_for_mining) is not bool:
            raise TypeError("eligible_for_mining must be a bool")


@dataclass(frozen=True, slots=True)
class ResidualGroup:
    group_id: int
    term_id: int
    state: ResidualGroupState
    eligible_observation_count: int
    last_observed_at: str
    last_mined_at: str | None
    materialized_at: str | None
    admitted_at: str | None
    revision: int
    canonical_term: TypedBvTerm
    raw_terms: tuple[TypedBvTerm, ...]


@dataclass(frozen=True, slots=True)
class MiningRun:
    run_id: str
    group_id: int
    claimed_revision: int
    miner_version: str
    budget_fingerprint: str
    state: MiningRunState
    started_at: str
    heartbeat_at: str
    finished_at: str | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _uuid(self.run_id, "run_id"))
        object.__setattr__(self, "group_id", _integer(self.group_id, "group_id"))
        object.__setattr__(
            self,
            "claimed_revision",
            _integer(self.claimed_revision, "claimed_revision"),
        )
        _text(self.miner_version, "miner_version")
        _text(self.budget_fingerprint, "budget_fingerprint")


@dataclass(frozen=True, slots=True)
class MiningClaim:
    group: ResidualGroup
    run: MiningRun


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    group_id: int
    run_id: str
    proposal_fingerprint: str
    replacement_term: TypedBvTerm
    proposal_payload: bytes
    proof_receipt_payload: bytes
    state: ProposalState
    created_at: str
    materialized_path: str | None = None
    materialized_digest: str | None = None
    materialized_at: str | None = None
    admitted_rule_id: str | None = None
    admitted_at: str | None = None
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_id", _uuid(self.proposal_id, "proposal_id"))
        object.__setattr__(self, "run_id", _uuid(self.run_id, "run_id"))
        _text(self.proposal_fingerprint, "proposal_fingerprint")
        if (
            type(self.proposal_payload) is not bytes
            or type(self.proof_receipt_payload) is not bytes
        ):
            raise TypeError("proposal payloads must be bytes")


@dataclass(frozen=True, slots=True)
class DiscoveryReceipt:
    status: ReceiptStatus | str
    reason: str | None = None
    attempt_id: int | None = None
    group_id: int | None = None
    term_id: int | None = None
    raw_term_id: int | None = None
    revision: int | None = None
    state: ResidualGroupState | None = None


@dataclass(frozen=True, slots=True)
class ClaimReceipt:
    status: ReceiptStatus | str
    claim: MiningClaim | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class HeartbeatReceipt:
    status: ReceiptStatus | str
    run: MiningRun | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class LifecycleReceipt:
    status: ReceiptStatus | str
    proposal: Proposal | None = None
    run: MiningRun | None = None
    group: ResidualGroup | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryStatus:
    group_counts: tuple[tuple[ResidualGroupState, int], ...]
    run_counts: tuple[tuple[MiningRunState, int], ...]
    proposal_counts: tuple[tuple[ProposalState, int], ...]
    outstanding_leases: int
    expired_leases: int


# Descriptive aliases keep receipt intent discoverable without introducing
# alternate mutable result shapes.
RecordAttemptReceipt = DiscoveryReceipt
ProposalReceipt = LifecycleReceipt
TransitionReceipt = LifecycleReceipt


__all__ = [
    "ClaimReceipt",
    "DiscoveryAttempt",
    "DiscoveryReceipt",
    "DiscoveryStatus",
    "GROUP_TRANSITIONS",
    "HeartbeatReceipt",
    "LifecycleReceipt",
    "MiningClaim",
    "MiningRun",
    "MiningRunState",
    "PROPOSAL_TRANSITIONS",
    "Proposal",
    "ProposalState",
    "ProposalReceipt",
    "RecordAttemptReceipt",
    "ReceiptStatus",
    "ResidualGroup",
    "ResidualGroupState",
    "TransitionReceipt",
    "valid_group_transition",
    "valid_proposal_transition",
]
