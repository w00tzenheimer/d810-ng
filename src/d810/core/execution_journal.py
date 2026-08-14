"""Provider-neutral execution-attempt correlation contracts.

This is the bottom-layer identity and record vocabulary every higher layer
must use to correlate one decompilation session with its nested execution
attempts, instead of passing raw UUID strings around. It answers "what did
D810 consider, run, abstain from, select, reject, or complete in this
decompilation, and why?" -- see ``profile-guided-execution-journal.md`` and
``profile-guided-native-mutation-integration.md`` (both under ``_gitless/``)
for the design this implements.

Layering
--------

``d810.core`` is the bottom of the layered-architecture import-linter
contract, so this module imports nothing from ``d810.capabilities``,
``d810.transforms``, ``d810.backends``, ``d810.hexrays``, ``d810.passes``, or
``d810.manager`` -- and never a live IDA package. In particular,
:class:`NativeTransactionLink` cannot hold the real ``NativePatchTransactionId``
type that a later task defines in ``d810.capabilities.native_patch``; it
carries that transaction's portable string identity instead. The higher-layer
transaction type is expected to expose the same string as its own identity
value, so the two stay correlatable without a layering violation.

Why validation rejects what it rejects
---------------------------------------

- :class:`DecompilationSessionId` and :class:`ExecutionAttemptId` wrap a
  non-blank string / a session plus a positive sequence number. Blank or
  wrong-typed identity fields are rejected at construction so a malformed
  identity can never enter a session, a journal row, or a log line silently.
- :class:`ExecutionAttempt` rejects a ``parent_attempt_id`` that belongs to a
  different session. Attempts are hierarchical *within* one decompilation
  session only (a public pass attempt may have child attempts for private
  rule stages, solver queries, or a mutation transaction); a cross-session
  parent link would let one decompile's provenance graph reference another
  decompile's attempts, which breaks both the "a new session clears only
  callback-local state" retention model and any later per-session query.
- A non-positive ``sequence`` is rejected because attempt ordering *is* the
  sequence number: sequence 0 or negative has no established "before this
  point" meaning and would corrupt ordering comparisons across a session's
  attempts. ``ExecutionAttemptId`` deliberately carries no extra random
  component -- ``(session, sequence)`` is already globally unique because
  ``DecompilationSessionId`` is, and staying deterministic keeps replay and
  logging reproducible.
- :class:`ExecutionAttemptStatus` only allows a transition out of
  ``STARTED``. Every other status (``abstained``, ``completed``, ``failed``,
  ``rejected``, ``poisoned_restart_required``) is terminal, matching
  ``profile-guided-execution-journal.md``'s attempt schema. Attempts are
  immutable records, so "transitioning" one means building a new record with
  :func:`advance_attempt`; allowing a terminal status to be overwritten would
  let a finished attempt's outcome silently change after the fact, which is
  exactly the provenance guarantee this layer exists to provide.
- :class:`NativeTransactionLink` rejects a missing (``None`` or wrong-typed)
  ``attempt_id``. A native mutation receipt with no owning execution attempt
  is unauthorized by construction: policy/selection authority is recorded on
  the attempt, not the transaction, per the "native write remains
  explicit-user-policy controlled" global constraint. A link type that could
  exist without an attempt would let a transaction float free of the record
  that justified it.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from uuid import uuid4


def _require_identifier(value: object, label: str) -> None:
    """Reject a non-string or blank identity field."""
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


def _freeze_json_value(value: object, *, label: str) -> object:
    """Return an immutable, JSON-safe representation of ``value``.

    Attempt/effect metadata is durable provenance, not a bag for live IDA,
    solver, or graph objects.  Keeping the validation in ``core`` lets every
    producer fail at the same boundary before a non-replayable object reaches
    SQLite.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{label} must contain only finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{label} mapping keys must be strings")
            frozen[key] = _freeze_json_value(nested, label=f"{label}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(nested, label=f"{label}[]") for nested in value)
    raise TypeError(
        f"{label} must contain only JSON-safe scalar, mapping, or sequence values"
    )


def _freeze_json_object(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    frozen = _freeze_json_value(value, label=label)
    if not isinstance(frozen, Mapping):  # pragma: no cover - defensive invariant
        raise TypeError(f"{label} must be a mapping")
    return frozen


@dataclass(frozen=True, slots=True)
class DecompilationSessionId:
    """Portable identity for one top-level decompilation session.

    Every top-level decompile creates exactly one of these, and every
    execution attempt inside that decompile carries it. See
    ``profile-guided-execution-journal.md``, "Session identity".
    """

    value: str

    def __post_init__(self) -> None:
        _require_identifier(self.value, "value")

    @classmethod
    def new(cls) -> DecompilationSessionId:
        """Mint a fresh, globally-unique session identity."""
        return cls(value=uuid4().hex)


@dataclass(frozen=True, slots=True)
class ExecutionAttemptId:
    """Ordered identity for one unit of work inside one session.

    Identity is the ``(session, sequence)`` pair. That pair is already
    globally unique, since ``session`` is, and it is deterministic rather
    than random: ``sequence`` is assigned by the session's monotonic attempt
    counter, so it also encodes creation order within the session (see
    ``test_attempts_are_ordered_within_one_session``).
    """

    session: DecompilationSessionId
    sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.session, DecompilationSessionId):
            raise TypeError("session must be a DecompilationSessionId")
        # bool is an int subclass; reject it explicitly so a stray True/False
        # sequence cannot silently pass the int check below.
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TypeError("sequence must be an integer")
        if self.sequence <= 0:
            raise ValueError("sequence must be a positive integer")

    @classmethod
    def new(
        cls, *, session: DecompilationSessionId, sequence: int
    ) -> ExecutionAttemptId:
        """Build the attempt identity for ``sequence`` within ``session``."""
        return cls(session=session, sequence=sequence)


class ExecutionDomain(enum.Enum):
    """Which execution lane produced an attempt.

    Mirrors the "Hook and backend coverage" seams enumerated in
    ``profile-guided-execution-journal.md``: the config-v2 pass driver, hook
    rule handlers/adapters, solver queries, pure transforms/fragment-plan
    emitters, and the mutation/native-normalization backend. Unlike
    :class:`~d810.core.pass_ids.PassId`, this vocabulary is never written
    into a project config or an extension manifest -- it is internal
    provenance bookkeeping -- so new members may be added later without an
    on-the-wire compatibility concern.
    """

    PASS = "pass"
    HOOK = "hook"
    SOLVER = "solver"
    TRANSFORM = "transform"
    MUTATION = "mutation"
    NATIVE_NORMALIZATION = "native_normalization"
    PROFILE_GUIDANCE = "profile_guidance"


class ExecutionAttemptStatus(enum.Enum):
    """Terminal/non-terminal outcome vocabulary for one execution attempt.

    Values match ``profile-guided-execution-journal.md``'s attempt schema:
    ``started``, ``abstained``, ``completed``, ``failed``, ``rejected``,
    ``poisoned_restart_required``. ``STARTED`` is the only non-terminal
    status; every other status is a finished outcome.
    """

    STARTED = "started"
    ABSTAINED = "abstained"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    POISONED_RESTART_REQUIRED = "poisoned_restart_required"

    @property
    def is_terminal(self) -> bool:
        return self is not ExecutionAttemptStatus.STARTED

    def can_transition_to(self, target: ExecutionAttemptStatus) -> bool:
        """Return whether ``self -> target`` is a legal attempt transition.

        The only legal edges leave ``STARTED`` for a different status. A
        terminal status has no outgoing edges, and ``STARTED`` cannot
        transition to itself -- an attempt starts exactly once, at
        construction, not by "transitioning" into its own initial state.
        """
        if not isinstance(target, ExecutionAttemptStatus):
            raise TypeError("target must be an ExecutionAttemptStatus")
        if self.is_terminal:
            return False
        return target is not ExecutionAttemptStatus.STARTED


class IllegalExecutionAttemptTransition(ValueError):
    """Raised when :func:`advance_attempt` is asked to cross a closed edge."""

    def __init__(
        self, current: ExecutionAttemptStatus, target: ExecutionAttemptStatus
    ) -> None:
        self.current = current
        self.target = target
        super().__init__(
            "illegal execution attempt status transition: "
            f"{current.value} -> {target.value}"
        )


@dataclass(frozen=True, slots=True)
class ExecutionEffectRef:
    """Portable pointer to one effect recorded elsewhere for an attempt.

    Effects (fact publication, rule-match counts, solver verdicts, plan
    operations, preflight/validation verdicts, transaction receipts,
    reduction metrics, ...) are persisted separately from the attempt header
    per ``profile-guided-execution-journal.md``, "Effects and evidence"; an
    attempt only carries a reference to each one. ``kind`` names the effect
    category and ``ref_id`` is that effect's identity in its own store.
    """

    kind: str
    ref_id: str
    #: Immutable JSON-safe detail owned by the effect producer.  This carries
    #: plan fingerprints, operation counts, and receipt summaries without
    #: smuggling live backend objects into the generic provenance ledger.
    detail: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        _require_identifier(self.kind, "kind")
        _require_identifier(self.ref_id, "ref_id")
        object.__setattr__(
            self,
            "detail",
            _freeze_json_object(self.detail, label="detail"),
        )


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """One correlated unit of work inside one decompilation session.

    Immutable by construction (``frozen=True, slots=True``); "transitioning"
    an attempt to a new status means calling :func:`advance_attempt` to build
    a replacement record, never mutating this one.
    """

    attempt_id: ExecutionAttemptId
    parent_attempt_id: ExecutionAttemptId | None
    stage_id: str
    domain: ExecutionDomain
    status: ExecutionAttemptStatus
    reason_code: str | None
    effect_refs: tuple[ExecutionEffectRef, ...]
    #: Elapsed wall-clock duration for a terminal attempt, assigned by the
    #: durable store when a caller does not provide an authoritative value.
    elapsed_ms: float | None = None
    #: Typed terminal payload for structured abstention, failure, mutation, or
    #: receipt context.  It is deliberately JSON-safe and immutable.
    details: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be an ExecutionAttemptId")
        if self.parent_attempt_id is not None:
            if not isinstance(self.parent_attempt_id, ExecutionAttemptId):
                raise TypeError(
                    "parent_attempt_id must be an ExecutionAttemptId or None"
                )
            if self.parent_attempt_id.session != self.attempt_id.session:
                raise ValueError(
                    "parent_attempt_id must belong to the same session as attempt_id"
                )
        _require_identifier(self.stage_id, "stage_id")
        if not isinstance(self.domain, ExecutionDomain):
            raise TypeError("domain must be an ExecutionDomain")
        if not isinstance(self.status, ExecutionAttemptStatus):
            raise TypeError("status must be an ExecutionAttemptStatus")
        if self.reason_code is not None and not isinstance(self.reason_code, str):
            raise TypeError("reason_code must be a string or None")
        if not isinstance(self.effect_refs, tuple):
            raise TypeError("effect_refs must be a tuple")
        for ref in self.effect_refs:
            if not isinstance(ref, ExecutionEffectRef):
                raise TypeError(
                    "effect_refs must contain only ExecutionEffectRef values"
                )
        if self.elapsed_ms is not None:
            if isinstance(self.elapsed_ms, bool) or not isinstance(
                self.elapsed_ms, (int, float)
            ):
                raise TypeError("elapsed_ms must be a finite number or None")
            elapsed_ms = float(self.elapsed_ms)
            if not math.isfinite(elapsed_ms) or elapsed_ms < 0.0:
                raise ValueError("elapsed_ms must be a finite non-negative number")
            object.__setattr__(self, "elapsed_ms", elapsed_ms)
        object.__setattr__(
            self,
            "details",
            _freeze_json_object(self.details, label="details"),
        )


def advance_attempt(
    attempt: ExecutionAttempt,
    *,
    status: ExecutionAttemptStatus,
    reason_code: str | None = None,
    effect_refs: tuple[ExecutionEffectRef, ...] | None = None,
    elapsed_ms: float | None = None,
    details: Mapping[str, object] | None = None,
) -> ExecutionAttempt:
    """Return a new attempt record advanced to ``status``.

    Raises :class:`IllegalExecutionAttemptTransition` when
    ``attempt.status.can_transition_to(status)`` is false -- either
    ``attempt.status`` is already terminal, or ``status`` is ``STARTED``.
    ``reason_code``/``effect_refs`` default to the current record's values so
    a caller can advance status alone.
    """
    if not attempt.status.can_transition_to(status):
        raise IllegalExecutionAttemptTransition(attempt.status, status)
    return replace(
        attempt,
        status=status,
        reason_code=reason_code if reason_code is not None else attempt.reason_code,
        effect_refs=effect_refs if effect_refs is not None else attempt.effect_refs,
        elapsed_ms=elapsed_ms if elapsed_ms is not None else attempt.elapsed_ms,
        details=details if details is not None else attempt.details,
    )


@dataclass(frozen=True, slots=True)
class NativeTransactionLink:
    """Correlates an execution attempt with a native-patch transaction.

    ``d810.core`` sits below ``d810.capabilities`` in the layered-
    architecture contract, so this cannot hold the real
    ``NativePatchTransactionId`` (defined in
    ``d810.capabilities.native_patch`` by a later task). It stores that
    transaction's portable string identity instead; the higher-layer
    transaction type is expected to expose the same string as its own
    identity value.

    ``attempt_id`` is mandatory: see the module docstring for why a
    transaction cannot be linked without its owning, authorizing attempt.
    """

    attempt_id: ExecutionAttemptId
    transaction_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be an ExecutionAttemptId")
        _require_identifier(self.transaction_id, "transaction_id")


__all__ = [
    "DecompilationSessionId",
    "ExecutionAttempt",
    "ExecutionAttemptId",
    "ExecutionAttemptStatus",
    "ExecutionDomain",
    "ExecutionEffectRef",
    "IllegalExecutionAttemptTransition",
    "NativeTransactionLink",
    "advance_attempt",
]
