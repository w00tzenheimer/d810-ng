"""Provider-neutral native-patch transaction identity, journal state, and
recovery vocabulary, plus the ``EncodingProvider`` Protocol.

See ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` section 14 (schemas) and
``_gitless/profile-guided-native-mutation-implementer-plan.md`` Task 2 for the
design this implements. This module is Task 2's bottom layer: the pure
identity/state/protocol vocabulary that both ``d810.transforms.native_patch_plan``
(the plan/operation records) and ``d810.backends.ida.native_patch.journal``
(the SQLite-backed write-ahead journal) build on.

Layering
--------

``d810.capabilities`` sits below ``d810.transforms`` and ``d810.backends`` in
the layered-architecture contract, so this module imports nothing from either
-- only ``d810.core`` and ``d810.ir`` (neither used here). In particular:

* :class:`NativePatchPlanEnvelope` is a *structural* Protocol, not the real
  ``NativePatchPlan`` dataclass defined in ``d810.transforms.native_patch_plan``.
  The journal store's ``prepare()`` is typed against this envelope so the
  dependency runs downward (``backends`` -> ``transforms`` -> ``capabilities``)
  while this module never imports ``transforms``. This is the same inversion
  the plan already applies to the policy gate
  (``d810.core.normalization_policy``) and the observation handler
  (``d810.backends.ida.native_patch.observation``): put the Protocol in the
  layer below both, inject the concrete type from above.
* :class:`EncodingProvider` is declared here specifically so
  ``d810.transforms.native_patch_lowering`` (Task 5, not yet built) can depend
  on it without importing ``d810.backends.ida.native_patch.encoder`` upward.
  The existing encoder will implement this Protocol; Task 5 injects it.

Byte-granular recovery -- why this exists (review finding P0 #2)
------------------------------------------------------------------

``ida_bytes.patch_bytes`` returns no status and documents no atomicity
guarantee, so a crash mid-write can leave a range that is partly the
before-image and partly the after-image. A classifier that compares an
*entire operation's* current bytes against its entire before-image or entire
after-image would see that mixed range, match neither, and misreport D810's
own interrupted write as external interference -- refusing the automatic
rollback that is actually safe.

The fix is granularity, not cleverness: classify every governed byte
independently against its own expected-before and expected-after value
(:class:`NativeByteRecoveryVerdict`), then reconstruct the operation-level
verdict (:class:`NativeOperationRecoveryVerdict`) from the *set* of per-byte
verdicts. A clean mix of ``BEFORE``/``AFTER`` bytes with zero ``NEITHER``
bytes is unambiguous partial progress -- automatically recoverable. Any single
``NEITHER`` byte is genuine interference -- automatic recovery must stop. The
concrete classifier lives in ``d810.backends.ida.native_patch.journal``
(it needs the durable per-EA write-ahead log); this module only defines the
verdict vocabulary the classifier produces and the journal states it feeds
into.

Journal states -- why ``BYTES_APPLIED`` is not ``APPLIED`` (review finding P1)
--------------------------------------------------------------------------------

Byte persistence and analysis certification are different failure domains: a
decompiler/reanalysis failure after bytes are durably written must not imply
those bytes should be rolled back. ``NativeJournalState`` therefore has
distinct byte-domain and analysis-domain states
(``BYTES_APPLIED``/``METADATA_APPLIED`` vs. ``ANALYSIS_PENDING`` /
``ANALYSIS_VALIDATED`` / ``CACHE_INVALIDATED``) so recovery can resume
reconciliation in the analysis domain without touching bytes that are already
known-good.

Design decision this module is NOT in the source plan verbatim
------------------------------------------------------------------

The implementer plan lists Task 2's states as "PREPARED, BYTES_APPLIED,
METADATA_APPLIED, ANALYSIS_PENDING, ANALYSIS_VALIDATED, CACHE_INVALIDATED,
CERTIFIED plus rollback/restore/recovery/interference states" -- no
``PLANNED`` state, even though the earlier research document's section 14.4
lists ``PLANNED`` first. This module treats "no durable row exists yet" as
the pre-``PREPARED`` state instead of persisting a ``PLANNED`` row: a
``NativePatchPlan`` object (``execution_safe=False``) is itself the "planned"
artifact, and requirement 3 ("PREPARED must be durably committed before a
transaction is exposed for application") means ``prepare()`` is the sole
entry point that creates a row, always landing directly on ``PREPARED``. A
:func:`SQLiteNativePatchJournal.transition` call against a transaction id
with no row raises :class:`IllegalNativeJournalTransition` with
``current=None`` -- see ``test_bytes_applied_requires_a_durable_prepared_record``
in the implementer plan's Task 2 Step 2.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from uuid import uuid4

from d810.core.execution_journal import ExecutionAttemptId
from d810.core.typing import Protocol, runtime_checkable

__all__ = [
    "EncodingProvider",
    "IllegalNativeJournalTransition",
    "NativeByteEventPhase",
    "NativeByteRecoveryEntry",
    "NativeByteRecoveryVerdict",
    "NativeEncodingResult",
    "NativeInstructionHead",
    "NativeInstructionSequenceShape",
    "NativeJournalState",
    "NativeMirrorOutcome",
    "NativeMirrorReceipt",
    "NativeOperationRecoveryReport",
    "NativeOperationRecoveryVerdict",
    "NativePatchJournalStore",
    "NativePatchPlanEnvelope",
    "NativePatchTransactionId",
    "NativePatchTransactionRecord",
    "NativeTransactionRecoveryReport",
    "OperationByteRecord",
    "is_legal_native_journal_transition",
    "legal_next_native_journal_states",
]


def _require_identifier(value: object, label: str) -> None:
    """Reject a non-string or blank identity field.

    Local copy of the same guard in ``d810.core.execution_journal`` -- that
    one is a private (unexported) module helper, so this module keeps its own
    rather than reach past ``__all__``.
    """
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


@dataclass(frozen=True, slots=True)
class NativePatchTransactionId:
    """Portable identity for one native-patch write-ahead transaction.

    Distinct from :class:`~d810.core.execution_journal.ExecutionAttemptId`:
    an attempt is "what D810 considered/ran and why"; a transaction is "what
    exact IDB write-ahead record owns this range." Every
    :class:`NativePatchTransactionRecord` carries both, and
    ``str(transaction_id.value)`` is the same string a
    :class:`~d810.core.execution_journal.NativeTransactionLink` stores as its
    ``transaction_id`` -- see that class's docstring for why ``core`` cannot
    hold this type directly.
    """

    value: str

    def __post_init__(self) -> None:
        _require_identifier(self.value, "value")

    @classmethod
    def new(cls) -> NativePatchTransactionId:
        return cls(value=uuid4().hex)


# ---------------------------------------------------------------------------
# Instruction shape -- needed by EncodingProvider's signature, so it lives at
# this layer rather than in transforms.native_patch_plan (which needs it too,
# and sits above capabilities, so importing it downward from there is legal).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeInstructionHead:
    """One decoded instruction: head EA, length, mnemonic, and successors."""

    ea: int
    length: int
    mnemonic: str
    operand_shapes: tuple[str, ...]
    successors: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ea, int) or isinstance(self.ea, bool):
            raise TypeError("ea must be an int")
        if self.ea < 0:
            raise ValueError("ea must be non-negative")
        if not isinstance(self.length, int) or isinstance(self.length, bool):
            raise TypeError("length must be an int")
        if self.length <= 0:
            raise ValueError("length must be positive")
        _require_identifier(self.mnemonic, "mnemonic")
        if not isinstance(self.operand_shapes, tuple):
            raise TypeError("operand_shapes must be a tuple")
        if not isinstance(self.successors, tuple):
            raise TypeError("successors must be a tuple")

    @property
    def end_ea(self) -> int:
        return self.ea + self.length


@dataclass(frozen=True, slots=True)
class NativeInstructionSequenceShape:
    """An ordered, contiguous-or-not run of decoded instruction heads."""

    heads: tuple[NativeInstructionHead, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.heads, tuple):
            raise TypeError("heads must be a tuple")
        for head in self.heads:
            if not isinstance(head, NativeInstructionHead):
                raise TypeError("heads must contain only NativeInstructionHead")

    @property
    def is_empty(self) -> bool:
        return len(self.heads) == 0

    @property
    def size(self) -> int:
        return sum(head.length for head in self.heads)


# ---------------------------------------------------------------------------
# EncodingProvider -- bytes-only lowering seam between pure `transforms` and a
# live encoder. See the module docstring for the interpretation of "bytes in;
# bytes + decoded expected-after shape out": `decode()` takes bytes in and
# returns a decoded shape (independent re-verification of emitted bytes);
# `encode_*` return bytes plus the decoded shape the provider claims it
# emitted, bundled in one `NativeEncodingResult`.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeEncodingResult:
    """Either an encoded replacement (bytes + decoded shape) or an abstention.

    ``reason`` is a stable string (matching
    ``d810.backends.ida.native_patch.encoder.AbstentionReason`` values such as
    ``UNREPRESENTABLE_BRANCH``) rather than that enum type directly, so this
    module -- which sits below ``backends`` -- never imports it.
    """

    ok: bool
    replacement_bytes: bytes | None = None
    expected_after_shape: NativeInstructionSequenceShape | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.ok:
            if self.replacement_bytes is None or self.expected_after_shape is None:
                raise ValueError(
                    "a successful NativeEncodingResult requires replacement_bytes "
                    "and expected_after_shape"
                )
        elif self.reason is None:
            raise ValueError("an abstained NativeEncodingResult requires a reason")


@runtime_checkable
class EncodingProvider(Protocol):
    """Bytes-only lowering seam: no method here accepts or returns a live IDA
    object -- every argument and return value is a plain int/str/bytes or one
    of the dataclasses above.

    ``d810.transforms.native_patch_lowering`` (Task 5) depends on this
    Protocol instead of importing ``d810.backends.ida.native_patch.encoder``
    directly, because ``transforms`` sits below ``backends`` and that import
    would be an upward layer violation. The existing encoder module is
    expected to implement this Protocol; the composition root injects it.
    """

    def encode_direct_jump(
        self, start_ea: int, end_ea: int, target_ea: int, *, bitness: int
    ) -> NativeEncodingResult:
        """Lower an owned ``[start_ea, end_ea)`` region to one direct jump."""
        ...

    def encode_conditional(
        self,
        start_ea: int,
        end_ea: int,
        *,
        condition: str,
        true_target_ea: int,
        false_target_ea: int,
        bitness: int,
    ) -> NativeEncodingResult:
        """Lower an owned region to ``jcc <true>; jmp <false>``."""
        ...

    def encode_nop_fill(
        self, start_ea: int, end_ea: int, *, bitness: int
    ) -> NativeEncodingResult:
        """Fill an owned ``[start_ea, end_ea)`` region with NOP padding.

        The correction for a branch proven *never* taken: erase it so control
        falls through to ``end_ea``. Distinct from ``encode_direct_jump`` --
        there is no target, because the surviving edge is the region's own end.

        The fill must measure the region exactly. A short fill would leave
        trailing bytes of the erased branch to be decoded as a fresh
        instruction, which is how a "safe" deletion silently becomes a rewrite.
        """
        ...

    def decode(
        self, ea: int, data: bytes, *, bitness: int
    ) -> NativeInstructionSequenceShape:
        """Independently decode ``data`` at ``ea`` (bytes in, shape out).

        Used to re-verify emitted bytes rather than trust the encoder's own
        claim -- ``NativeEncodingEvidence.independent_decode_hash`` is built
        from this.
        """
        ...


# ---------------------------------------------------------------------------
# Write-ahead journal state machine
# ---------------------------------------------------------------------------


class NativeJournalState(str, enum.Enum):
    """Write-ahead recovery states for one native-patch transaction.

    See the module docstring for why ``BYTES_APPLIED``/``METADATA_APPLIED``
    are distinct from the analysis-domain states, and why there is no
    ``PLANNED`` row.
    """

    PREPARED = "PREPARED"
    BYTES_APPLIED = "BYTES_APPLIED"
    METADATA_APPLIED = "METADATA_APPLIED"
    ANALYSIS_PENDING = "ANALYSIS_PENDING"
    ANALYSIS_VALIDATED = "ANALYSIS_VALIDATED"
    CACHE_INVALIDATED = "CACHE_INVALIDATED"
    CERTIFICATE_PENDING = "CERTIFICATE_PENDING"
    CERTIFIED = "CERTIFIED"
    ROLLING_BACK = "ROLLING_BACK"
    RESTORING = "RESTORING"
    RESTORE_BYTES_RESTORED = "RESTORE_BYTES_RESTORED"
    RESTORED = "RESTORED"
    RESTORE_FAILED = "RESTORE_FAILED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    INTERFERENCE_DETECTED = "INTERFERENCE_DETECTED"


# Legal edges. Documented per-state below since the plan does not spell out
# every rollback/restore/recovery edge verbatim -- these are this
# implementation's resolution of that gap (see the report for the rationale
# behind each non-obvious edge).
_LEGAL_NATIVE_JOURNAL_TRANSITIONS: dict[
    NativeJournalState, frozenset[NativeJournalState]
] = {
    # A freshly prepared transaction may start writing bytes, be abandoned
    # before any write (ROLLING_BACK degrades gracefully to a zero-op
    # rollback), or discover at apply-entry that current bytes already
    # diverge from what PREPARED recorded (INTERFERENCE_DETECTED /
    # RECOVERY_REQUIRED -- "divergent current bytes produce
    # INTERFERENCE_DETECTED without writes").
    NativeJournalState.PREPARED: frozenset(
        {
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.INTERFERENCE_DETECTED,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    # BYTES_APPLIED -> METADATA_APPLIED only when the plan owns metadata
    # actions (enforced by the store, not this pure graph -- see
    # SQLiteNativePatchJournal.transition). Both plans may proceed straight
    # to ANALYSIS_PENDING when there is nothing to apply/skip.
    NativeJournalState.BYTES_APPLIED: frozenset(
        {
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.METADATA_APPLIED: frozenset(
        {
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.ANALYSIS_PENDING: frozenset(
        {
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.ANALYSIS_VALIDATED: frozenset(
        {
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.CACHE_INVALIDATED: frozenset(
        {
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    # Both external certificate-store writes happen while this state is
    # durable.  A crash or a store failure can therefore still take the
    # ordinary apply rollback lane; CERTIFIED means both the overlay and its
    # certificate/link witnesses are complete.
    NativeJournalState.CERTIFICATE_PENDING: frozenset(
        {
            NativeJournalState.CERTIFIED,
            NativeJournalState.ROLLING_BACK,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    # Section 15.3 step 1: explicit restore requires an applied certificate.
    # CERTIFIED's only forward edge is into the restore lane.
    NativeJournalState.CERTIFIED: frozenset({NativeJournalState.RESTORING}),
    # Apply-failure rollback (15.2): every byte is disambiguated (no NEITHER
    # verdicts), so automatic rollback either fully succeeds (RESTORED) or
    # cannot complete (RESTORE_FAILED / RECOVERY_REQUIRED, e.g. a byte that
    # was disambiguated at classification time but a subsequent write during
    # the rollback itself fails).
    NativeJournalState.ROLLING_BACK: frozenset(
        {
            NativeJournalState.RESTORED,
            NativeJournalState.RESTORE_FAILED,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.RESTORING: frozenset(
        {
            NativeJournalState.RESTORE_BYTES_RESTORED,
            NativeJournalState.RESTORED,
            NativeJournalState.RESTORE_FAILED,
            # 15.3 step 2: "If the current state differs, record interference
            # and require user resolution."
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    # This durable receipt means a restart need not infer whether the
    # byte-reversal loop completed before it resumes metadata/analysis work.
    NativeJournalState.RESTORE_BYTES_RESTORED: frozenset(
        {
            NativeJournalState.RESTORED,
            NativeJournalState.RESTORE_FAILED,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    NativeJournalState.RESTORED: frozenset(),
    # A failed restore may be retried, or escalated for manual recovery.
    NativeJournalState.RESTORE_FAILED: frozenset(
        {
            NativeJournalState.RESTORING,
            NativeJournalState.RECOVERY_REQUIRED,
        }
    ),
    # Recovery on plugin load or IDB open (15.4) resolves into either lane
    # depending on what the byte classifier found.
    NativeJournalState.RECOVERY_REQUIRED: frozenset(
        {
            NativeJournalState.RESTORING,
            NativeJournalState.ROLLING_BACK,
        }
    ),
    # "Stop automatic writes" -- the only forward edge is into recovery,
    # which requires operator/automation acknowledgement before any further
    # write is attempted.
    NativeJournalState.INTERFERENCE_DETECTED: frozenset(
        {NativeJournalState.RECOVERY_REQUIRED}
    ),
}


def legal_next_native_journal_states(
    state: NativeJournalState,
) -> frozenset[NativeJournalState]:
    """Return the set of states ``state`` may legally transition to."""
    if not isinstance(state, NativeJournalState):
        raise TypeError("state must be a NativeJournalState")
    return _LEGAL_NATIVE_JOURNAL_TRANSITIONS[state]


def is_legal_native_journal_transition(
    current: NativeJournalState, target: NativeJournalState
) -> bool:
    if not isinstance(current, NativeJournalState):
        raise TypeError("current must be a NativeJournalState")
    if not isinstance(target, NativeJournalState):
        raise TypeError("target must be a NativeJournalState")
    return target in _LEGAL_NATIVE_JOURNAL_TRANSITIONS[current]


class IllegalNativeJournalTransition(ValueError):
    """Raised when a journal transition crosses a closed edge.

    ``current=None`` means no durable row exists yet for the transaction --
    the only legal way to create one is :meth:`NativePatchJournalStore.prepare`,
    never :meth:`NativePatchJournalStore.transition`.
    """

    def __init__(
        self,
        current: NativeJournalState | None,
        target: NativeJournalState,
        *,
        detail: str | None = None,
    ) -> None:
        self.current = current
        self.target = target
        self.detail = detail
        current_label = current.value if current is not None else "<no durable record>"
        message = (
            f"illegal native journal transition: {current_label} -> {target.value}"
        )
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


# ---------------------------------------------------------------------------
# Byte-granular recovery classification vocabulary
# ---------------------------------------------------------------------------


class NativeByteEventPhase(str, enum.Enum):
    """Durable write-ahead receipt phases for one byte of one operation."""

    WRITE_STARTED = "write_started"
    WRITE_APPLIED = "write_applied"


class NativeByteRecoveryVerdict(str, enum.Enum):
    """Per-byte recovery classification: current value vs. before/after image."""

    BEFORE = "BEFORE"
    """Current value matches expected-current (not yet written)."""

    AFTER = "AFTER"
    """Current value matches the replacement (written)."""

    BOTH = "BOTH"
    """expected-current == replacement for this byte; consistent either way."""

    NEITHER = "NEITHER"
    """Current value matches neither image, or could not be read: interference."""


class NativeOperationRecoveryVerdict(str, enum.Enum):
    """Operation-level verdict reconstructed from its byte verdicts."""

    NOT_APPLIED = "NOT_APPLIED"
    APPLIED = "APPLIED"
    PARTIALLY_APPLIED = "PARTIALLY_APPLIED"
    INTERFERENCE = "INTERFERENCE"


@dataclass(frozen=True, slots=True)
class NativeByteRecoveryEntry:
    ea: int
    verdict: NativeByteRecoveryVerdict
    current_value: int | None


@dataclass(frozen=True, slots=True)
class NativeOperationRecoveryReport:
    operation_id: str
    verdict: NativeOperationRecoveryVerdict
    byte_entries: tuple[NativeByteRecoveryEntry, ...]
    corroborated_by_write_applied_receipt: bool
    """True only when every non-``BOTH`` byte has a durable ``write_applied``
    receipt matching the observed value. An ``APPLIED`` verdict without this
    is an unexplained delta (section 15.1.1 point 4) -- current bytes happen
    to match our intended after-image, but nothing in the write-ahead log
    says we ever wrote them.
    """


@dataclass(frozen=True, slots=True)
class NativeTransactionRecoveryReport:
    transaction_id: NativePatchTransactionId
    recorded_state: NativeJournalState
    operation_reports: tuple[NativeOperationRecoveryReport, ...]
    recommended_state: NativeJournalState


@dataclass(frozen=True, slots=True)
class AppliedMetadataAction:
    """One metadata action that was applied, and the state it replaced.

    ``recorded_before`` is what the database *actually* held immediately
    before the action ran -- not the plan's ``expected_before``, which is an
    assertion about that state rather than the state itself. Reversal replays
    this recorded value, because re-deriving a before-state at restore time
    reads the already-mutated database, which is precisely what is being
    undone (the lesson the function-extent P0 taught).
    """

    operation_id: str
    kind: str
    ea: int
    recorded_before: str
    expected_after: str


@dataclass(frozen=True, slots=True)
class OperationByteRecord:
    """One durably-planned byte, exactly as ``prepare()`` recorded it.

    This is the write-ahead log's own record of what a byte's before/original/
    after values were *planned* to be -- distinct from
    :class:`NativeByteRecoveryEntry`, which additionally carries the
    *currently observed* value and a verdict. Task 6's gateway needs the plain
    planned values (not a verdict) to restore exactly: whether
    ``expected_current == expected_original`` for a given ``ea`` is exactly
    the fact that decides ``revert_byte`` (byte was pristine before this
    transaction) vs. ``patch_byte(ea, expected_current)`` (byte already
    carried an inherited patch before this transaction, and reverting to IDA's
    original layer would erase that inherited patch rather than restore it).
    Reading this back from the durable log -- rather than requiring the
    gateway to keep the original ``NativePatchPlan`` object alive in memory --
    is what makes :meth:`NativePatchJournalStore.restore`-style recovery work
    even across a process restart (section 15.4).
    """

    operation_id: str
    ea: int
    expected_current: int
    expected_original: int
    replacement: int


# ---------------------------------------------------------------------------
# Netnode mirror receipt -- a separate receipt lane, never a state authority.
# ---------------------------------------------------------------------------


class NativeMirrorOutcome(str, enum.Enum):
    MIRROR_WRITTEN = "mirror_written"
    MIRROR_FAILED = "mirror_failed"


@dataclass(frozen=True, slots=True)
class NativeMirrorReceipt:
    """One netnode-mirror attempt receipt.

    Design requirement 4: the mirror is a separate receipt lane that can
    never retroactively change the SQLite transaction's ``state``.
    ``at_state`` is *observational* (the SQLite state at the moment the
    mirror attempt was recorded), not authoritative.
    """

    transaction_id: NativePatchTransactionId
    outcome: NativeMirrorOutcome
    at_state: NativeJournalState
    reason: str | None
    recorded_at: float


# ---------------------------------------------------------------------------
# Transaction record + journal store protocol
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativePatchTransactionRecord:
    transaction_id: NativePatchTransactionId
    plan_id: str
    plan_hash: str
    authorizing_attempt_id: ExecutionAttemptId
    state: NativeJournalState
    has_metadata_actions: bool
    database_identity: str | None
    created_at: float
    updated_at: float


@runtime_checkable
class NativePatchPlanEnvelope(Protocol):
    """Structural view of a plan the journal store needs.

    Not the real ``NativePatchPlan`` (``d810.transforms.native_patch_plan``,
    which sits above this module) -- a minimal duck-typed contract so this
    Protocol's declaration never imports ``transforms`` upward. The concrete
    ``NativePatchPlan`` structurally satisfies this without any explicit
    inheritance.
    """

    plan_id: str
    plan_hash: str
    database_identity: object
    function_identity: object
    authorizing_attempt_id: ExecutionAttemptId
    operations: tuple[object, ...]


@runtime_checkable
class NativePatchJournalStore(Protocol):
    """The SQLite-backed write-ahead journal's storage contract.

    ``d810.backends.ida.native_patch.journal.SQLiteNativePatchJournal`` is
    the (only, for now) concrete implementation.
    """

    def prepare(self, plan: NativePatchPlanEnvelope) -> NativePatchTransactionRecord:
        """Durably commit a new ``PREPARED`` transaction row for ``plan``.

        Must not return until the durable commit has succeeded -- design
        requirement 3: "PREPARED must be durably committed before a
        transaction is exposed for application."
        """
        ...

    def transition(
        self,
        transaction_id: NativePatchTransactionId,
        target_state: NativeJournalState,
        *,
        note: str | None = None,
    ) -> NativePatchTransactionRecord: ...

    def get(
        self, transaction_id: NativePatchTransactionId
    ) -> NativePatchTransactionRecord | None: ...

    def recoverable_transaction_ids(
        self, *, database_identity: str
    ) -> tuple[NativePatchTransactionId, ...]:
        """Durably enumerate interrupted apply/restore transactions that may
        be reconciled automatically at startup."""
        ...

    def record_byte_event(
        self,
        transaction_id: NativePatchTransactionId,
        operation_id: str,
        ea: int,
        phase: NativeByteEventPhase,
        *,
        expected_current: int,
        expected_original: int,
        replacement: int,
    ) -> None: ...

    def record_mirror_receipt(
        self,
        transaction_id: NativePatchTransactionId,
        outcome: NativeMirrorOutcome,
        *,
        reason: str | None = None,
    ) -> NativeMirrorReceipt: ...

    def mirror_receipts(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[NativeMirrorReceipt, ...]: ...

    def classify_recovery(
        self,
        transaction_id: NativePatchTransactionId,
        read_current_bytes: object,
    ) -> NativeTransactionRecoveryReport: ...

    def operation_bytes(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[OperationByteRecord, ...]:
        """Every durably-planned byte for ``transaction_id``, in ``(operation_id,
        ea)`` order. See :class:`OperationByteRecord` for why this -- not the
        original in-memory ``NativePatchPlan`` -- is what restore reads from.
        """
        ...

    def operation_ownership(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[int, tuple[tuple[int, int], ...]]]:
        """Pre-patch function extent per operation:
        ``{operation_id: (owning_function_entry_ea, ((start, end), ...))}``.

        Durable for the same reason the bytes are. Restoring bytes is not
        restoring state: erasing a branch orphans its target block, reanalysis
        shrinks the owning function, and a restore that re-derives ownership
        from the live database reads the already-shrunken extent -- so the
        function never comes back.
        """
        ...

    def operation_flow_refs(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[tuple[int, int, int, bool], ...]]:
        """Exact pre-patch internal code refs per operation."""
        ...

    def operation_function_metadata(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[int, tuple[bytes, bytes | None, bytes | None] | None]]:
        """Exact inherited flags and SDK-serialized function type per operation."""
        ...
