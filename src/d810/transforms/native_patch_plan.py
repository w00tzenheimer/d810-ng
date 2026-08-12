"""Pure, provider-neutral native-patch plan/operation records and hashing.

Implements the minimum schema from section 14.1/14.2 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md``, folded into Task 2 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. Every record
here is a frozen dataclass validated at construction; there is no live IDA
object anywhere in this module and no method here writes anything.

Layering
--------

``d810.transforms`` sits above ``d810.capabilities`` and below
``d810.backends`` in the layered-architecture contract. This module may
import ``d810.capabilities`` (for :class:`~d810.capabilities.native_patch.
NativeInstructionSequenceShape`, reused for both ``expected_before_shape``
and ``expected_after_shape``) and ``d810.core`` (for
:class:`~d810.core.execution_journal.ExecutionAttemptId`, the authorizing
attempt every plan must carry per the global constraint "your plan must carry
its authorizing ExecutionAttemptId"). It imports nothing from ``d810.backends``
-- ``d810.backends.ida.native_patch.journal`` imports this module downward
instead.

Expected-before fields are authorization, not diagnostics (design requirement
6): a mismatch at apply time must abstain before writing, which is why every
field this module validates is checked at construction rather than deferred
to a later "real" validation pass.

Plan hashing -- what is and is not included (interpretation decision)
-----------------------------------------------------------------------

The plan does not spell out ``plan_hash``'s exact input set beyond "changing
expected-before bytes must change plan_hash." :func:`NativePatchPlan.plan_hash`
is a *content* hash: it excludes ``plan_id`` (an instance identity, not
content) and ``authorizing_attempt_id`` (which attempt tried this plan is
provenance, not content), and each operation's hash similarly excludes
``operation_id``. Two plans built independently with identical operations but
different ids/attempts hash identically. This is deliberate: certificates
(section 14.5) store a ``native_plan_hash`` specifically to answer "was this
exact plan content already applied," which only works if the hash is
attempt/instance-independent. See the report for this decision being flagged
as an interpretation rather than silently resolved.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
from dataclasses import dataclass

from d810.capabilities.native_patch import NativeInstructionSequenceShape
from d810.core.execution_journal import ExecutionAttemptId

__all__ = [
    "InheritedPatchRow",
    "NativeAddressRange",
    "NativeDatabaseIdentity",
    "NativeEncodingEvidence",
    "NativeFunctionIdentity",
    "NativeFunctionOwnership",
    "NativeIncomingRef",
    "NativeItemHead",
    "NativeItemKind",
    "NativeItemShape",
    "NativeMetadataAction",
    "NativeMetadataActionKind",
    "NativePatchOperation",
    "NativePatchPlan",
    "NativeRelocationEvidence",
    "NativeRestoreSnapshot",
    "OverlappingNativePatchOperationsError",
]


def _require_identifier(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


def _stable_hash(content: tuple) -> str:
    """Deterministic content hash: sha256 of a canonical tuple's ``repr``.

    Every input to this function is already a plain tuple of ints/strs/bytes
    (via ``dataclasses.astuple`` or an explicit ``_content_for_hash``), so
    ``repr`` is fully deterministic within a run -- no dict/set ordering, no
    float formatting ambiguity, no object-identity leakage.
    """
    return hashlib.sha256(repr(content).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# NativeAddressRange
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeAddressRange:
    """Inclusive start EA, exclusive end EA. Never empty."""

    start_ea: int
    end_ea: int

    def __post_init__(self) -> None:
        if not isinstance(self.start_ea, int) or isinstance(self.start_ea, bool):
            raise TypeError("start_ea must be an int")
        if not isinstance(self.end_ea, int) or isinstance(self.end_ea, bool):
            raise TypeError("end_ea must be an int")
        if self.start_ea < 0:
            raise ValueError("start_ea must be non-negative")
        if self.end_ea <= self.start_ea:
            raise ValueError("range must be non-empty: end_ea must exceed start_ea")

    @property
    def size(self) -> int:
        return self.end_ea - self.start_ea

    def overlaps(self, other: NativeAddressRange) -> bool:
        if not isinstance(other, NativeAddressRange):
            raise TypeError("other must be a NativeAddressRange")
        return self.start_ea < other.end_ea and other.start_ea < self.end_ea


# ---------------------------------------------------------------------------
# Identity records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NativeDatabaseIdentity:
    idb_uuid: str
    input_file_hash: str
    processor: str
    bitness: int
    image_base: int
    database_path_hash: str


@dataclass(frozen=True, slots=True)
class NativeFunctionIdentity:
    entry_ea: int
    chunk_ranges: tuple[NativeAddressRange, ...]
    inherited_bytes_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.chunk_ranges, tuple) or not all(
            isinstance(r, NativeAddressRange) for r in self.chunk_ranges
        ):
            raise TypeError("chunk_ranges must be a tuple of NativeAddressRange")


# ---------------------------------------------------------------------------
# Support records (section 14.2 table)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InheritedPatchRow:
    ea: int
    file_position: int
    ida_original_value: int
    inherited_current_value: int


class NativeItemKind(str, enum.Enum):
    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class NativeItemHead:
    ea: int
    size: int
    kind: NativeItemKind
    user_defined: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NativeItemKind):
            raise TypeError("kind must be a NativeItemKind")
        if self.size <= 0:
            raise ValueError("size must be positive")


@dataclass(frozen=True, slots=True)
class NativeItemShape:
    heads: tuple[NativeItemHead, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.heads, tuple) or not all(
            isinstance(h, NativeItemHead) for h in self.heads
        ):
            raise TypeError("heads must be a tuple of NativeItemHead")


@dataclass(frozen=True, slots=True)
class NativeIncomingRef:
    source_ea: int
    target_ea: int
    kind: str
    ownership: str  # "user" | "auto"

    def __post_init__(self) -> None:
        if self.ownership not in ("user", "auto"):
            raise ValueError("ownership must be 'user' or 'auto'")


@dataclass(frozen=True, slots=True)
class NativeFunctionOwnership:
    owning_function_entry_ea: int
    chunk_ranges: tuple[NativeAddressRange, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.chunk_ranges, tuple) or not all(
            isinstance(r, NativeAddressRange) for r in self.chunk_ranges
        ):
            raise TypeError("chunk_ranges must be a tuple of NativeAddressRange")


@dataclass(frozen=True, slots=True)
class NativeEncodingEvidence:
    provider_id: str
    provider_version: str
    final_ea: int
    opcode_intent: str
    emitted_hash: str
    independent_decode_hash: str


@dataclass(frozen=True, slots=True)
class NativeRelocationEvidence:
    original_ea: int
    final_ea: int
    kind: str
    target_ea: int
    original_displacement: int
    rewritten_displacement: int


class NativeMetadataActionKind(str, enum.Enum):
    RECREATE_ITEM = "recreate_item"
    UPDATE_XREF = "update_xref"
    SET_FUNCTION_TAIL = "set_function_tail"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class NativeMetadataAction:
    """A typed, non-byte change plus its expected-before/-after state.

    ``expected_before``/``expected_after`` are opaque description tokens
    (e.g. ``"code:2"``): the concrete IDA-specific metadata shapes (item
    kind, xref set, function-tail range) belong to Task 5's capture module,
    not to this provider-neutral vocabulary.
    """

    kind: NativeMetadataActionKind
    ea: int
    expected_before: str
    expected_after: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NativeMetadataActionKind):
            raise TypeError("kind must be a NativeMetadataActionKind")


@dataclass(frozen=True, slots=True)
class NativeRestoreSnapshot:
    """Everything a restore needs to reconstruct the pre-patch state."""

    inherited_bytes: bytes
    inherited_patch_rows: tuple[InheritedPatchRow, ...]
    item_shape: NativeItemShape
    incoming_refs: tuple[NativeIncomingRef, ...]
    function_ownership: NativeFunctionOwnership
    switch_fixup_metadata: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.inherited_bytes, bytes):
            raise TypeError("inherited_bytes must be bytes")
        if not isinstance(self.item_shape, NativeItemShape):
            raise TypeError("item_shape must be a NativeItemShape")
        if not isinstance(self.function_ownership, NativeFunctionOwnership):
            raise TypeError("function_ownership must be a NativeFunctionOwnership")


# ---------------------------------------------------------------------------
# Operation and Plan
# ---------------------------------------------------------------------------

_PATCH_CLASSES = frozenset({"lifting_normalization", "semantic_deobfuscation"})
_FALLBACK_POLICIES = frozenset({"mba", "preopt", "no_patch"})


@dataclass(frozen=True, slots=True)
class NativePatchOperation:
    """One byte-range rewrite plus its full authorization/restore evidence.

    See design requirement 6: expected current/original bytes, inherited
    patch rows, before/after decoded shapes, owned metadata actions, and a
    restore snapshot are all mandatory, non-optional fields.
    """

    operation_id: str
    range: NativeAddressRange
    expected_current_bytes: bytes
    expected_original_bytes: bytes
    expected_patch_rows: tuple[InheritedPatchRow, ...]
    expected_before_shape: NativeInstructionSequenceShape
    expected_item_shape: NativeItemShape
    expected_incoming_refs: tuple[NativeIncomingRef, ...]
    expected_function_ownership: NativeFunctionOwnership
    replacement_bytes: bytes
    expected_after_shape: NativeInstructionSequenceShape
    expected_after_successors: tuple[int, ...]
    encoding_evidence: NativeEncodingEvidence
    relocation_evidence: tuple[NativeRelocationEvidence, ...]
    metadata_actions: tuple[NativeMetadataAction, ...]
    restore_snapshot: NativeRestoreSnapshot

    def __post_init__(self) -> None:
        _require_identifier(self.operation_id, "operation_id")
        if not isinstance(self.range, NativeAddressRange):
            raise TypeError("range must be a NativeAddressRange")

        for label in (
            "expected_current_bytes",
            "expected_original_bytes",
            "replacement_bytes",
        ):
            value = getattr(self, label)
            if not isinstance(value, bytes):
                raise TypeError(f"{label} must be bytes")
            if len(value) != self.range.size:
                raise ValueError(
                    f"{label} must cover the full operation range "
                    f"({len(value)} bytes given, {self.range.size} expected)"
                )

        if not isinstance(self.expected_before_shape, NativeInstructionSequenceShape):
            raise TypeError(
                "expected_before_shape must be a NativeInstructionSequenceShape"
            )
        if self.range.size > 0 and self.expected_before_shape.is_empty:
            raise ValueError(
                "expected_before_shape must describe at least one instruction "
                "for a non-empty range"
            )

        if not isinstance(self.expected_after_shape, NativeInstructionSequenceShape):
            raise TypeError(
                "expected_after_shape must be a NativeInstructionSequenceShape"
            )
        if len(self.replacement_bytes) > 0 and self.expected_after_shape.is_empty:
            raise ValueError(
                "expected_after_shape must describe at least one instruction "
                "when replacement_bytes is non-empty"
            )

        if not isinstance(self.expected_item_shape, NativeItemShape):
            raise TypeError("expected_item_shape must be a NativeItemShape")
        if not isinstance(self.expected_function_ownership, NativeFunctionOwnership):
            raise TypeError(
                "expected_function_ownership must be a NativeFunctionOwnership"
            )
        if not isinstance(self.encoding_evidence, NativeEncodingEvidence):
            raise TypeError("encoding_evidence must be a NativeEncodingEvidence")

        if not isinstance(self.expected_patch_rows, tuple):
            raise TypeError("expected_patch_rows must be a tuple")
        if not isinstance(self.expected_incoming_refs, tuple):
            raise TypeError("expected_incoming_refs must be a tuple")
        if not isinstance(self.relocation_evidence, tuple):
            raise TypeError("relocation_evidence must be a tuple")
        if not isinstance(self.metadata_actions, tuple):
            raise TypeError("metadata_actions must be a tuple")
        if not isinstance(self.expected_after_successors, tuple):
            raise TypeError("expected_after_successors must be a tuple")

        # Missing/degenerate restore state (design requirement 6 + Task 2
        # Step 1 negative "missing restore state"): the snapshot must be
        # present and must actually cover this operation's range, or a
        # restore built from it would be silently incomplete.
        if not isinstance(self.restore_snapshot, NativeRestoreSnapshot):
            raise TypeError("restore_snapshot must be a NativeRestoreSnapshot")
        if len(self.restore_snapshot.inherited_bytes) != self.range.size:
            raise ValueError(
                "restore_snapshot.inherited_bytes must cover the full operation range"
            )

    def _content_for_hash(self) -> tuple:
        """Everything except ``operation_id`` (instance identity, not content)."""
        return (
            self.range.start_ea,
            self.range.end_ea,
            self.expected_current_bytes,
            self.expected_original_bytes,
            tuple(dataclasses.astuple(row) for row in self.expected_patch_rows),
            dataclasses.astuple(self.expected_before_shape),
            dataclasses.astuple(self.expected_item_shape),
            tuple(dataclasses.astuple(ref) for ref in self.expected_incoming_refs),
            dataclasses.astuple(self.expected_function_ownership),
            self.replacement_bytes,
            dataclasses.astuple(self.expected_after_shape),
            self.expected_after_successors,
            dataclasses.astuple(self.encoding_evidence),
            tuple(dataclasses.astuple(r) for r in self.relocation_evidence),
            tuple(dataclasses.astuple(m) for m in self.metadata_actions),
            dataclasses.astuple(self.restore_snapshot),
        )


class OverlappingNativePatchOperationsError(ValueError):
    """Two operations in one plan claim overlapping, non-identical ranges.

    Invariant 5: "Operations do not overlap. Byte-identical overlaps may be
    coalesced only under the same proof, owner, and restore snapshot." This
    implementation's resolution of "byte-identical": the two operations'
    ranges must be exactly equal (not merely intersecting) and their
    current/original/replacement bytes and restore snapshot must be equal --
    any partial overlap is always rejected, regardless of content, since a
    partial overlap is inherently ambiguous to encode safely. See the report
    for this being flagged as an interpretation.
    """

    def __init__(
        self, first: NativePatchOperation, second: NativePatchOperation
    ) -> None:
        self.first = first
        self.second = second
        super().__init__(
            f"operations {first.operation_id!r} and {second.operation_id!r} "
            "claim overlapping, non-identical ranges"
        )


def _operations_conflict(a: NativePatchOperation, b: NativePatchOperation) -> bool:
    if not a.range.overlaps(b.range):
        return False
    return not (
        a.range == b.range
        and a.expected_current_bytes == b.expected_current_bytes
        and a.expected_original_bytes == b.expected_original_bytes
        and a.replacement_bytes == b.replacement_bytes
        and a.restore_snapshot == b.restore_snapshot
    )


@dataclass(frozen=True, slots=True)
class NativePatchPlan:
    """A complete, provider-neutral native-patch plan. Writes nothing itself.

    ``execution_safe`` is always ``False`` (invariant 23: "All certificates
    state execution_safe=false until a separate runtime-parity project proves
    otherwise" -- the same posture applies to the plan that authorizes the
    write). ``authorizing_attempt_id`` is mandatory: see the "carry its
    authorizing ExecutionAttemptId" global constraint.
    """

    plan_id: str
    schema_version: int
    patch_class: str  # "lifting_normalization" | "semantic_deobfuscation"
    database_identity: NativeDatabaseIdentity
    function_identity: NativeFunctionIdentity
    inherited_function_fingerprint: str
    target_cfg_fingerprint: str
    native_origin_map_fingerprint: str
    architecture: str
    bitness: int
    endianness: str
    processor: str
    issuer_id: str
    proof_id: str
    proof_hash: str
    provenance: tuple[str, ...]
    operations: tuple[NativePatchOperation, ...]
    fallback_policy: str  # "mba" | "preopt" | "no_patch"
    authorizing_attempt_id: ExecutionAttemptId
    execution_safe: bool = False

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "plan_id")
        if not isinstance(self.schema_version, int) or isinstance(
            self.schema_version, bool
        ):
            raise TypeError("schema_version must be an int")
        if self.schema_version <= 0:
            raise ValueError("schema_version must be positive")

        if self.patch_class not in _PATCH_CLASSES:
            raise ValueError(f"patch_class must be one of {sorted(_PATCH_CLASSES)}")
        if self.fallback_policy not in _FALLBACK_POLICIES:
            raise ValueError(
                f"fallback_policy must be one of {sorted(_FALLBACK_POLICIES)}"
            )

        if not isinstance(self.database_identity, NativeDatabaseIdentity):
            raise TypeError("database_identity must be a NativeDatabaseIdentity")
        if not isinstance(self.function_identity, NativeFunctionIdentity):
            raise TypeError("function_identity must be a NativeFunctionIdentity")

        for label in (
            "inherited_function_fingerprint",
            "target_cfg_fingerprint",
            "native_origin_map_fingerprint",
            "architecture",
            "endianness",
            "processor",
            "issuer_id",
            "proof_id",
            "proof_hash",
        ):
            _require_identifier(getattr(self, label), label)

        if not isinstance(self.provenance, tuple):
            raise TypeError("provenance must be a tuple")

        if not isinstance(self.operations, tuple):
            raise TypeError("operations must be a tuple")
        if len(self.operations) == 0:
            raise ValueError("a plan must contain at least one operation")
        for op in self.operations:
            if not isinstance(op, NativePatchOperation):
                raise TypeError("operations must contain only NativePatchOperation")

        for i, a in enumerate(self.operations):
            for b in self.operations[i + 1 :]:
                if _operations_conflict(a, b):
                    raise OverlappingNativePatchOperationsError(a, b)

        if not isinstance(self.authorizing_attempt_id, ExecutionAttemptId):
            raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")

        if self.execution_safe is not False:
            raise ValueError("execution_safe must be False (invariant 23)")

    def _content_for_hash(self) -> tuple:
        """Everything except ``plan_id`` and ``authorizing_attempt_id``.

        See the module docstring: ``plan_hash`` is a content hash, not an
        instance fingerprint.
        """
        return (
            self.schema_version,
            self.patch_class,
            dataclasses.astuple(self.database_identity),
            dataclasses.astuple(self.function_identity),
            self.inherited_function_fingerprint,
            self.target_cfg_fingerprint,
            self.native_origin_map_fingerprint,
            self.architecture,
            self.bitness,
            self.endianness,
            self.processor,
            self.issuer_id,
            self.proof_id,
            self.proof_hash,
            self.provenance,
            tuple(op._content_for_hash() for op in self.operations),
            self.fallback_policy,
        )

    @property
    def plan_hash(self) -> str:
        return _stable_hash(self._content_for_hash())
