"""Pure conversion from a captured native-origin edge to a lowered Mode-A
``NativePatchOperation``.

Task 5 ("Read-only capture, lowering, and preflight") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. Lowers only
direct/conditional Mode-A edges (section 10 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md``): an owned terminator region is
replaced in place with one jump, or a ``jcc <true>; jmp <false>`` stencil,
never with a relocated body instruction (invariant 11).

Layer correction -- this module must not import the encoder
--------------------------------------------------------------------------

``d810.transforms`` (rank 9) sits *below* ``d810.backends`` (rank 6) in the
layered-architecture contract, so importing
``d810.backends.ida.native_patch.encoder`` here would be the exact upward
import the contract forbids. The inversion (identical to the one already
applied to the policy gate and the observation handler in Task 4): this
module depends only on the ``EncodingProvider`` Protocol declared in
``d810.capabilities.native_patch`` (rank 12, a lower layer than both
``transforms`` and ``backends``); ``MinimalX86BranchEncoder`` in
``d810.backends.ida.native_patch.encoder`` implements that Protocol, and the
composition root injects it. This module never imports ``d810.backends``.

The pure-control-transfer mnemonic check (``_is_pure_control_transfer_mnemonic``)
is a small, self-contained rule duplicated here rather than imported from the
encoder for the same reason -- it is a naming convention, not encoder logic,
and importing the encoder module just to reuse it would reintroduce the
forbidden edge.

Edge-state authority
--------------------

Every lowering entry point requires a positive portable ``EdgeStateContract``
issued by the pass-owned proof adapter. The contract proves target live-ins,
stack state, skipped effects, aliases, and calls; lowering still restricts the
writable span to exactly one pure native control-transfer instruction. A
positive state proof therefore cannot accidentally authorize overwriting body
instructions or a state-defining terminator.

Origin coverage (global constraint)
--------------------------------------------------------------------------

``PARTIAL``, ``AMBIGUOUS``, and ``SYNTHETIC`` :class:`~d810.ir.native_origin.
NativeOriginCoverage` are all automatic abstention reasons -- see
``_origin_state_check``. Only ``COMPLETE`` coverage may ever be lowered.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from enum import Enum

from d810.capabilities.native_patch import (
    EncodingProvider,
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.ir.native_origin import NativeOriginCoverage, NativeOriginSpan
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.semantics import PredicateKind
from d810.transforms.native_patch_plan import (
    InheritedPatchRow,
    NativeAddressRange,
    NativeEncodingEvidence,
    NativeFunctionOwnership,
    NativeIncomingRef,
    NativeItemShape,
    NativePatchOperation,
    NativeRestoreSnapshot,
)

__all__ = [
    "NativeEdgeAbstentionReason",
    "NativeEdgeCaptureEvidence",
    "NativeEdgeLoweringOutcome",
    "lower_conditional_edge",
    "lower_direct_edge",
    "lower_removed_edge",
]


class NativeEdgeAbstentionReason(str, Enum):
    """Stable reasons this module produces on its own (not forwarded from an
    ``EncodingProvider`` abstention -- those pass through verbatim as plain
    strings; see ``lower_direct_edge``/``lower_conditional_edge``).

    ``PARTIAL_NATIVE_ORIGIN``, ``AMBIGUOUS_NATIVE_ORIGIN``, and
    ``UNREPRESENTABLE_BRANCH`` reuse the stable vocabulary from section 16 of
    ``_gitless/REVERSIBLE-NATIVE-PATCHES.md``. ``SYNTHETIC_NATIVE_ORIGIN`` and
    ``EDGE_STATE_CONTRACT_REQUIRED`` are not in that list -- both are
    deliberate additions documented in the module and report: section 16 only
    names partial/ambiguous explicitly, and the EdgeStateContract reason is
    part of the Stage C authorization boundary (see the module docstring).
    """

    PARTIAL_NATIVE_ORIGIN = "PARTIAL_NATIVE_ORIGIN"
    AMBIGUOUS_NATIVE_ORIGIN = "AMBIGUOUS_NATIVE_ORIGIN"
    SYNTHETIC_NATIVE_ORIGIN = "SYNTHETIC_NATIVE_ORIGIN"
    EDGE_STATE_CONTRACT_REQUIRED = "EDGE_STATE_CONTRACT_REQUIRED"
    INSTRUCTION_SPLIT = "INSTRUCTION_SPLIT"
    UNREPRESENTABLE_BRANCH = "UNREPRESENTABLE_BRANCH"


def _is_pure_control_transfer_mnemonic(mnemonic: str) -> bool:
    """Whether ``mnemonic`` names an instruction that only transfers control.

    This is the ``EdgeStateContract`` gate: it asks "would overwriting this
    instruction destroy any register, flag, memory or stack effect?" Every x86
    jump answers no, so **unconditional ``jmp`` is deliberately included** --
    replacing a ``jmp`` with another branch eliminates no definition and needs
    no liveness proof.

    That is why this differs from
    ``d810.backends.ida.native_patch.observation._is_conditional_branch``,
    which excludes ``jmp``: that predicate hunts for *conditional* branches as
    rewrite candidates, a different question. Do not "fix" this by adding an
    ``!= "jmp"`` clause to match it -- that would make lowering abstain on
    ``jmp``-terminated regions that are provably safe to rewrite.

    Prefix-matching rather than a finite mnemonic set is deliberate. IDA's
    decoder does not always print the short-name spelling one would guess by
    hand; a hand-maintained set was proved wrong against the live
    ``fake_jumps.dll`` fixture on this module's first Docker run, abstaining on
    seven genuine single-branch regions. Every x86 jump mnemonic IDA emits
    starts with ``"j"`` (``je``, ``jz``, ``jnb``, ``jrcxz``, ``jmp``, ...) and
    no non-branch x86 mnemonic does.
    """
    return mnemonic.startswith("j")


# Portable PredicateKind -> Condition member/alias name (see
# d810.backends.ida.native_patch.encoder.Condition.__members__). TRUTHY (m_jcnd)
# tests a value rather than a condition-code flag, so it has no single-Jcc
# hardware form in this minimal model and is deliberately absent -- a lookup
# miss abstains with UNREPRESENTABLE_BRANCH.
_PREDICATE_TO_CONDITION_NAME: dict[PredicateKind, str] = {
    PredicateKind.EQ: "E",
    PredicateKind.NE: "NE",
    PredicateKind.UGE: "AE",
    PredicateKind.UGT: "A",
    PredicateKind.ULE: "BE",
    PredicateKind.ULT: "B",
    PredicateKind.SGE: "GE",
    PredicateKind.SGT: "G",
    PredicateKind.SLE: "LE",
    PredicateKind.SLT: "L",
}


@dataclass(frozen=True, slots=True)
class NativeEdgeCaptureEvidence:
    """Plain, already-captured facts a backend caller read from the live
    database, handed to lowering by value.

    Bundles exactly the ``NativePatchOperation`` fields this pure module
    cannot derive on its own (it never touches IDA). The backend-layer
    ``capture`` module builds one of these from live reads; lowering only
    ever sees this plain, provider-neutral snapshot.
    """

    expected_current_bytes: bytes
    expected_original_bytes: bytes
    expected_patch_rows: tuple[InheritedPatchRow, ...]
    expected_item_shape: NativeItemShape
    expected_incoming_refs: tuple[NativeIncomingRef, ...]
    expected_function_ownership: NativeFunctionOwnership
    restore_snapshot: NativeRestoreSnapshot


@dataclass(frozen=True, slots=True)
class NativeEdgeLoweringOutcome:
    """Either a lowered ``NativePatchOperation`` or a stable abstention reason."""

    operation: NativePatchOperation | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if (self.operation is None) == (self.reason is None):
            raise ValueError("exactly one of operation/reason must be set")

    @property
    def ok(self) -> bool:
        return self.operation is not None


def _origin_state_check(
    origin_span: NativeOriginSpan,
    state_contract: EdgeStateContract | None,
) -> str | None:
    """Return an abstention reason, or ``None`` if lowering may proceed.

    Coverage is checked first (global constraint: partial/ambiguous/synthetic
    are automatic abstentions). Only a ``COMPLETE`` span may reach the
    state-store check, which requires the span to be exactly one pure
    control-transfer instruction -- see the module docstring.
    """
    if origin_span.coverage is NativeOriginCoverage.PARTIAL:
        return NativeEdgeAbstentionReason.PARTIAL_NATIVE_ORIGIN.value
    if origin_span.coverage is NativeOriginCoverage.AMBIGUOUS:
        return NativeEdgeAbstentionReason.AMBIGUOUS_NATIVE_ORIGIN.value
    if origin_span.coverage is NativeOriginCoverage.SYNTHETIC:
        return NativeEdgeAbstentionReason.SYNTHETIC_NATIVE_ORIGIN.value

    if (
        not isinstance(state_contract, EdgeStateContract)
        or not state_contract.permits_control_only_relink
    ):
        return NativeEdgeAbstentionReason.EDGE_STATE_CONTRACT_REQUIRED.value

    # COMPLETE.
    if len(origin_span.instructions) != 1:
        return NativeEdgeAbstentionReason.EDGE_STATE_CONTRACT_REQUIRED.value
    if not _is_pure_control_transfer_mnemonic(origin_span.instructions[0].mnemonic):
        return NativeEdgeAbstentionReason.EDGE_STATE_CONTRACT_REQUIRED.value
    return None


def _build_operation(
    *,
    operation_id: str,
    origin_span: NativeOriginSpan,
    successors: tuple[int, ...],
    replacement_bytes: bytes,
    expected_after_shape: NativeInstructionSequenceShape,
    capture: NativeEdgeCaptureEvidence,
    provider: EncodingProvider,
    provider_id: str,
    provider_version: str,
    bitness: int,
) -> NativePatchOperation:
    before_insn = origin_span.instructions[0]
    expected_before_shape = NativeInstructionSequenceShape(
        heads=(
            NativeInstructionHead(
                ea=before_insn.ea,
                length=before_insn.length,
                mnemonic=before_insn.mnemonic,
                operand_shapes=before_insn.operand_shape,
                successors=(before_insn.end_ea,),
            ),
        )
    )
    # Independent re-verification: decode the emitted bytes again rather than
    # trust expected_after_shape, matching EncodingProvider.decode's contract.
    independent_decode = provider.decode(
        origin_span.start_ea, replacement_bytes, bitness=bitness
    )
    encoding_evidence = NativeEncodingEvidence(
        provider_id=provider_id,
        provider_version=provider_version,
        final_ea=origin_span.start_ea,
        opcode_intent="; ".join(h.mnemonic for h in expected_after_shape.heads),
        emitted_hash=hashlib.sha256(replacement_bytes).hexdigest(),
        independent_decode_hash=hashlib.sha256(
            repr(dataclasses.astuple(independent_decode)).encode("utf-8")
        ).hexdigest(),
    )
    return NativePatchOperation(
        operation_id=operation_id,
        range=NativeAddressRange(origin_span.start_ea, origin_span.end_ea),
        expected_current_bytes=capture.expected_current_bytes,
        expected_original_bytes=capture.expected_original_bytes,
        expected_patch_rows=capture.expected_patch_rows,
        expected_before_shape=expected_before_shape,
        expected_item_shape=capture.expected_item_shape,
        expected_incoming_refs=capture.expected_incoming_refs,
        expected_function_ownership=capture.expected_function_ownership,
        replacement_bytes=replacement_bytes,
        expected_after_shape=expected_after_shape,
        expected_after_successors=successors,
        encoding_evidence=encoding_evidence,
        # Version 1 relocates no body instruction (invariant 11), and Mode A's
        # same-size NOP-padded replacement never changes item boundaries
        # ahead of a live apply -- metadata_actions population (RECREATE_ITEM
        # planning) is deferred to Task 6's gateway, which owns post-write
        # item recreation with live data this pure module does not have.
        relocation_evidence=(),
        metadata_actions=(),
        restore_snapshot=capture.restore_snapshot,
    )


def lower_direct_edge(
    *,
    operation_id: str,
    origin_span: NativeOriginSpan,
    target_ea: int,
    known_instruction_heads: frozenset[int],
    capture: NativeEdgeCaptureEvidence,
    provider: EncodingProvider,
    provider_id: str,
    provider_version: str,
    bitness: int = 64,
    state_contract: EdgeStateContract | None = None,
) -> NativeEdgeLoweringOutcome:
    """Lower an owned terminator region to a single unconditional jump."""
    reason = _origin_state_check(origin_span, state_contract)
    if reason is not None:
        return NativeEdgeLoweringOutcome(reason=reason)
    if target_ea not in known_instruction_heads:
        return NativeEdgeLoweringOutcome(
            reason=NativeEdgeAbstentionReason.INSTRUCTION_SPLIT.value
        )

    result = provider.encode_direct_jump(
        origin_span.start_ea, origin_span.end_ea, target_ea, bitness=bitness
    )
    if not result.ok:
        return NativeEdgeLoweringOutcome(reason=result.reason)

    return NativeEdgeLoweringOutcome(
        operation=_build_operation(
            operation_id=operation_id,
            origin_span=origin_span,
            successors=(target_ea,),
            replacement_bytes=result.replacement_bytes,
            expected_after_shape=result.expected_after_shape,
            capture=capture,
            provider=provider,
            provider_id=provider_id,
            provider_version=provider_version,
            bitness=bitness,
        )
    )


def lower_removed_edge(
    *,
    operation_id: str,
    origin_span: NativeOriginSpan,
    capture: NativeEdgeCaptureEvidence,
    provider: EncodingProvider,
    provider_id: str,
    provider_version: str,
    bitness: int = 64,
    state_contract: EdgeStateContract | None = None,
) -> NativeEdgeLoweringOutcome:
    """Erase an owned terminator region so control falls through.

    The correction for a branch a direction proof shows is *never* taken. Its
    counterpart is :func:`lower_direct_edge` with the taken target, for a
    branch proven always taken.

    Deliberately takes no ``target_ea`` and does no ``known_instruction_heads``
    lookup. The surviving edge is ``origin_span.end_ea``, and the state check
    below has already established the span is exactly one whole instruction --
    so its end is the next instruction's head by construction, and there is no
    ``INSTRUCTION_SPLIT`` case to guard. Adding a head lookup here would reject
    valid regions whenever the caller's head set happened not to enumerate the
    fallthrough.
    """
    reason = _origin_state_check(origin_span, state_contract)
    if reason is not None:
        return NativeEdgeLoweringOutcome(reason=reason)

    result = provider.encode_nop_fill(
        origin_span.start_ea, origin_span.end_ea, bitness=bitness
    )
    if not result.ok:
        return NativeEdgeLoweringOutcome(reason=result.reason)

    return NativeEdgeLoweringOutcome(
        operation=_build_operation(
            operation_id=operation_id,
            origin_span=origin_span,
            successors=(origin_span.end_ea,),
            replacement_bytes=result.replacement_bytes,
            expected_after_shape=result.expected_after_shape,
            capture=capture,
            provider=provider,
            provider_id=provider_id,
            provider_version=provider_version,
            bitness=bitness,
        )
    )


def lower_conditional_edge(
    *,
    operation_id: str,
    origin_span: NativeOriginSpan,
    condition: PredicateKind,
    true_target_ea: int,
    false_target_ea: int,
    known_instruction_heads: frozenset[int],
    capture: NativeEdgeCaptureEvidence,
    provider: EncodingProvider,
    provider_id: str,
    provider_version: str,
    bitness: int = 64,
    state_contract: EdgeStateContract | None = None,
) -> NativeEdgeLoweringOutcome:
    """Lower an owned terminator region to ``jcc <true>; jmp <false>``."""
    reason = _origin_state_check(origin_span, state_contract)
    if reason is not None:
        return NativeEdgeLoweringOutcome(reason=reason)
    if (
        true_target_ea not in known_instruction_heads
        or false_target_ea not in known_instruction_heads
    ):
        return NativeEdgeLoweringOutcome(
            reason=NativeEdgeAbstentionReason.INSTRUCTION_SPLIT.value
        )

    condition_name = _PREDICATE_TO_CONDITION_NAME.get(condition)
    if condition_name is None:
        return NativeEdgeLoweringOutcome(
            reason=NativeEdgeAbstentionReason.UNREPRESENTABLE_BRANCH.value
        )

    result = provider.encode_conditional(
        origin_span.start_ea,
        origin_span.end_ea,
        condition=condition_name,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        bitness=bitness,
    )
    if not result.ok:
        return NativeEdgeLoweringOutcome(reason=result.reason)

    return NativeEdgeLoweringOutcome(
        operation=_build_operation(
            operation_id=operation_id,
            origin_span=origin_span,
            successors=(true_target_ea, false_target_ea),
            replacement_bytes=result.replacement_bytes,
            expected_after_shape=result.expected_after_shape,
            capture=capture,
            provider=provider,
            provider_id=provider_id,
            provider_version=provider_version,
            bitness=bitness,
        )
    )
