"""Lower one frozen Stage C CFG intent into one aggregate native plan."""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from enum import Enum

from d810.backends.ida.native_patch.capture import (
    LiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.origin_mapper import NativeOriginMapper
from d810.capabilities.native_patch import (
    EncodingProvider,
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.core.execution_journal import ExecutionAttemptId
from d810.core.input_identity_attestation import InputIdentityAttestation
from d810.ir.native_origin import NativeOriginCoverage, NativeOriginSpan
from d810.ir.native_range_projection import NativeRange
from d810.transforms.native_cfg_normalization import (
    NativeCfgBlockRangeBinding,
    NativeCfgEdgeKind,
    NativeCfgNormalizationIntent,
)
from d810.transforms.native_patch_lowering import (
    lower_conditional_edge,
    lower_direct_edge,
    lower_removed_edge,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
    NativePatchOperation,
    NativePatchPlan,
    OverlappingNativePatchOperationsError,
)

__all__ = [
    "DatabaseAttestation",
    "NativeCfgPlanBuildOutcome",
    "NativeCfgPlanBuildReason",
    "build_native_cfg_plan",
    "capture_database_attestation",
]


class NativeCfgPlanBuildReason(str, Enum):
    FUNCTION_MISMATCH = "FUNCTION_MISMATCH"
    STALE_FUNCTION_BYTES = "STALE_FUNCTION_BYTES"
    STALE_NATIVE_TERMINATOR = "STALE_NATIVE_TERMINATOR"
    MISSING_SOURCE_RANGE = "MISSING_SOURCE_RANGE"
    SOURCE_HINT_OUTSIDE_RANGE = "SOURCE_HINT_OUTSIDE_RANGE"
    AMBIGUOUS_NATIVE_TERMINATOR = "AMBIGUOUS_NATIVE_TERMINATOR"
    MISSING_TARGET_RANGE = "MISSING_TARGET_RANGE"
    TARGET_HINT_MISMATCH = "TARGET_HINT_MISMATCH"
    INSTRUCTION_SPLIT = "INSTRUCTION_SPLIT"
    FUNCTION_OWNERSHIP_CHANGE_REQUIRED = "FUNCTION_OWNERSHIP_CHANGE_REQUIRED"
    OVERLAPPING_PATCH_SPANS = "OVERLAPPING_PATCH_SPANS"


@dataclass(frozen=True, slots=True)
class DatabaseAttestation:
    database_identity: NativeDatabaseIdentity
    function_identity: NativeFunctionIdentity
    authorizing_attempt_id: ExecutionAttemptId
    architecture: str
    endianness: str

    def __post_init__(self) -> None:
        if not isinstance(self.database_identity, NativeDatabaseIdentity):
            raise TypeError("database_identity must be a NativeDatabaseIdentity")
        if not isinstance(self.function_identity, NativeFunctionIdentity):
            raise TypeError("function_identity must be a NativeFunctionIdentity")
        if not isinstance(self.authorizing_attempt_id, ExecutionAttemptId):
            raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")
        if not self.architecture.strip() or not self.endianness.strip():
            raise ValueError("architecture and endianness must not be blank")


@dataclass(frozen=True, slots=True)
class NativeCfgPlanBuildOutcome:
    plan: NativePatchPlan | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if (self.plan is None) == (self.reason is None):
            raise ValueError("outcome must contain exactly one of plan or reason")

    @property
    def ok(self) -> bool:
        return self.plan is not None


def _failure(reason: str | NativeCfgPlanBuildReason) -> NativeCfgPlanBuildOutcome:
    return NativeCfgPlanBuildOutcome(
        reason=reason.value if isinstance(reason, NativeCfgPlanBuildReason) else reason
    )


def _contains(binding: NativeCfgBlockRangeBinding, ea: int) -> bool:
    return any(native_range.contains(ea) for native_range in binding.native_ranges)


def _owned_by_function(
    reader: LiveDatabaseReader,
    ea: int,
    function_identity: NativeFunctionIdentity,
) -> bool:
    ownership = reader.read_function_ownership(ea)
    return (
        ownership is not None
        and ownership.owning_function_entry_ea == function_identity.entry_ea
        and ownership.chunk_ranges == function_identity.chunk_ranges
    )


def _native_successor_order(successors: tuple[int, ...]) -> tuple[int, ...]:
    """Convert Hex-Rays [fallthrough, taken] to native [taken, fallthrough]."""
    return tuple(reversed(successors)) if len(successors) == 2 else successors


def _fresh_function_hash(
    reader: LiveDatabaseReader,
    identity: NativeFunctionIdentity,
) -> str | None:
    chunks: list[bytes] = []
    for chunk in identity.chunk_ranges:
        image = reader.read_current_bytes(chunk.start_ea, chunk.end_ea)
        if image is None:
            return None
        chunks.append(image)
    if not chunks:
        return None
    return hashlib.sha256(b"".join(chunks)).hexdigest()


def capture_database_attestation(
    *,
    function_ea: int,
    reader: LiveDatabaseReader,
    input_attestation: InputIdentityAttestation,
    authorizing_attempt_id: ExecutionAttemptId,
) -> DatabaseAttestation | None:
    """Capture the live function identity under the durable IDB identity."""
    import ida_nalt

    ownership = reader.read_function_ownership(int(function_ea))
    if ownership is None or ownership.owning_function_entry_ea != int(function_ea):
        return None
    function_identity = NativeFunctionIdentity(
        entry_ea=int(function_ea),
        chunk_ranges=ownership.chunk_ranges,
        inherited_bytes_hash="pending",
    )
    inherited_hash = _fresh_function_hash(reader, function_identity)
    if inherited_hash is None:
        return None
    path = str(ida_nalt.get_input_file_path() or "<unnamed-idb>")
    return DatabaseAttestation(
        database_identity=NativeDatabaseIdentity(
            idb_uuid=input_attestation.database_uuid,
            input_file_hash=input_attestation.input_sha256,
            processor=input_attestation.processor,
            bitness=input_attestation.bitness,
            image_base=input_attestation.imagebase,
            database_path_hash=hashlib.sha256(path.encode("utf-8")).hexdigest(),
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=int(function_ea),
            chunk_ranges=ownership.chunk_ranges,
            inherited_bytes_hash=inherited_hash,
        ),
        authorizing_attempt_id=authorizing_attempt_id,
        architecture=(
            "x86"
            if input_attestation.processor.lower() == "metapc"
            else input_attestation.processor
        ),
        endianness="little",
    )


def _origin_span(transfer) -> NativeOriginSpan:
    instruction = transfer.instruction
    return NativeOriginSpan(
        start_ea=instruction.ea,
        end_ea=instruction.end_ea,
        expected_bytes_hash=instruction.bytes_hash,
        instructions=(instruction,),
        terminal_ea=instruction.ea,
        incoming_refs=(),
        coverage=NativeOriginCoverage.COMPLETE,
    )


def build_native_cfg_plan(
    *,
    intent: NativeCfgNormalizationIntent,
    reader: LiveDatabaseReader,
    origin_mapper: NativeOriginMapper,
    encoder: EncodingProvider,
    attestation: DatabaseAttestation,
) -> NativeCfgPlanBuildOutcome:
    """Recapture and lower every edge or abstain before any gateway write."""

    function_identity = attestation.function_identity
    if (
        intent.function_ea != function_identity.entry_ea
        or attestation.database_identity.bitness not in (32, 64)
    ):
        return _failure(NativeCfgPlanBuildReason.FUNCTION_MISMATCH)
    fresh_hash = _fresh_function_hash(reader, function_identity)
    if fresh_hash != function_identity.inherited_bytes_hash:
        return _failure(NativeCfgPlanBuildReason.STALE_FUNCTION_BYTES)

    bindings = {
        binding.block_serial: binding for binding in intent.block_range_bindings
    }
    function_ranges = tuple(
        NativeRange(item.start_ea, item.end_ea)
        for item in function_identity.chunk_ranges
    )
    function_decode = None
    operations: list[NativePatchOperation] = []
    for index, edge in enumerate(
        sorted(intent.edge_intents, key=lambda item: item.source_native_ea)
    ):
        inherited_native_successors = _native_successor_order(
            edge.inherited_target_native_eas
        )
        source_binding = bindings.get(edge.source_block)
        if source_binding is None:
            if function_decode is None:
                function_decode = origin_mapper.decode_ranges(function_ranges)
            candidates = tuple(
                transfer
                for transfer in function_decode.control_transfers
                if transfer.instruction.ea == edge.source_native_ea
                and transfer.successors == inherited_native_successors
            )
        else:
            if not _contains(source_binding, edge.source_native_ea):
                return _failure(NativeCfgPlanBuildReason.SOURCE_HINT_OUTSIDE_RANGE)
            source_decode = origin_mapper.decode_ranges(source_binding.native_ranges)
            candidates = tuple(
                transfer
                for transfer in source_decode.control_transfers
                if transfer.instruction.ea == edge.source_native_ea
                and transfer.successors == inherited_native_successors
                and _contains(source_binding, transfer.instruction.ea)
                and _contains(source_binding, transfer.instruction.end_ea - 1)
            )
        diagnostic_decode = function_decode if source_binding is None else source_decode
        successor_matches = tuple(
            item
            for item in diagnostic_decode.control_transfers
            if item.successors == inherited_native_successors
            and (
                source_binding is None
                or (
                    _contains(source_binding, item.instruction.ea)
                    and _contains(source_binding, item.instruction.end_ea - 1)
                )
            )
        )
        if not candidates and len(successor_matches) == 1:
            candidates = successor_matches
        if len(candidates) != 1:
            return _failure(
                f"{NativeCfgPlanBuildReason.AMBIGUOUS_NATIVE_TERMINATOR.value}: "
                f"source=0x{edge.source_native_ea:X} "
                f"inherited_hexrays={edge.inherited_target_native_eas} "
                f"inherited_native={inherited_native_successors} "
                f"candidates={tuple(item.instruction.ea for item in candidates)} "
                "successor_matches="
                f"{tuple(item.instruction.ea for item in successor_matches)}"
            )
        transfer = candidates[0]
        if not _owned_by_function(reader, transfer.instruction.ea, function_identity):
            return _failure(NativeCfgPlanBuildReason.FUNCTION_OWNERSHIP_CHANGE_REQUIRED)

        known_heads: set[int] = set()
        resolved_targets: list[int] = []
        for target_serial, target_hint in zip(
            edge.final_successors, edge.target_native_eas, strict=True
        ):
            target_binding = bindings.get(target_serial)
            if (
                target_binding is None
                or target_binding.microcode_native_ea != target_hint
                or not _contains(target_binding, target_hint)
            ):
                if function_decode is None:
                    function_decode = origin_mapper.decode_ranges(function_ranges)
                target_decode = function_decode
            else:
                target_decode = origin_mapper.decode_ranges(
                    target_binding.native_ranges
                )
            if target_hint not in target_decode.instruction_heads:
                return _failure(NativeCfgPlanBuildReason.INSTRUCTION_SPLIT)
            if not _owned_by_function(reader, target_hint, function_identity):
                return _failure(
                    NativeCfgPlanBuildReason.FUNCTION_OWNERSHIP_CHANGE_REQUIRED
                )
            known_heads.update(target_decode.instruction_heads)
            resolved_targets.append(target_hint)

        address_range = NativeAddressRange(
            transfer.instruction.ea, transfer.instruction.end_ea
        )
        captured = capture_range_evidence(
            reader,
            address_range,
            function_ea=function_identity.entry_ea,
        )
        if not captured.ok or captured.evidence is None:
            return _failure(str(captured.reason))
        if (
            hashlib.sha256(captured.evidence.expected_current_bytes).hexdigest()
            != transfer.instruction.bytes_hash
        ):
            return _failure(NativeCfgPlanBuildReason.STALE_NATIVE_TERMINATOR)
        if (
            captured.evidence.expected_function_ownership.owning_function_entry_ea
            != function_identity.entry_ea
            or captured.evidence.expected_function_ownership.chunk_ranges
            != function_identity.chunk_ranges
        ):
            return _failure(NativeCfgPlanBuildReason.FUNCTION_OWNERSHIP_CHANGE_REQUIRED)

        common = dict(
            operation_id=f"stage-c-edge-{index}",
            origin_span=_origin_span(transfer),
            capture=captured.evidence,
            provider=encoder,
            provider_id="minimal-x86",
            provider_version="1",
            bitness=attestation.database_identity.bitness,
            state_contract=edge.state_contract,
        )
        if edge.kind is NativeCfgEdgeKind.FORCE_FALLTHROUGH:
            if resolved_targets != [transfer.instruction.end_ea]:
                return _failure(NativeCfgPlanBuildReason.TARGET_HINT_MISMATCH)
            lowered = lower_removed_edge(**common)
        elif (
            edge.kind in (NativeCfgEdgeKind.FORCE_TAKEN, NativeCfgEdgeKind.REDIRECT)
            and len(resolved_targets) == 1
        ):
            lowered = lower_direct_edge(
                **common,
                target_ea=resolved_targets[0],
                known_instruction_heads=frozenset(known_heads),
            )
        elif edge.kind is NativeCfgEdgeKind.REDIRECT and len(resolved_targets) == 2:
            if transfer.predicate is None:
                return _failure(NativeCfgPlanBuildReason.AMBIGUOUS_NATIVE_TERMINATOR)
            lowered = lower_conditional_edge(
                **common,
                condition=transfer.predicate,
                true_target_ea=resolved_targets[1],
                false_target_ea=resolved_targets[0],
                known_instruction_heads=frozenset(known_heads),
            )
        else:
            return _failure(NativeCfgPlanBuildReason.AMBIGUOUS_NATIVE_TERMINATOR)
        if not lowered.ok or lowered.operation is None:
            return _failure(str(lowered.reason))
        before = lowered.operation.expected_before_shape.heads[0]
        operations.append(
            dataclasses.replace(
                lowered.operation,
                expected_before_shape=NativeInstructionSequenceShape(
                    heads=(
                        NativeInstructionHead(
                            ea=before.ea,
                            length=before.length,
                            mnemonic=before.mnemonic,
                            operand_shapes=before.operand_shapes,
                            successors=transfer.successors,
                        ),
                    )
                ),
            )
        )

    provenance = (
        "stage-c-native-cfg",
        *(
            f"{ref.kind}:{ref.ref_id}"
            for edge in intent.edge_intents
            for ref in edge.receipt_refs
        ),
    )
    try:
        plan = NativePatchPlan(
            plan_id=f"stage-c:{intent.intent_hash[:20]}",
            schema_version=1,
            patch_class="semantic_deobfuscation",
            database_identity=attestation.database_identity,
            function_identity=function_identity,
            inherited_function_fingerprint=function_identity.inherited_bytes_hash,
            target_cfg_fingerprint=intent.target_cfg_fingerprint,
            native_origin_map_fingerprint=intent.target_ctree_range_fingerprint,
            architecture=attestation.architecture,
            bitness=attestation.database_identity.bitness,
            endianness=attestation.endianness,
            processor=attestation.database_identity.processor,
            issuer_id="stage-c-native-cfg-normalizer",
            proof_id=f"native-cfg-intent-v1:{intent.intent_hash}",
            proof_hash=intent.target_cfg_fingerprint,
            provenance=provenance,
            operations=tuple(sorted(operations, key=lambda op: op.range.start_ea)),
            fallback_policy="no_patch",
            authorizing_attempt_id=attestation.authorizing_attempt_id,
        )
    except OverlappingNativePatchOperationsError:
        return _failure(NativeCfgPlanBuildReason.OVERLAPPING_PATCH_SPANS)
    return NativeCfgPlanBuildOutcome(plan=plan)
