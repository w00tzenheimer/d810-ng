"""Shared ``NativePatchPlan``/``NativePatchOperation`` builders for the
journal + recovery test modules in this directory.

Not a test module: ``pyproject.toml``'s ``python_files = ["test_*.py"]``
already excludes it from pytest collection. A private, colocated support
module following the precedent of
``tests/system/runtime/support/mutation_witness.py``.
"""

from __future__ import annotations

from d810.capabilities.native_patch import (
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeEncodingEvidence,
    NativeFunctionIdentity,
    NativeFunctionFlowRef,
    NativeFunctionOwnership,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
    NativeMetadataAction,
    NativePatchOperation,
    NativePatchPlan,
    NativeRestoreSnapshot,
)


def attempt_id(sequence: int = 1) -> ExecutionAttemptId:
    return ExecutionAttemptId.new(
        session=DecompilationSessionId.new(), sequence=sequence
    )


def shape(ea: int, length: int, mnemonic: str) -> NativeInstructionSequenceShape:
    return NativeInstructionSequenceShape(
        heads=(
            NativeInstructionHead(
                ea=ea,
                length=length,
                mnemonic=mnemonic,
                operand_shapes=(),
                successors=(ea + length,),
            ),
        )
    )


def restore_snapshot(start_ea: int, size: int) -> NativeRestoreSnapshot:
    return NativeRestoreSnapshot(
        inherited_bytes=bytes([0x90] * size),
        inherited_patch_rows=(),
        item_shape=NativeItemShape(
            heads=(
                NativeItemHead(
                    ea=start_ea, size=size, kind=NativeItemKind.CODE, user_defined=False
                ),
            )
        ),
        incoming_refs=(),
        function_ownership=NativeFunctionOwnership(
            owning_function_entry_ea=0x1000,
            chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
            flow_refs=(NativeFunctionFlowRef(0x1000, 0x1002, 21, False),),
        ),
        switch_fixup_metadata=(),
    )


def operation(
    *,
    operation_id: str = "op-1",
    start_ea: int = 0x1000,
    end_ea: int = 0x1002,
    expected_current_bytes: bytes = b"\x75\x01",
    expected_original_bytes: bytes | None = None,
    replacement_bytes: bytes = b"\xeb\x01",
    metadata_actions: tuple[NativeMetadataAction, ...] = (),
) -> NativePatchOperation:
    size = end_ea - start_ea
    return NativePatchOperation(
        operation_id=operation_id,
        range=NativeAddressRange(start_ea, end_ea),
        expected_current_bytes=expected_current_bytes,
        expected_original_bytes=(
            expected_original_bytes
            if expected_original_bytes is not None
            else expected_current_bytes
        ),
        expected_patch_rows=(),
        expected_before_shape=shape(start_ea, size, "jcc"),
        expected_item_shape=NativeItemShape(
            heads=(
                NativeItemHead(
                    ea=start_ea, size=size, kind=NativeItemKind.CODE, user_defined=False
                ),
            )
        ),
        expected_incoming_refs=(),
        expected_function_ownership=NativeFunctionOwnership(
            owning_function_entry_ea=0x1000,
            chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
            flow_refs=(NativeFunctionFlowRef(0x1000, 0x1002, 21, False),),
        ),
        replacement_bytes=replacement_bytes,
        expected_after_shape=shape(start_ea, size, "jmp"),
        expected_after_successors=(end_ea,),
        encoding_evidence=NativeEncodingEvidence(
            provider_id="test-encoder",
            provider_version="1",
            final_ea=start_ea,
            opcode_intent="jmp",
            emitted_hash="h1",
            independent_decode_hash="h1",
        ),
        relocation_evidence=(),
        metadata_actions=metadata_actions,
        restore_snapshot=restore_snapshot(start_ea, size),
    )


def plan(
    *,
    operations: tuple[NativePatchOperation, ...] | None = None,
    plan_id: str = "plan-1",
    attempt: ExecutionAttemptId | None = None,
    function_identity: NativeFunctionIdentity | None = None,
) -> NativePatchPlan:
    return NativePatchPlan(
        plan_id=plan_id,
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=NativeDatabaseIdentity(
            idb_uuid="idb-1",
            input_file_hash="filehash",
            processor="metapc",
            bitness=64,
            image_base=0x140000000,
            database_path_hash="pathhash",
        ),
        function_identity=(
            function_identity
            if function_identity is not None
            else NativeFunctionIdentity(
                entry_ea=0x1000,
                chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
                inherited_bytes_hash="funchash",
            )
        ),
        inherited_function_fingerprint="fp-before",
        target_cfg_fingerprint="cfg-1",
        native_origin_map_fingerprint="origin-1",
        architecture="x86",
        bitness=64,
        endianness="little",
        processor="metapc",
        issuer_id="issuer-1",
        proof_id="proof-1",
        proof_hash="proofhash",
        provenance=("test",),
        operations=operations if operations is not None else (operation(),),
        fallback_policy="no_patch",
        authorizing_attempt_id=attempt if attempt is not None else attempt_id(),
    )
