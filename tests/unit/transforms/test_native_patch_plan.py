"""Pure vocabulary, validation-negative, and hash-stability tests for the
provider-neutral native patch plan (section 14 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md``, folded into Task 2 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``).

Covers Task 2 Step 1's required negatives: operation overlap, empty ranges,
missing restore state, missing expected-after shape, and unstable
serialization -- plus the plan's own required test, "changing expected-before
bytes must change plan_hash."
"""

from __future__ import annotations

import dataclasses

import pytest

from d810.capabilities.native_patch import (
    EncodingProvider,
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeEncodingEvidence,
    NativeFunctionIdentity,
    NativeFunctionOwnership,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
    NativeMetadataAction,
    NativeMetadataActionKind,
    NativePatchOperation,
    NativePatchPlan,
    NativeRestoreSnapshot,
    OverlappingNativePatchOperationsError,
)

pytestmark = pytest.mark.pure_python


def _attempt_id(sequence: int = 1) -> ExecutionAttemptId:
    return ExecutionAttemptId.new(
        session=DecompilationSessionId.new(), sequence=sequence
    )


def _shape(
    ea: int = 0x1000, length: int = 2, mnemonic: str = "jmp"
) -> NativeInstructionSequenceShape:
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


def _restore_snapshot(start_ea: int, size: int) -> NativeRestoreSnapshot:
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
        ),
        switch_fixup_metadata=(),
    )


def _operation(
    *,
    operation_id: str = "op-1",
    start_ea: int = 0x1000,
    end_ea: int = 0x1002,
    expected_current_bytes: bytes = b"\x75\x01",
    replacement_bytes: bytes = b"\xeb\x01",
    restore_snapshot: NativeRestoreSnapshot | None = None,
    expected_after_shape: NativeInstructionSequenceShape | None = None,
) -> NativePatchOperation:
    size = end_ea - start_ea
    return NativePatchOperation(
        operation_id=operation_id,
        range=NativeAddressRange(start_ea, end_ea),
        expected_current_bytes=expected_current_bytes,
        expected_original_bytes=expected_current_bytes,
        expected_patch_rows=(),
        expected_before_shape=_shape(ea=start_ea, length=size, mnemonic="jcc"),
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
        ),
        replacement_bytes=replacement_bytes,
        expected_after_shape=(
            expected_after_shape
            if expected_after_shape is not None
            else _shape(ea=start_ea, length=size, mnemonic="jmp")
        ),
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
        metadata_actions=(),
        restore_snapshot=(
            restore_snapshot
            if restore_snapshot is not None
            else _restore_snapshot(start_ea, size)
        ),
    )


def _plan(
    *,
    operations: tuple[NativePatchOperation, ...] | None = None,
    plan_id: str = "plan-1",
    attempt_id: ExecutionAttemptId | None = None,
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
        function_identity=NativeFunctionIdentity(
            entry_ea=0x1000,
            chunk_ranges=(NativeAddressRange(0x1000, 0x2000),),
            inherited_bytes_hash="funchash",
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
        operations=operations if operations is not None else (_operation(),),
        fallback_policy="no_patch",
        authorizing_attempt_id=attempt_id if attempt_id is not None else _attempt_id(),
    )


def plan_with_before(before: bytes) -> NativePatchPlan:
    return _plan(operations=(_operation(expected_current_bytes=before),))


# ---------------------------------------------------------------------------
# The plan's own required test
# ---------------------------------------------------------------------------


def test_plan_hash_changes_when_expected_before_bytes_change() -> None:
    first = plan_with_before(b"\x75\x01")
    second = plan_with_before(b"\x75\x02")
    assert first.plan_hash != second.plan_hash


def test_metadata_target_fingerprint_binds_after_state_not_before_state() -> None:
    action = NativeMetadataAction(
        kind=NativeMetadataActionKind.UPDATE_XREF,
        ea=0x1000,
        expected_before="cref3:",
        expected_after="cref3:0x2000@0x11@u",
    )
    reread_action = dataclasses.replace(action, expected_before="cref3:0x2000@0x11@u")
    changed_target = dataclasses.replace(action, expected_after="cref3:0x3000@0x11@u")

    first = _plan(
        operations=(dataclasses.replace(_operation(), metadata_actions=(action,)),)
    )
    reread = _plan(
        operations=(
            dataclasses.replace(_operation(), metadata_actions=(reread_action,)),
        )
    )
    changed = _plan(
        operations=(
            dataclasses.replace(_operation(), metadata_actions=(changed_target,)),
        )
    )

    assert first.plan_hash != reread.plan_hash
    assert first.metadata_target_fingerprint == reread.metadata_target_fingerprint
    assert first.metadata_target_fingerprint != changed.metadata_target_fingerprint


# ---------------------------------------------------------------------------
# Hash stability ("unstable serialization")
# ---------------------------------------------------------------------------


class TestPlanHashStability:
    def test_hash_is_stable_across_repeated_calls(self) -> None:
        plan = _plan()
        assert plan.plan_hash == plan.plan_hash

    def test_hash_does_not_depend_on_object_identity(self) -> None:
        a = plan_with_before(b"\x75\x01")
        b = plan_with_before(b"\x75\x01")
        assert a is not b
        assert a.operations[0] is not b.operations[0]
        assert a.plan_hash == b.plan_hash

    def test_hash_ignores_plan_id(self) -> None:
        a = _plan(plan_id="plan-a")
        b = _plan(plan_id="plan-b")
        assert a.plan_hash == b.plan_hash

    def test_hash_ignores_authorizing_attempt(self) -> None:
        a = _plan(attempt_id=_attempt_id(sequence=1))
        b = _plan(attempt_id=_attempt_id(sequence=7))
        assert a.plan_hash == b.plan_hash

    def test_hash_ignores_operation_id(self) -> None:
        a = _plan(operations=(_operation(operation_id="op-a"),))
        b = _plan(operations=(_operation(operation_id="op-b"),))
        assert a.plan_hash == b.plan_hash

    def test_hash_changes_when_replacement_bytes_change(self) -> None:
        a = _plan(operations=(_operation(replacement_bytes=b"\xeb\x01"),))
        b = _plan(operations=(_operation(replacement_bytes=b"\xeb\x02"),))
        assert a.plan_hash != b.plan_hash


# ---------------------------------------------------------------------------
# NativeAddressRange
# ---------------------------------------------------------------------------


class TestNativeAddressRange:
    def test_rejects_empty_range(self) -> None:
        with pytest.raises(ValueError):
            NativeAddressRange(0x1000, 0x1000)

    def test_rejects_inverted_range(self) -> None:
        with pytest.raises(ValueError):
            NativeAddressRange(0x1000, 0x0FFF)

    def test_rejects_negative_start(self) -> None:
        with pytest.raises(ValueError):
            NativeAddressRange(-1, 0x10)

    def test_size(self) -> None:
        assert NativeAddressRange(0x1000, 0x1010).size == 0x10

    def test_overlap_detection(self) -> None:
        a = NativeAddressRange(0x1000, 0x1010)
        b = NativeAddressRange(0x1008, 0x1020)
        c = NativeAddressRange(0x1010, 0x1020)
        assert a.overlaps(b)
        assert not a.overlaps(c)  # adjacent, not overlapping


# ---------------------------------------------------------------------------
# NativePatchOperation validation
# ---------------------------------------------------------------------------


class TestNativePatchOperationValidation:
    def test_rejects_byte_length_mismatch_with_range(self) -> None:
        with pytest.raises(ValueError):
            _operation(start_ea=0x1000, end_ea=0x1002, expected_current_bytes=b"\x90")

    def test_rejects_missing_expected_after_shape(self) -> None:
        empty_shape = NativeInstructionSequenceShape(heads=())
        with pytest.raises(ValueError):
            _operation(expected_after_shape=empty_shape)

    def test_rejects_restore_snapshot_not_covering_range(self) -> None:
        bad_snapshot = _restore_snapshot(0x1000, 1)  # operation range size is 2
        with pytest.raises(ValueError):
            _operation(restore_snapshot=bad_snapshot)

    def test_rejects_wrong_typed_restore_snapshot(self) -> None:
        with pytest.raises(TypeError):
            _operation(restore_snapshot="not-a-snapshot")  # type: ignore[arg-type]

    def test_accepts_a_well_formed_operation(self) -> None:
        op = _operation()
        assert op.range.size == 2


# ---------------------------------------------------------------------------
# NativePatchPlan overlap handling (invariant 5)
# ---------------------------------------------------------------------------


class TestNativePatchPlanOverlap:
    def test_rejects_overlapping_operations(self) -> None:
        a = _operation(operation_id="a", start_ea=0x1000, end_ea=0x1002)
        b = _operation(operation_id="b", start_ea=0x1001, end_ea=0x1003)
        with pytest.raises(OverlappingNativePatchOperationsError):
            _plan(operations=(a, b))

    def test_allows_adjacent_non_overlapping_operations(self) -> None:
        a = _operation(operation_id="a", start_ea=0x1000, end_ea=0x1002)
        b = _operation(operation_id="b", start_ea=0x1002, end_ea=0x1004)
        plan = _plan(operations=(a, b))
        assert len(plan.operations) == 2

    def test_allows_byte_identical_duplicate_operations(self) -> None:
        a = _operation(operation_id="a")
        b = _operation(operation_id="b")  # same range + content, different id
        plan = _plan(operations=(a, b))
        assert len(plan.operations) == 2

    def test_rejects_same_range_different_content(self) -> None:
        a = _operation(
            operation_id="a",
            expected_current_bytes=b"\x75\x01",
            replacement_bytes=b"\xeb\x01",
        )
        b = _operation(
            operation_id="b",
            expected_current_bytes=b"\x75\x02",
            replacement_bytes=b"\xeb\x01",
        )
        with pytest.raises(OverlappingNativePatchOperationsError):
            _plan(operations=(a, b))

    def test_rejects_empty_operations(self) -> None:
        with pytest.raises(ValueError):
            _plan(operations=())


# ---------------------------------------------------------------------------
# NativePatchPlan field validation
# ---------------------------------------------------------------------------


class TestNativePatchPlanFieldValidation:
    def test_requires_execution_attempt_id(self) -> None:
        with pytest.raises(TypeError):
            _plan(attempt_id="not-an-attempt-id")  # type: ignore[arg-type]

    def test_rejects_unknown_patch_class(self) -> None:
        plan = _plan()
        with pytest.raises(ValueError):
            dataclasses.replace(plan, patch_class="bogus")

    def test_rejects_execution_safe_true(self) -> None:
        plan = _plan()
        with pytest.raises(ValueError):
            dataclasses.replace(plan, execution_safe=True)

    def test_rejects_unknown_fallback_policy(self) -> None:
        plan = _plan()
        with pytest.raises(ValueError):
            dataclasses.replace(plan, fallback_policy="bogus")

    def test_is_immutable(self) -> None:
        plan = _plan()
        with pytest.raises((AttributeError, TypeError)):
            plan.plan_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# EncodingProvider Protocol shape
# ---------------------------------------------------------------------------


class TestEncodingProviderProtocol:
    def test_conforming_provider_satisfies_the_protocol(self) -> None:
        class _FakeProvider:
            def encode_direct_jump(self, start_ea, end_ea, target_ea, *, bitness):
                return None

            def encode_conditional(
                self,
                start_ea,
                end_ea,
                *,
                condition,
                true_target_ea,
                false_target_ea,
                bitness,
            ):
                return None

            def encode_nop_fill(self, start_ea, end_ea, *, bitness):
                return None

            def decode(self, ea, data, *, bitness):
                return None

        assert isinstance(_FakeProvider(), EncodingProvider)

    def test_incomplete_object_does_not_satisfy_the_protocol(self) -> None:
        class _Incomplete:
            def encode_direct_jump(self, *args, **kwargs):
                return None

        assert not isinstance(_Incomplete(), EncodingProvider)
