"""Task 5 Step 5: prove the capture/lowering/preflight pipeline writes nothing.

Builds one real ``NativePatchOperation`` end to end -- observation ->
origin correlation -> capture -> lowering -- against the live
``fake_jumps.dll`` disposable IDB, then preflights it both honestly
(authorized) and against several deliberately wrong static expectations
(rejected). Every case, positive and negative, is wrapped in a
``MutationWitness`` and asserted clean: unchanged whole-image digest AND
zero ``IDB_Hooks``/``Hexrays_Hooks`` event counters -- not just unchanged
bytes. Negative cases never touch the real database to manufacture the
mismatch (which would itself be a write); they instead preflight a locally
modified copy of the truthfully-captured operation against the unmodified,
real live reader, so the only bytes ever compared are read, never written.
"""

from __future__ import annotations

import dataclasses

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_ida = pytest.importorskip("ida_ida")
idaapi = pytest.importorskip("idaapi")

from d810.backends.ida.native_patch.capture import (  # noqa: E402
    CaptureAbstentionReason,
    IdaLiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder  # noqa: E402
from d810.backends.ida.native_patch.observation import observe_function  # noqa: E402
from d810.backends.ida.native_patch.origin_mapper import (  # noqa: E402
    correlate_native_span,
    ida_decoded_range_reader,
)
from d810.backends.ida.native_patch.preflight import (  # noqa: E402
    OperationInvariant,
    preflight_operation_live,
    preflight_plan_live,
)
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)
from d810.ir.native_origin import NativeOriginCoverage  # noqa: E402
from d810.transforms.native_patch_lowering import lower_direct_edge  # noqa: E402
from d810.transforms.native_patch_plan import (  # noqa: E402
    InheritedPatchRow,
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
    NativeFunctionOwnership,
    NativeItemShape,
    NativePatchPlan,
)
from tests.system.runtime.support.mutation_witness import MutationWitness  # noqa: E402

TARGET = "fake_jump_opaque_predicate"


def _target_ea() -> int:
    ea = idaapi.get_name_ea(idaapi.BADADDR, TARGET)
    if ea == idaapi.BADADDR:
        pytest.skip(f"{TARGET} not in fixture")
    return ida_funcs.get_func(ea).start_ea


def _first_encodable_branch(function_ea: int):
    observation = observe_function(function_ea)
    assert observation is not None
    for branch in observation.branches:
        if branch.encodable:
            return branch
    pytest.skip("fixture has no Mode-A-encodable branch to build a plan from")


def _bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else 32


def _authorizing_attempt_id() -> ExecutionAttemptId:
    return ExecutionAttemptId.new(session=DecompilationSessionId.new(), sequence=1)


def _build_operation(function_ea: int):
    """Real end-to-end capture + origin correlation + lowering for one
    encodable conditional branch. Read-only throughout."""
    branch = _first_encodable_branch(function_ea)
    start_ea, end_ea = branch.site_ea, branch.site_ea + branch.size

    origin_span = correlate_native_span(
        start_ea,
        end_ea,
        ida_decoded_range_reader(),
        expected_bytes_hash="system-test-hash",
    )
    assert origin_span.coverage is NativeOriginCoverage.COMPLETE, (
        "observation already validated this branch decodes cleanly"
    )

    capture_outcome = capture_range_evidence(
        IdaLiveDatabaseReader(),
        NativeAddressRange(start_ea, end_ea),
        function_ea=function_ea,
    )
    assert capture_outcome.ok, capture_outcome.reason

    lowering = lower_direct_edge(
        operation_id="system-test-op",
        origin_span=origin_span,
        target_ea=branch.taken_target,
        known_instruction_heads=frozenset({branch.taken_target}),
        capture=capture_outcome.evidence,
        provider=MinimalX86BranchEncoder(),
        provider_id="minimal-x86",
        provider_version="1",
        bitness=_bitness(),
    )
    assert lowering.ok, lowering.reason
    return lowering.operation


def _build_plan(function_ea: int, operation) -> NativePatchPlan:
    func = ida_funcs.get_func(function_ea)
    return NativePatchPlan(
        plan_id="system-test-plan",
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=NativeDatabaseIdentity(
            idb_uuid="system-test",
            input_file_hash="system-test",
            processor="metapc",
            bitness=_bitness(),
            image_base=idaapi.get_imagebase(),
            database_path_hash="system-test",
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=function_ea,
            chunk_ranges=(NativeAddressRange(int(func.start_ea), int(func.end_ea)),),
            inherited_bytes_hash="system-test",
        ),
        inherited_function_fingerprint="system-test-fp",
        target_cfg_fingerprint="system-test-cfg",
        native_origin_map_fingerprint="system-test-origin",
        architecture="x86",
        bitness=_bitness(),
        endianness="little",
        processor="metapc",
        issuer_id="system-test-issuer",
        proof_id="system-test-proof",
        proof_hash="system-test-proof-hash",
        provenance=("system-test",),
        operations=(operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=_authorizing_attempt_id(),
    )


class TestCaptureLoweringPreflightWriteNothing:
    binary_name = "fake_jumps.dll"

    def test_positive_preflight_authorizes_and_mutates_nothing(self, ida_database):
        function_ea = _target_ea()

        with MutationWitness() as witness:
            operation = _build_operation(function_ea)
            result = preflight_operation_live(
                IdaLiveDatabaseReader(),
                operation,
                MinimalX86BranchEncoder().decode,
            )
            reading = witness.assert_clean("positive capture+lowering+preflight")

        assert result.ok, result.rejection_reasons
        assert reading.clean, reading.describe()

    def test_current_bytes_mismatch_is_rejected_and_mutates_nothing(self, ida_database):
        function_ea = _target_ea()
        operation = _build_operation(function_ea)
        flipped = bytes(b ^ 0xFF for b in operation.expected_current_bytes)
        wrong = dataclasses.replace(operation, expected_current_bytes=flipped)

        with MutationWitness() as witness:
            result = preflight_operation_live(
                IdaLiveDatabaseReader(), wrong, MinimalX86BranchEncoder().decode
            )
            reading = witness.assert_clean("current-bytes-mismatch preflight")

        assert not result.ok
        failing = {r.invariant for r in result.receipts if not r.ok}
        assert failing == {OperationInvariant.CURRENT_BYTES}
        assert reading.clean, reading.describe()

    def test_preexisting_patch_row_mismatch_is_rejected_and_mutates_nothing(
        self, ida_database
    ):
        """The explicit 'preexisting user-patch' case: the operation's own
        (fabricated, never-applied) expectation claims a patch row the real
        database does not have -- proving the comparison, not proving a real
        patch, which this task must never create."""
        function_ea = _target_ea()
        operation = _build_operation(function_ea)
        fabricated_row = InheritedPatchRow(
            ea=operation.range.start_ea,
            file_position=0,
            ida_original_value=operation.expected_current_bytes[0],
            inherited_current_value=(operation.expected_current_bytes[0] ^ 0xFF) & 0xFF,
        )
        wrong = dataclasses.replace(operation, expected_patch_rows=(fabricated_row,))

        with MutationWitness() as witness:
            result = preflight_operation_live(
                IdaLiveDatabaseReader(), wrong, MinimalX86BranchEncoder().decode
            )
            reading = witness.assert_clean("patch-row-mismatch preflight")

        assert not result.ok
        failing = {r.invariant for r in result.receipts if not r.ok}
        assert failing == {OperationInvariant.PATCH_ROWS}
        assert reading.clean, reading.describe()

    def test_function_ownership_mismatch_is_rejected_and_mutates_nothing(
        self, ida_database
    ):
        function_ea = _target_ea()
        operation = _build_operation(function_ea)
        true_ownership = operation.expected_function_ownership
        wrong_ownership = NativeFunctionOwnership(
            owning_function_entry_ea=true_ownership.owning_function_entry_ea,
            chunk_ranges=true_ownership.chunk_ranges + (NativeAddressRange(1, 2),),
        )
        wrong = dataclasses.replace(
            operation, expected_function_ownership=wrong_ownership
        )

        with MutationWitness() as witness:
            result = preflight_operation_live(
                IdaLiveDatabaseReader(), wrong, MinimalX86BranchEncoder().decode
            )
            reading = witness.assert_clean("function-ownership-mismatch preflight")

        assert not result.ok
        failing = {r.invariant for r in result.receipts if not r.ok}
        assert failing == {OperationInvariant.FUNCTION_OWNERSHIP}
        assert reading.clean, reading.describe()

    def test_item_shape_mismatch_is_rejected_and_mutates_nothing(self, ida_database):
        function_ea = _target_ea()
        operation = _build_operation(function_ea)
        wrong = dataclasses.replace(
            operation, expected_item_shape=NativeItemShape(heads=())
        )

        with MutationWitness() as witness:
            result = preflight_operation_live(
                IdaLiveDatabaseReader(), wrong, MinimalX86BranchEncoder().decode
            )
            reading = witness.assert_clean("item-shape-mismatch preflight")

        assert not result.ok
        failing = {r.invariant for r in result.receipts if not r.ok}
        assert failing == {OperationInvariant.ITEM_SHAPE}
        assert reading.clean, reading.describe()

    def test_decoded_replacement_mismatch_is_rejected_and_mutates_nothing(
        self, ida_database
    ):
        function_ea = _target_ea()
        operation = _build_operation(function_ea)

        def _always_disagrees(ea: int, data: bytes):
            del ea, data
            return dataclasses.replace(operation.expected_after_shape, heads=())

        with MutationWitness() as witness:
            result = preflight_operation_live(
                IdaLiveDatabaseReader(), operation, _always_disagrees
            )
            reading = witness.assert_clean("decoded-replacement-mismatch preflight")

        assert not result.ok
        failing = {r.invariant for r in result.receipts if not r.ok}
        assert failing == {OperationInvariant.DECODED_REPLACEMENT}
        assert reading.clean, reading.describe()

    def test_capture_abstains_on_an_unmapped_range_and_mutates_nothing(
        self, ida_database
    ):
        """A genuinely unmapped address (not fabricated) -- the highest
        plausible EA is exercised directly rather than any real database
        content, so this needs no operation at all."""
        unmapped_ea = max(idaapi.inf_get_max_ea() + 0x1000, 0x7FFFFFFF)

        with MutationWitness() as witness:
            outcome = capture_range_evidence(
                IdaLiveDatabaseReader(),
                NativeAddressRange(unmapped_ea, unmapped_ea + 2),
                function_ea=unmapped_ea,
            )
            reading = witness.assert_clean("capture on an unmapped range")

        assert not outcome.ok
        assert outcome.reason == CaptureAbstentionReason.LOADED_STATE_CHANGED.value
        assert reading.clean, reading.describe()

    def test_full_plan_preflight_round_trip_mutates_nothing(self, ida_database):
        """End to end through NativePatchPlan, matching what Task 6's
        gateway will eventually preflight before ever writing."""
        function_ea = _target_ea()

        with MutationWitness() as witness:
            operation = _build_operation(function_ea)
            plan = _build_plan(function_ea, operation)
            result = preflight_plan_live(
                IdaLiveDatabaseReader(), plan, MinimalX86BranchEncoder().decode
            )
            reading = witness.assert_clean("full plan preflight round trip")

        assert result.authorized
        assert reading.clean, reading.describe()
