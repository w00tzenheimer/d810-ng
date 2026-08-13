"""Preflight -- one receipt per invariant, no writes (Task 5 Step 4 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``).

Design requirement: "Preflight rereads from the live database: current
bytes, original bytes, inherited patch rows, item shapes, incoming refs,
function ownership, and the decoded replacement. One receipt per invariant.
A single mismatch yields a typed rejection and no state transition beyond a
recorded rejection." Expected-before fields are authorization, not
diagnostics -- a mismatch abstains, it does not warn, so every negative test
here asserts the *whole plan* becomes unauthorized, not merely that one
receipt is flagged while the rest proceeds.

Covers spec Task 6's "positive and one-negative-per-invariant" requirement,
including the explicit "preexisting user-patch case" (the ``PATCH_ROWS``
negative below: a live patch row the plan's capture never saw).

Every fixture is a plain fake -- never a mocked ``ida_*`` module.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.capture import CaptureAbstentionReason
from d810.backends.ida.native_patch.preflight import (
    OperationInvariant,
    preflight_operation,
    preflight_operation_live,
    preflight_plan_live,
)
from d810.capabilities.native_patch import (
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.transforms.native_patch_lowering import NativeEdgeCaptureEvidence
from d810.transforms.native_patch_plan import (
    InheritedPatchRow,
    NativeAddressRange,
    NativeFunctionOwnership,
    NativeIncomingRef,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
)

from ._plan_fixtures import operation as build_operation
from ._plan_fixtures import plan as build_plan

pytestmark = pytest.mark.pure_python

_START, _END = 0x1000, 0x1002


def _matching_live_evidence(op) -> NativeEdgeCaptureEvidence:
    """A live capture that matches ``op`` exactly on every field."""
    return NativeEdgeCaptureEvidence(
        expected_current_bytes=op.expected_current_bytes,
        expected_original_bytes=op.expected_original_bytes,
        expected_patch_rows=op.expected_patch_rows,
        expected_item_shape=op.expected_item_shape,
        expected_incoming_refs=op.expected_incoming_refs,
        expected_function_ownership=op.expected_function_ownership,
        restore_snapshot=op.restore_snapshot,
    )


def _matching_decode(ea: int, data: bytes) -> NativeInstructionSequenceShape:
    del ea, data
    return NativeInstructionSequenceShape(
        heads=(
            NativeInstructionHead(
                ea=_START,
                length=2,
                mnemonic="jmp",
                operand_shapes=(),
                successors=(_END,),
            ),
        )
    )


class TestPreflightOperationPositive:
    def test_all_invariants_pass_when_live_matches_exactly(self) -> None:
        op = build_operation()
        result = preflight_operation(
            operation=op,
            live=_matching_live_evidence(op),
            decode_replacement=_matching_decode,
        )
        assert result.ok
        assert len(result.receipts) == 7
        assert all(r.ok for r in result.receipts)
        assert result.ea == op.range.start_ea


class TestPreflightOperationOneNegativePerInvariant:
    def test_current_bytes_mismatch_rejects_the_whole_operation(self) -> None:
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=b"\x90\x90",  # someone else patched it
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {OperationInvariant.CURRENT_BYTES: "EXTERNAL_INTERFERENCE"}

    def test_original_bytes_mismatch_rejects(self) -> None:
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=live.expected_current_bytes,
            expected_original_bytes=b"\xcc\xcc",
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {OperationInvariant.ORIGINAL_BYTES: "UNEXPLAINED_BYTE_DELTA"}

    def test_preexisting_user_patch_row_rejects(self) -> None:
        """The explicit 'preexisting user-patch case': a live patch row the
        plan's own capture never saw -- someone patched this byte manually
        after the plan was built."""
        op = build_operation()
        live = _matching_live_evidence(op)
        surprise_row = InheritedPatchRow(
            ea=_START,
            file_position=0x400,
            ida_original_value=0x75,
            inherited_current_value=0x74,
        )
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=live.expected_current_bytes,
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=(surprise_row,),
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {OperationInvariant.PATCH_ROWS: "PREEXISTING_PATCH_CONFLICT"}

    def test_item_shape_mismatch_rejects(self) -> None:
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=live.expected_current_bytes,
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=NativeItemShape(
                heads=(
                    NativeItemHead(
                        ea=_START, size=1, kind=NativeItemKind.DATA, user_defined=True
                    ),
                )
            ),
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {OperationInvariant.ITEM_SHAPE: "ITEM_SHAPE_MISMATCH"}

    def test_incoming_refs_mismatch_rejects(self) -> None:
        """A user-defined interior ref appearing live that the plan never
        authorized against."""
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=live.expected_current_bytes,
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=(
                NativeIncomingRef(
                    source_ea=0x900, target_ea=_START + 1, kind="code", ownership="user"
                ),
            ),
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {
            OperationInvariant.INCOMING_REFS: "INCOMING_INTERIOR_REFERENCE"
        }

    def test_function_ownership_mismatch_rejects(self) -> None:
        """A function-tail ownership mismatch: the live owning function
        differs from what the plan's capture recorded."""
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=live.expected_current_bytes,
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=NativeFunctionOwnership(
                owning_function_entry_ea=0x5000,
                chunk_ranges=(NativeAddressRange(0x5000, 0x5010),),
            ),
            restore_snapshot=live.restore_snapshot,
        )
        result = preflight_operation(
            operation=op, live=live, decode_replacement=_matching_decode
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {
            OperationInvariant.FUNCTION_OWNERSHIP: "FUNCTION_OWNERSHIP_CHANGE_REQUIRED"
        }

    def test_decoded_replacement_mismatch_rejects(self) -> None:
        op = build_operation()

        def _wrong_decode(ea: int, data: bytes) -> NativeInstructionSequenceShape:
            del ea, data
            return NativeInstructionSequenceShape(
                heads=(
                    NativeInstructionHead(
                        ea=_START,
                        length=1,
                        mnemonic="nop",
                        operand_shapes=(),
                        successors=(_START + 1,),
                    ),
                )
            )

        result = preflight_operation(
            operation=op,
            live=_matching_live_evidence(op),
            decode_replacement=_wrong_decode,
        )
        assert not result.ok
        failed = {r.invariant: r.reason for r in result.receipts if not r.ok}
        assert failed == {
            OperationInvariant.DECODED_REPLACEMENT: "POST_DECODE_MISMATCH"
        }


class TestExpectedBeforeIsAuthorizationNotDiagnostic:
    def test_a_single_mismatch_makes_the_whole_plan_unauthorized(self) -> None:
        op = build_operation()
        live = _matching_live_evidence(op)
        live = NativeEdgeCaptureEvidence(
            expected_current_bytes=b"\x90\x90",
            expected_original_bytes=live.expected_original_bytes,
            expected_patch_rows=live.expected_patch_rows,
            expected_item_shape=live.expected_item_shape,
            expected_incoming_refs=live.expected_incoming_refs,
            expected_function_ownership=live.expected_function_ownership,
            restore_snapshot=live.restore_snapshot,
        )

        class _StaticReader:
            def read_current_bytes(self, s, e):
                return live.expected_current_bytes

            def read_original_bytes(self, s, e):
                return live.expected_original_bytes

            def read_patch_rows(self, s, e):
                return live.expected_patch_rows

            def read_item_shape(self, s, e):
                return live.expected_item_shape

            def read_incoming_refs(self, s, e):
                return live.expected_incoming_refs

            def read_function_ownership(self, ea):
                return live.expected_function_ownership

        plan = build_plan(operations=(op,))
        result = preflight_plan_live(_StaticReader(), plan, _matching_decode)
        assert not result.authorized


class TestPreflightOperationLive:
    def test_uses_capture_to_reread_the_live_database(self) -> None:
        op = build_operation()
        live = _matching_live_evidence(op)

        class _StaticReader:
            def read_current_bytes(self, s, e):
                return live.expected_current_bytes

            def read_original_bytes(self, s, e):
                return live.expected_original_bytes

            def read_patch_rows(self, s, e):
                return live.expected_patch_rows

            def read_item_shape(self, s, e):
                return live.expected_item_shape

            def read_incoming_refs(self, s, e):
                return live.expected_incoming_refs

            def read_function_ownership(self, ea):
                return live.expected_function_ownership

        result = preflight_operation_live(_StaticReader(), op, _matching_decode)
        assert result.ok

    def test_a_capture_level_abstention_is_reported_as_a_rejection_not_a_crash(
        self,
    ) -> None:
        op = build_operation()

        class _UnloadedReader:
            def read_current_bytes(self, s, e):
                return None

            def read_original_bytes(self, s, e):
                return None

            def read_patch_rows(self, s, e):
                return ()

            def read_item_shape(self, s, e):
                return NativeItemShape(heads=())

            def read_incoming_refs(self, s, e):
                return ()

            def read_function_ownership(self, ea):
                return None

        result = preflight_operation_live(_UnloadedReader(), op, _matching_decode)
        assert not result.ok
        assert result.ea == op.range.start_ea
        assert any(
            r.reason == CaptureAbstentionReason.LOADED_STATE_CHANGED.value
            for r in result.receipts
        )
