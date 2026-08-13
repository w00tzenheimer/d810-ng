"""Read-only capture and origin-correlation negatives (Task 5 Step 1 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``).

Covers both ``origin_mapper.py`` (microblock-boundary/fictitious-EA/
non-contiguous-span correlation) and ``capture.py`` (existing patch-row,
user-defined incoming ref, function-tail ownership, and loaded-state
negatives) -- there is no separate ``test_origin_mapper.py`` in the task's
file list, and both modules are small and tightly related, so their tests
live together here (an explicit, flagged scope decision -- see the report).

All fixtures here are plain Python objects implementing the
``DecodedRangeReader``/``LiveDatabaseReader`` protocols -- never a mocked
``ida_*`` module (``tests/unit/conftest.py``'s ``_enforce_no_ida_mocks``
fixture would fail the test if one were injected). The real
``ida_*``-backed adapters are exercised only by the Docker system-test suite.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.capture import (
    CaptureAbstentionReason,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.origin_mapper import (
    correlate_microblock_origin,
    correlate_native_span,
)
from d810.ir.native_origin import NativeInstructionIdentity, NativeOriginCoverage
from d810.transforms.native_patch_plan import (
    InheritedPatchRow,
    NativeAddressRange,
    NativeFunctionOwnership,
    NativeIncomingRef,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
)

pytestmark = pytest.mark.pure_python


def _insn(ea: int, length: int = 2, mnemonic: str = "jne") -> NativeInstructionIdentity:
    return NativeInstructionIdentity(
        ea=ea,
        end_ea=ea + length,
        bytes_hash=f"h-{ea:#x}",
        mnemonic=mnemonic,
        operand_shape=(),
        pc_relative_sites=(),
    )


# ---------------------------------------------------------------------------
# origin_mapper.py
# ---------------------------------------------------------------------------


class TestCorrelateNativeSpan:
    def test_microblock_boundary_alone_never_creates_an_owned_span(self) -> None:
        """A claimed [start, end) with nothing actually decodable inside it
        must never be reported as COMPLETE -- trusting the boundary alone is
        exactly the bug this module exists to prevent."""

        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return ()

        span = correlate_native_span(
            0x1000, 0x1010, decode_range, expected_bytes_hash="claim"
        )
        assert span.coverage is NativeOriginCoverage.SYNTHETIC
        assert span.instructions == ()

    def test_fictitious_native_ea_correlation_is_synthetic(self) -> None:
        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            # Decoding finds nothing at the claimed (fictitious) address.
            return ()

        span = correlate_native_span(
            0x9999, 0x999B, decode_range, expected_bytes_hash="fictitious"
        )
        assert span.coverage is NativeOriginCoverage.SYNTHETIC

    def test_a_genuine_gap_between_decoded_runs_is_partial_not_complete(self) -> None:
        """Exactly the 'non-contiguous span' negative: two real, decodable
        runs exist but do not tile the claimed range -- this must never be
        silently reported as COMPLETE."""

        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return (_insn(0x1000, 2), _insn(0x1006, 2))  # gap 0x1002-0x1006

        span = correlate_native_span(
            0x1000, 0x1008, decode_range, expected_bytes_hash="gapped"
        )
        assert span.coverage is NativeOriginCoverage.PARTIAL
        assert len(span.instructions) == 2

    def test_a_full_contiguous_tiling_is_complete(self) -> None:
        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return (_insn(0x1000, 2), _insn(0x1002, 2))

        span = correlate_native_span(
            0x1000, 0x1004, decode_range, expected_bytes_hash="clean"
        )
        assert span.coverage is NativeOriginCoverage.COMPLETE
        assert span.terminal_ea == 0x1002

    def test_overlapping_decode_candidates_are_ambiguous(self) -> None:
        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return (_insn(0x1000, 3), _insn(0x1001, 3))  # overlap

        span = correlate_native_span(
            0x1000, 0x1004, decode_range, expected_bytes_hash="ambiguous"
        )
        assert span.coverage is NativeOriginCoverage.AMBIGUOUS

    def test_instructions_reported_outside_the_claimed_range_are_ambiguous(
        self,
    ) -> None:
        """A decoder returning something outside the window it was asked to
        decode is a contract violation -- treat it as ambiguous rather than
        silently degrading to PARTIAL or letting it corrupt a COMPLETE claim."""

        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return (_insn(0x1000, 2), _insn(0x2000, 2))  # 0x2000 is out of range

        span = correlate_native_span(
            0x1000, 0x1004, decode_range, expected_bytes_hash="oob"
        )
        assert span.coverage is NativeOriginCoverage.AMBIGUOUS


class TestCorrelateMicroblockOrigin:
    def test_every_result_carries_a_native_ea_anchor_regardless_of_coverage(
        self,
    ) -> None:
        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return ()

        origin = correlate_microblock_origin(
            microblock_serial=7,
            microblock_maturity="MMAT_GENERATED",
            native_ea_anchor=0x4000,
            expected_ranges=((0x4000, 0x4002),),
            decode_range=decode_range,
        )
        assert origin.native_ea_anchor == 0x4000
        assert origin.spans[0].coverage is NativeOriginCoverage.SYNTHETIC

    def test_correlation_evidence_is_populated_per_span(self) -> None:
        def decode_range(start: int, end: int) -> tuple[NativeInstructionIdentity, ...]:
            return (_insn(start, end - start),)

        origin = correlate_microblock_origin(
            microblock_serial=1,
            microblock_maturity="MMAT_LVARS",
            native_ea_anchor=0x1000,
            expected_ranges=((0x1000, 0x1002),),
            decode_range=decode_range,
        )
        assert len(origin.correlation_evidence) == 1


# ---------------------------------------------------------------------------
# capture.py
# ---------------------------------------------------------------------------


_DEFAULT_OWNERSHIP = NativeFunctionOwnership(
    owning_function_entry_ea=0x1000,
    chunk_ranges=(NativeAddressRange(0x1000, 0x2000),),
)
_UNSET = object()


class _FakeReader:
    """A plain fake implementing ``LiveDatabaseReader`` -- not a mock of an
    ``ida_*`` module, so ``tests/unit/conftest.py``'s no-IDA-mocking rule
    does not apply to it."""

    def __init__(
        self,
        *,
        current_bytes: bytes | None = b"\x75\x01",
        original_bytes: bytes | None = b"\x75\x01",
        patch_rows: tuple[InheritedPatchRow, ...] = (),
        item_shape: NativeItemShape | None = None,
        incoming_refs: tuple[NativeIncomingRef, ...] = (),
        function_ownership: NativeFunctionOwnership | None | object = _UNSET,
    ) -> None:
        self._current_bytes = current_bytes
        self._original_bytes = original_bytes
        self._patch_rows = patch_rows
        self._item_shape = item_shape or NativeItemShape(
            heads=(
                NativeItemHead(
                    ea=0x1000, size=2, kind=NativeItemKind.CODE, user_defined=False
                ),
            )
        )
        self._incoming_refs = incoming_refs
        self._function_ownership = (
            _DEFAULT_OWNERSHIP if function_ownership is _UNSET else function_ownership
        )

    def read_current_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        return self._current_bytes

    def read_original_bytes(self, start_ea: int, end_ea: int) -> bytes | None:
        return self._original_bytes

    def read_patch_rows(
        self, start_ea: int, end_ea: int
    ) -> tuple[InheritedPatchRow, ...]:
        return self._patch_rows

    def read_item_shape(self, start_ea: int, end_ea: int) -> NativeItemShape:
        return self._item_shape

    def read_incoming_refs(
        self, start_ea: int, end_ea: int
    ) -> tuple[NativeIncomingRef, ...]:
        return self._incoming_refs

    def read_function_ownership(self, ea: int) -> NativeFunctionOwnership | None:
        return self._function_ownership


_RANGE = NativeAddressRange(0x1000, 0x1002)


class TestCaptureRangeEvidence:
    def test_positive_capture_builds_matching_restore_snapshot(self) -> None:
        outcome = capture_range_evidence(_FakeReader(), _RANGE, function_ea=0x1000)

        assert outcome.ok
        assert outcome.evidence.expected_current_bytes == b"\x75\x01"
        assert outcome.evidence.restore_snapshot.inherited_bytes == b"\x75\x01"
        assert outcome.ea == 0x1000

    def test_reports_existing_patch_rows_faithfully(self) -> None:
        """Sets up exactly the 'existing patch-row mismatch' scenario:
        capture must faithfully reflect a live patch row so a later preflight
        comparison against a plan's stale expectation can detect the
        mismatch."""
        row = InheritedPatchRow(
            ea=0x1000,
            file_position=0x400,
            ida_original_value=0x74,
            inherited_current_value=0x75,
        )
        outcome = capture_range_evidence(
            _FakeReader(patch_rows=(row,)), _RANGE, function_ea=0x1000
        )
        assert outcome.ok
        assert outcome.evidence.expected_patch_rows == (row,)
        assert outcome.evidence.restore_snapshot.inherited_patch_rows == (row,)

    def test_reports_user_owned_incoming_ref_ownership_faithfully(self) -> None:
        ref = NativeIncomingRef(
            source_ea=0x900, target_ea=0x1001, kind="code", ownership="user"
        )
        outcome = capture_range_evidence(
            _FakeReader(incoming_refs=(ref,)), _RANGE, function_ea=0x1000
        )
        assert outcome.ok
        assert outcome.evidence.expected_incoming_refs == (ref,)
        assert outcome.evidence.expected_incoming_refs[0].ownership == "user"

    def test_reports_function_ownership_faithfully(self) -> None:
        ownership = NativeFunctionOwnership(
            owning_function_entry_ea=0x1000,
            chunk_ranges=(
                NativeAddressRange(0x1000, 0x1002),
                NativeAddressRange(0x3000, 0x3010),
            ),
        )
        outcome = capture_range_evidence(
            _FakeReader(function_ownership=ownership), _RANGE, function_ea=0x1000
        )
        assert outcome.ok
        assert outcome.evidence.expected_function_ownership == ownership
        assert outcome.evidence.restore_snapshot.function_ownership == ownership

    def test_abstains_when_current_bytes_are_not_loaded(self) -> None:
        outcome = capture_range_evidence(
            _FakeReader(current_bytes=None), _RANGE, function_ea=0x1000
        )
        assert not outcome.ok
        assert outcome.reason == CaptureAbstentionReason.LOADED_STATE_CHANGED.value
        assert outcome.ea == 0x1000  # native EA anchor present on the abstention too

    def test_abstains_when_original_bytes_cannot_be_read(self) -> None:
        outcome = capture_range_evidence(
            _FakeReader(original_bytes=None), _RANGE, function_ea=0x1000
        )
        assert not outcome.ok
        assert outcome.reason == CaptureAbstentionReason.LOADED_STATE_CHANGED.value

    def test_abstains_when_range_has_no_owning_function(self) -> None:
        outcome = capture_range_evidence(
            _FakeReader(function_ownership=None), _RANGE, function_ea=0x1000
        )
        assert not outcome.ok
        assert (
            outcome.reason
            == CaptureAbstentionReason.FUNCTION_OWNERSHIP_CHANGE_REQUIRED.value
        )
