"""Origin-map invariants for the provider-neutral native-origin vocabulary.

Task 5 ("Read-only capture, lowering, and preflight") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``, Step 1.
Section 9 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` proposes
``NativeInstructionIdentity`` / ``NativeOriginSpan`` / ``MicroblockNativeOrigin``
/ ``NativeOriginMap`` and requires: "Synthetic or ambiguous origins are valid
diagnostic facts and automatic lowering abstention reasons" and "Block serials
must always be accompanied by an EA anchor because serials are maturity-local."

``d810.ir`` is the second-lowest layer (rank 13; only ``d810.core`` is lower),
so this module -- unlike the section-9 pseudocode -- cannot reuse
``d810.transforms.native_patch_plan.NativeIncomingRef`` (rank 9, a higher
layer) or ``d810.capabilities.native_patch.NativeInstructionHead`` (rank 12,
also higher). It defines its own minimal, self-contained incoming-ref record
instead -- see the module docstring in ``d810/ir/native_origin.py``.
"""

from __future__ import annotations

import pytest

from d810.ir.native_origin import (
    NativeFixupSite,
    NativeInstructionIdentity,
    NativeOriginCoverage,
    NativeOriginIncomingRef,
    NativeOriginMap,
    NativeOriginSpan,
    MicroblockNativeOrigin,
)

pytestmark = pytest.mark.pure_python


def _insn(ea: int, length: int = 2, mnemonic: str = "jmp") -> NativeInstructionIdentity:
    return NativeInstructionIdentity(
        ea=ea,
        end_ea=ea + length,
        bytes_hash=f"hash-{ea:#x}",
        mnemonic=mnemonic,
        operand_shape=(),
        pc_relative_sites=(),
    )


class TestNativeFixupSite:
    def test_rejects_negative_site_ea(self) -> None:
        with pytest.raises(ValueError):
            NativeFixupSite(
                site_ea=-1, kind="rel32", target_ea=0x2000, original_displacement=4
            )

    def test_rejects_blank_kind(self) -> None:
        with pytest.raises(ValueError):
            NativeFixupSite(
                site_ea=0x1000, kind="", target_ea=0x2000, original_displacement=4
            )


class TestNativeInstructionIdentity:
    def test_end_ea_must_exceed_ea(self) -> None:
        with pytest.raises(ValueError):
            NativeInstructionIdentity(
                ea=0x1000,
                end_ea=0x1000,
                bytes_hash="h",
                mnemonic="jmp",
                operand_shape=(),
                pc_relative_sites=(),
            )

    def test_rejects_blank_mnemonic(self) -> None:
        with pytest.raises(ValueError):
            NativeInstructionIdentity(
                ea=0x1000,
                end_ea=0x1002,
                bytes_hash="h",
                mnemonic="",
                operand_shape=(),
                pc_relative_sites=(),
            )

    def test_length_property(self) -> None:
        insn = _insn(0x1000, length=5)
        assert insn.length == 5


class TestNativeOriginIncomingRef:
    def test_ownership_must_be_user_or_auto(self) -> None:
        with pytest.raises(ValueError):
            NativeOriginIncomingRef(
                source_ea=0x900, target_ea=0x1000, kind="jcc", ownership="maybe"
            )


class TestNativeOriginSpanCoverage:
    """Complete/partial/synthetic/ambiguous coverage negatives (Step 1)."""

    def test_complete_coverage_requires_at_least_one_instruction(self) -> None:
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1002,
                expected_bytes_hash="h",
                instructions=(),
                terminal_ea=None,
                incoming_refs=(),
                coverage=NativeOriginCoverage.COMPLETE,
            )

    def test_complete_coverage_rejects_a_non_contiguous_span(self) -> None:
        """A gap between decoded instructions is exactly a 'non-contiguous
        span' (Step 1's explicit negative) and must never be reported as
        COMPLETE -- COMPLETE means the instructions fully tile the range with
        no gap and no overlap."""
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1006,
                expected_bytes_hash="h",
                instructions=(
                    _insn(0x1000, 2),
                    _insn(0x1004, 2),
                ),  # gap at 0x1002-0x1004
                terminal_ea=0x1004,
                incoming_refs=(),
                coverage=NativeOriginCoverage.COMPLETE,
            )

    def test_complete_coverage_rejects_instructions_outside_the_range(self) -> None:
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1002,
                expected_bytes_hash="h",
                instructions=(_insn(0x1000, 4),),  # runs past end_ea
                terminal_ea=0x1000,
                incoming_refs=(),
                coverage=NativeOriginCoverage.COMPLETE,
            )

    def test_complete_coverage_accepts_a_contiguous_tiling(self) -> None:
        span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=0x1004,
            expected_bytes_hash="h",
            instructions=(_insn(0x1000, 2), _insn(0x1002, 2)),
            terminal_ea=0x1002,
            incoming_refs=(),
            coverage=NativeOriginCoverage.COMPLETE,
        )
        assert span.coverage is NativeOriginCoverage.COMPLETE

    def test_synthetic_coverage_requires_no_instructions(self) -> None:
        """A synthetic origin has no real decoded native ancestor at all."""
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1002,
                expected_bytes_hash="h",
                instructions=(_insn(0x1000, 2),),
                terminal_ea=None,
                incoming_refs=(),
                coverage=NativeOriginCoverage.SYNTHETIC,
            )

    def test_synthetic_coverage_accepts_an_empty_instruction_set(self) -> None:
        span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=0x1002,
            expected_bytes_hash="h",
            instructions=(),
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.SYNTHETIC,
        )
        assert span.coverage is NativeOriginCoverage.SYNTHETIC

    def test_partial_coverage_rejects_a_fully_contiguous_tiling(self) -> None:
        """A span that in fact fully and contiguously tiles its range is
        COMPLETE by definition; claiming PARTIAL for it is a modelling bug,
        not a legitimate partial-origin fact."""
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1004,
                expected_bytes_hash="h",
                instructions=(_insn(0x1000, 2), _insn(0x1002, 2)),
                terminal_ea=0x1002,
                incoming_refs=(),
                coverage=NativeOriginCoverage.PARTIAL,
            )

    def test_partial_coverage_accepts_a_genuine_gap(self) -> None:
        span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=0x1006,
            expected_bytes_hash="h",
            instructions=(_insn(0x1000, 2), _insn(0x1004, 2)),
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.PARTIAL,
        )
        assert span.coverage is NativeOriginCoverage.PARTIAL

    def test_ambiguous_coverage_allows_overlapping_candidate_instructions(self) -> None:
        """Ambiguous means more than one decode candidate claims the same
        bytes -- overlap is the defining feature, not a validation error."""
        span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=0x1004,
            expected_bytes_hash="h",
            instructions=(_insn(0x1000, 3), _insn(0x1001, 3)),
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.AMBIGUOUS,
        )
        assert span.coverage is NativeOriginCoverage.AMBIGUOUS

    def test_ambiguous_coverage_requires_a_reason_to_be_ambiguous(self) -> None:
        """A tidy, fully-contiguous instruction set is never legitimately
        AMBIGUOUS -- if it tiles cleanly there is nothing to be ambiguous
        about, so this must be rejected the same way PARTIAL is."""
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1004,
                expected_bytes_hash="h",
                instructions=(_insn(0x1000, 2), _insn(0x1002, 2)),
                terminal_ea=0x1002,
                incoming_refs=(),
                coverage=NativeOriginCoverage.AMBIGUOUS,
            )

    def test_end_ea_must_exceed_start_ea(self) -> None:
        with pytest.raises(ValueError):
            NativeOriginSpan(
                start_ea=0x1000,
                end_ea=0x1000,
                expected_bytes_hash="h",
                instructions=(),
                terminal_ea=None,
                incoming_refs=(),
                coverage=NativeOriginCoverage.SYNTHETIC,
            )


class TestMicroblockNativeOrigin:
    """Every block-level diagnostic must carry a native EA anchor (global
    constraint: 'A microcode block serial alone is not acceptable')."""

    def test_requires_a_native_ea_anchor(self) -> None:
        with pytest.raises(TypeError):
            MicroblockNativeOrigin(  # type: ignore[call-arg]
                microblock_serial=3,
                microblock_maturity="MMAT_GENERATED",
                spans=(),
                correlation_evidence=(),
            )

    def test_rejects_a_negative_native_ea_anchor(self) -> None:
        with pytest.raises(ValueError):
            MicroblockNativeOrigin(
                microblock_serial=3,
                microblock_maturity="MMAT_GENERATED",
                native_ea_anchor=-1,
                spans=(),
                correlation_evidence=(),
            )

    def test_rejects_a_negative_serial(self) -> None:
        with pytest.raises(ValueError):
            MicroblockNativeOrigin(
                microblock_serial=-1,
                microblock_maturity="MMAT_GENERATED",
                native_ea_anchor=0x1000,
                spans=(),
                correlation_evidence=(),
            )

    def test_one_microblock_may_map_to_multiple_non_contiguous_spans(self) -> None:
        origin = MicroblockNativeOrigin(
            microblock_serial=3,
            microblock_maturity="MMAT_GENERATED",
            native_ea_anchor=0x1000,
            spans=(
                NativeOriginSpan(
                    start_ea=0x1000,
                    end_ea=0x1002,
                    expected_bytes_hash="h1",
                    instructions=(_insn(0x1000, 2),),
                    terminal_ea=0x1000,
                    incoming_refs=(),
                    coverage=NativeOriginCoverage.COMPLETE,
                ),
                NativeOriginSpan(
                    start_ea=0x2000,
                    end_ea=0x2002,
                    expected_bytes_hash="h2",
                    instructions=(_insn(0x2000, 2),),
                    terminal_ea=0x2000,
                    incoming_refs=(),
                    coverage=NativeOriginCoverage.COMPLETE,
                ),
            ),
            correlation_evidence=("split across a compiler-inserted pad",),
        )
        assert len(origin.spans) == 2


class TestNativeOriginMap:
    def test_map_fingerprint_is_deterministic(self) -> None:
        def build() -> NativeOriginMap:
            return NativeOriginMap(
                function_entry_ea=0x1000,
                input_fingerprint="fp-1",
                microblock_origins=(
                    MicroblockNativeOrigin(
                        microblock_serial=1,
                        microblock_maturity="MMAT_GENERATED",
                        native_ea_anchor=0x1000,
                        spans=(),
                        correlation_evidence=(),
                    ),
                ),
            )

        first, second = build(), build()
        assert first.map_fingerprint == second.map_fingerprint

    def test_map_fingerprint_changes_with_content(self) -> None:
        def build(anchor: int) -> NativeOriginMap:
            return NativeOriginMap(
                function_entry_ea=0x1000,
                input_fingerprint="fp-1",
                microblock_origins=(
                    MicroblockNativeOrigin(
                        microblock_serial=1,
                        microblock_maturity="MMAT_GENERATED",
                        native_ea_anchor=anchor,
                        spans=(),
                        correlation_evidence=(),
                    ),
                ),
            )

        first, second = build(0x1000), build(0x2000)
        assert first.map_fingerprint != second.map_fingerprint

    def test_multiple_microblocks_may_cite_the_same_span_as_provenance(self) -> None:
        """Multiple microblocks citing the same native span is valid
        provenance overlap -- only a *patch plan*'s mutation ownership must
        not overlap (enforced separately by
        ``NativePatchPlan``/``OverlappingNativePatchOperationsError``)."""
        shared_span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=0x1002,
            expected_bytes_hash="h",
            instructions=(_insn(0x1000, 2),),
            terminal_ea=0x1000,
            incoming_refs=(),
            coverage=NativeOriginCoverage.COMPLETE,
        )
        origin_map = NativeOriginMap(
            function_entry_ea=0x1000,
            input_fingerprint="fp-1",
            microblock_origins=(
                MicroblockNativeOrigin(
                    microblock_serial=1,
                    microblock_maturity="MMAT_GENERATED",
                    native_ea_anchor=0x1000,
                    spans=(shared_span,),
                    correlation_evidence=(),
                ),
                MicroblockNativeOrigin(
                    microblock_serial=2,
                    microblock_maturity="MMAT_LVARS",
                    native_ea_anchor=0x1000,
                    spans=(shared_span,),
                    correlation_evidence=(),
                ),
            ),
        )
        assert len(origin_map.microblock_origins) == 2
