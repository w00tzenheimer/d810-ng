"""Pure lowering of a captured native-origin edge to a Mode-A
``NativePatchOperation`` (Task 5 Step 2/3 of
``_gitless/profile-guided-native-mutation-implementer-plan.md``).

Covers Step 2's required negatives: rel8/rel32 boundaries, insufficient
in-place space, target not at an instruction head, an unsupported conditional
predicate, and a state-store edge that lacks an ``EdgeStateContract``
authorization (deliberately not designed here -- see the module docstring in
``d810/transforms/native_patch_lowering.py`` for why this abstains rather than
invents the contract).

Uses the real ``MinimalX86BranchEncoder`` (``d810.backends.ida.native_patch.
encoder``, IDA-free) as the injected ``EncodingProvider`` throughout: unlike
production ``native_patch_lowering.py``, a *test* importing a ``backends``
module is not a layer violation (the layered-architecture contract only
governs ``d810.*`` packages, not ``tests.*``), and using the real provider
proves genuine integration instead of a hand-maintained fake's assumptions.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder
from d810.ir.native_origin import (
    NativeInstructionIdentity,
    NativeOriginCoverage,
    NativeOriginSpan,
)
from d810.ir.semantics import PredicateKind
from d810.transforms.native_patch_lowering import (
    NativeEdgeAbstentionReason,
    NativeEdgeCaptureEvidence,
    lower_conditional_edge,
    lower_direct_edge,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeFunctionOwnership,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
    NativeRestoreSnapshot,
)

pytestmark = pytest.mark.pure_python

_PROVIDER = MinimalX86BranchEncoder()


def _insn(ea: int, length: int = 2, mnemonic: str = "jcc") -> NativeInstructionIdentity:
    return NativeInstructionIdentity(
        ea=ea,
        end_ea=ea + length,
        bytes_hash=f"h-{ea:#x}",
        mnemonic=mnemonic,
        operand_shape=(),
        pc_relative_sites=(),
    )


def _origin_span(
    start_ea: int = 0x1000,
    end_ea: int = 0x1002,
    *,
    instructions: tuple[NativeInstructionIdentity, ...] | None = None,
    coverage: NativeOriginCoverage = NativeOriginCoverage.COMPLETE,
) -> NativeOriginSpan:
    size = end_ea - start_ea
    if instructions is None:
        instructions = (
            (_insn(start_ea, size, "jne"),) if coverage.value == "complete" else ()
        )
    return NativeOriginSpan(
        start_ea=start_ea,
        end_ea=end_ea,
        expected_bytes_hash="src-hash",
        instructions=instructions,
        terminal_ea=start_ea if instructions else None,
        incoming_refs=(),
        coverage=coverage,
    )


def _capture(start_ea: int, size: int) -> NativeEdgeCaptureEvidence:
    return NativeEdgeCaptureEvidence(
        expected_current_bytes=bytes([0x75, 0x00] + [0x90] * (size - 2))
        if size >= 2
        else bytes(size),
        expected_original_bytes=bytes([0x75, 0x00] + [0x90] * (size - 2))
        if size >= 2
        else bytes(size),
        expected_patch_rows=(),
        expected_item_shape=NativeItemShape(
            heads=(
                NativeItemHead(
                    ea=start_ea,
                    size=size,
                    kind=NativeItemKind.CODE,
                    user_defined=False,
                ),
            )
        ),
        expected_incoming_refs=(),
        expected_function_ownership=NativeFunctionOwnership(
            owning_function_entry_ea=start_ea,
            chunk_ranges=(NativeAddressRange(start_ea, start_ea + size),),
        ),
        restore_snapshot=NativeRestoreSnapshot(
            inherited_bytes=bytes([0x75, 0x00] + [0x90] * (size - 2))
            if size >= 2
            else bytes(size),
            inherited_patch_rows=(),
            item_shape=NativeItemShape(
                heads=(
                    NativeItemHead(
                        ea=start_ea,
                        size=size,
                        kind=NativeItemKind.CODE,
                        user_defined=False,
                    ),
                )
            ),
            incoming_refs=(),
            function_ownership=NativeFunctionOwnership(
                owning_function_entry_ea=start_ea,
                chunk_ranges=(NativeAddressRange(start_ea, start_ea + size),),
            ),
            switch_fixup_metadata=(),
        ),
    )


class TestLowerDirectEdgePositive:
    def test_produces_a_valid_operation_with_a_short_jump(self) -> None:
        span = _origin_span(0x1000, 0x1002)
        outcome = lower_direct_edge(
            operation_id="op-1",
            origin_span=span,
            target_ea=0x1010,
            known_instruction_heads=frozenset({0x1010}),
            capture=_capture(0x1000, 2),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )

        assert outcome.ok
        op = outcome.operation
        assert op.range == NativeAddressRange(0x1000, 0x1002)
        assert op.replacement_bytes == bytes([0xEB, 0x0E])
        assert op.expected_after_successors == (0x1010,)
        assert op.expected_after_shape.heads[0].mnemonic == "jmp"
        assert op.encoding_evidence.provider_id == "minimal-x86"
        assert op.expected_current_bytes == _capture(0x1000, 2).expected_current_bytes

    def test_wide_region_promotes_to_rel32_and_pads_with_nop(self) -> None:
        # A 6-byte region cannot be reached by rel8 to a far target, but
        # comfortably fits the 5-byte rel32 jmp plus one NOP byte of padding.
        span = _origin_span(0x1000, 0x1006, instructions=(_insn(0x1000, 6, "jne"),))
        far_target = 0x1000 + 0x10000
        outcome = lower_direct_edge(
            operation_id="op-2",
            origin_span=span,
            target_ea=far_target,
            known_instruction_heads=frozenset({far_target}),
            capture=_capture(0x1000, 6),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )

        assert outcome.ok
        assert len(outcome.operation.replacement_bytes) == 6
        assert outcome.operation.replacement_bytes[0] == 0xE9  # jmp rel32


class TestLowerDirectEdgeNegatives:
    def test_rel8_boundary_one_byte_past_reach_falls_back_and_succeeds(self) -> None:
        """Not a negative by itself -- proves the boundary is exact: one byte
        beyond rel8 range still succeeds by promoting to rel32 when the
        region has room."""
        span = _origin_span(0x1000, 0x1005, instructions=(_insn(0x1000, 5, "jne"),))
        outcome = lower_direct_edge(
            operation_id="op-3",
            origin_span=span,
            target_ea=0x1000 + 130,
            known_instruction_heads=frozenset({0x1000 + 130}),
            capture=_capture(0x1000, 5),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert outcome.ok
        assert outcome.operation.replacement_bytes[0] == 0xE9

    def test_displacement_beyond_rel32_abstains(self) -> None:
        span = _origin_span(0x1000, 0x1006, instructions=(_insn(0x1000, 6, "jne"),))
        far_target = 0x1000 + (1 << 32)
        outcome = lower_direct_edge(
            operation_id="op-4",
            origin_span=span,
            target_ea=far_target,
            known_instruction_heads=frozenset({far_target}),
            capture=_capture(0x1000, 6),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == "UNREPRESENTABLE_BRANCH"

    def test_insufficient_in_place_space_abstains(self) -> None:
        # A 1-byte region cannot fit even the shortest jmp rel8 (2 bytes).
        # The mnemonic is still a pure control transfer so this fails on
        # space, not on the state-store check.
        span = _origin_span(0x1000, 0x1001, instructions=(_insn(0x1000, 1, "jne"),))
        outcome = lower_direct_edge(
            operation_id="op-5",
            origin_span=span,
            target_ea=0x2000,
            known_instruction_heads=frozenset({0x2000}),
            capture=_capture(0x1000, 1),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == "INSUFFICIENT_SPACE"

    def test_target_not_at_an_instruction_head_abstains(self) -> None:
        span = _origin_span(0x1000, 0x1002)
        outcome = lower_direct_edge(
            operation_id="op-6",
            origin_span=span,
            target_ea=0x1010,
            known_instruction_heads=frozenset({0x1011}),  # 0x1010 is not a head
            capture=_capture(0x1000, 2),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == NativeEdgeAbstentionReason.INSTRUCTION_SPLIT.value

    def test_state_store_edge_with_extra_instruction_requires_edge_state_contract(
        self,
    ) -> None:
        """The origin span covers more than the terminator itself (a second,
        data-defining instruction folded into the candidate region). Removing
        it would eliminate a register/memory/flag definition -- authorizing
        that needs an EdgeStateContract, which does not exist yet, so this
        must abstain rather than silently drop the definition."""
        span = _origin_span(
            0x1000,
            0x1004,
            instructions=(_insn(0x1000, 2, "mov"), _insn(0x1002, 2, "jne")),
        )
        outcome = lower_direct_edge(
            operation_id="op-7",
            origin_span=span,
            target_ea=0x2000,
            known_instruction_heads=frozenset({0x2000}),
            capture=_capture(0x1000, 4),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert (
            outcome.reason
            == NativeEdgeAbstentionReason.EDGE_STATE_CONTRACT_REQUIRED.value
        )

    def test_single_non_branch_instruction_also_requires_edge_state_contract(
        self,
    ) -> None:
        """Even a single instruction is a state-store edge if it is not
        itself a pure control transfer -- Mode A only ever replaces a
        terminator, never a data-defining instruction."""
        span = _origin_span(0x1000, 0x1002, instructions=(_insn(0x1000, 2, "mov"),))
        outcome = lower_direct_edge(
            operation_id="op-8",
            origin_span=span,
            target_ea=0x2000,
            known_instruction_heads=frozenset({0x2000}),
            capture=_capture(0x1000, 2),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert (
            outcome.reason
            == NativeEdgeAbstentionReason.EDGE_STATE_CONTRACT_REQUIRED.value
        )

    @pytest.mark.parametrize(
        "coverage,expected_reason",
        [
            (
                NativeOriginCoverage.PARTIAL,
                NativeEdgeAbstentionReason.PARTIAL_NATIVE_ORIGIN.value,
            ),
            (
                NativeOriginCoverage.AMBIGUOUS,
                NativeEdgeAbstentionReason.AMBIGUOUS_NATIVE_ORIGIN.value,
            ),
            (
                NativeOriginCoverage.SYNTHETIC,
                NativeEdgeAbstentionReason.SYNTHETIC_NATIVE_ORIGIN.value,
            ),
        ],
    )
    def test_non_complete_origin_coverage_always_abstains(
        self, coverage: NativeOriginCoverage, expected_reason: str
    ) -> None:
        if coverage is NativeOriginCoverage.PARTIAL:
            instructions = (_insn(0x1000, 2, "jne"), _insn(0x1006, 2, "jmp"))
            end_ea = 0x1008
        elif coverage is NativeOriginCoverage.AMBIGUOUS:
            instructions = (_insn(0x1000, 3, "jne"), _insn(0x1001, 3, "jmp"))
            end_ea = 0x1004
        else:
            instructions = ()
            end_ea = 0x1002
        span = NativeOriginSpan(
            start_ea=0x1000,
            end_ea=end_ea,
            expected_bytes_hash="h",
            instructions=instructions,
            terminal_ea=None,
            incoming_refs=(),
            coverage=coverage,
        )
        outcome = lower_direct_edge(
            operation_id="op-9",
            origin_span=span,
            target_ea=0x2000,
            known_instruction_heads=frozenset({0x2000}),
            capture=_capture(0x1000, end_ea - 0x1000),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == expected_reason


class TestLowerConditionalEdge:
    def test_supported_predicate_produces_a_jcc_jmp_stencil(self) -> None:
        span = _origin_span(0x1000, 0x100C, instructions=(_insn(0x1000, 0x0C, "jne"),))
        outcome = lower_conditional_edge(
            operation_id="op-10",
            origin_span=span,
            condition=PredicateKind.EQ,
            true_target_ea=0x1020,
            false_target_ea=0x1030,
            known_instruction_heads=frozenset({0x1020, 0x1030}),
            capture=_capture(0x1000, 0x0C),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert outcome.ok
        heads = outcome.operation.expected_after_shape.heads
        assert heads[0].mnemonic == "je"
        assert heads[1].mnemonic == "jmp"
        assert outcome.operation.expected_after_successors == (0x1020, 0x1030)

    def test_truthy_predicate_has_no_single_condition_code_and_abstains(self) -> None:
        """PredicateKind.TRUTHY (m_jcnd) tests a value, not a flag -- there is
        no single x86 Jcc that represents it in this minimal encoder, so
        lowering must abstain instead of guessing a codegen sequence."""
        span = _origin_span(0x1000, 0x100C, instructions=(_insn(0x1000, 0x0C, "jne"),))
        outcome = lower_conditional_edge(
            operation_id="op-11",
            origin_span=span,
            condition=PredicateKind.TRUTHY,
            true_target_ea=0x1020,
            false_target_ea=0x1030,
            known_instruction_heads=frozenset({0x1020, 0x1030}),
            capture=_capture(0x1000, 0x0C),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == NativeEdgeAbstentionReason.UNREPRESENTABLE_BRANCH.value

    def test_false_target_not_at_an_instruction_head_abstains(self) -> None:
        span = _origin_span(0x1000, 0x100C, instructions=(_insn(0x1000, 0x0C, "jne"),))
        outcome = lower_conditional_edge(
            operation_id="op-12",
            origin_span=span,
            condition=PredicateKind.EQ,
            true_target_ea=0x1020,
            false_target_ea=0x1030,
            known_instruction_heads=frozenset({0x1020}),  # 0x1030 missing
            capture=_capture(0x1000, 0x0C),
            provider=_PROVIDER,
            provider_id="minimal-x86",
            provider_version="1",
        )
        assert not outcome.ok
        assert outcome.reason == NativeEdgeAbstentionReason.INSTRUCTION_SPLIT.value
