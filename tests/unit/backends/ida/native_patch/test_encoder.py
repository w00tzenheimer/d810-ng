"""Unit tests for the minimal x86/x64 branch encoder.

The encoder is the version-1 provider described in section 12 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md``: a tiny explicit encoder for ``jmp``,
``jcc``, and NOP padding, chosen over a general assembler to minimise syntax and
dependency risk.

These tests are pure. The encoder emits bytes and must never touch IDA.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.encoder import (
    AbstentionReason,
    Condition,
    MinimalX86BranchEncoder,
    decode,
    encode_jcc,
    encode_jmp,
    encode_nop_padding,
    plan_conditional_region,
    plan_direct_jump_region,
)
from d810.capabilities.native_patch import EncodingProvider

pytestmark = pytest.mark.pure_python


class TestEncodeJmpRel8:
    """Short-form ``EB cb`` encoding and its displacement arithmetic."""

    def test_forward_jump_uses_two_byte_form(self):
        outcome = encode_jmp(ea=0x1000, target=0x1005)

        assert outcome.ok
        # next_ip = 0x1000 + 2 = 0x1002; disp = 0x1005 - 0x1002 = 3
        assert outcome.instruction.data == bytes([0xEB, 0x03])
        assert outcome.instruction.displacement == 3
        assert outcome.instruction.mnemonic == "jmp"

    def test_jump_to_self_encodes_negative_two(self):
        outcome = encode_jmp(ea=0x1000, target=0x1000)

        assert outcome.ok
        # disp = 0x1000 - 0x1002 = -2 -> 0xFE
        assert outcome.instruction.data == bytes([0xEB, 0xFE])
        assert outcome.instruction.displacement == -2

    def test_maximum_forward_rel8_target_still_fits(self):
        # disp 127 is the largest signed byte: target = ea + 2 + 127
        outcome = encode_jmp(ea=0x1000, target=0x1000 + 129)

        assert outcome.ok
        assert outcome.instruction.data == bytes([0xEB, 0x7F])

    def test_minimum_backward_rel8_target_still_fits(self):
        # disp -128 is the smallest signed byte: target = ea + 2 - 128
        outcome = encode_jmp(ea=0x1000, target=0x1000 - 126)

        assert outcome.ok
        assert outcome.instruction.data == bytes([0xEB, 0x80])


class TestEncodeJmpRel32:
    """Near-form ``E9 cd`` encoding, selected when rel8 cannot reach."""

    def test_one_past_rel8_range_promotes_to_rel32(self):
        outcome = encode_jmp(ea=0x1000, target=0x1000 + 130)

        assert outcome.ok
        # next_ip = 0x1005; disp = 0x1082 - 0x1005 = 0x7D
        assert outcome.instruction.data == bytes([0xE9, 0x7D, 0x00, 0x00, 0x00])
        assert outcome.instruction.displacement == 0x7D

    def test_backward_rel32_encodes_twos_complement_little_endian(self):
        outcome = encode_jmp(ea=0x1000, target=0x1000 - 127)

        assert outcome.ok
        # next_ip = 0x1005; disp = 0xF81 - 0x1005 = -132 -> 0xFFFFFF7C
        assert outcome.instruction.data == bytes([0xE9, 0x7C, 0xFF, 0xFF, 0xFF])
        assert outcome.instruction.displacement == -132


class TestEncodeJmpExplicitWidth:
    """A fixed-size region needs a fixed-size branch, not the shortest one."""

    def test_width_32_is_honoured_even_when_rel8_would_reach(self):
        outcome = encode_jmp(ea=0x1000, target=0x1005, width=32)

        assert outcome.ok
        # next_ip = 0x1005; disp = 0
        assert outcome.instruction.data == bytes([0xE9, 0x00, 0x00, 0x00, 0x00])

    def test_width_8_abstains_when_target_is_out_of_reach(self):
        outcome = encode_jmp(ea=0x1000, target=0x9000, width=8)

        assert not outcome.ok
        assert outcome.instruction is None
        assert outcome.reason is AbstentionReason.UNREPRESENTABLE_BRANCH


class TestEncodeJmpAbstention:
    """Fail closed with a stable reason; never raise, never guess."""

    def test_displacement_beyond_rel32_abstains(self):
        outcome = encode_jmp(ea=0x1000, target=0x1000 + (1 << 32), bitness=64)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNREPRESENTABLE_BRANCH

    def test_target_outside_address_space_abstains(self):
        outcome = encode_jmp(ea=0x1000, target=1 << 33, bitness=32)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNSUPPORTED_ARCHITECTURE

    def test_unsupported_bitness_abstains(self):
        outcome = encode_jmp(ea=0x1000, target=0x1005, bitness=16)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNSUPPORTED_ARCHITECTURE


class TestConditionInversion:
    """Inverting a predicate is XOR 1 over the low ``tttn`` nibble.

    Mode A's stencil and retired-reference's compact-dispatcher rewrite both need the
    inverse predicate to build a jump-over, so the encoder owns the operation
    rather than leaving each caller to open-code ``condition ^ 1``.
    """

    def test_equal_inverts_to_not_equal(self):
        assert Condition.E.inverted() is Condition.NE

    def test_inversion_is_an_involution_for_every_condition(self):
        for condition in Condition:
            assert condition.inverted().inverted() is condition

    def test_no_condition_is_its_own_inverse(self):
        for condition in Condition:
            assert condition.inverted() is not condition


class TestEncodeJccRel8:
    """Short-form ``70+cc cb`` encoding."""

    def test_forward_conditional_uses_two_byte_form(self):
        outcome = encode_jcc(ea=0x1000, target=0x1005, condition=Condition.E)

        assert outcome.ok
        # 0x70 + 0x4 = 0x74 (je); disp = 0x1005 - 0x1002 = 3
        assert outcome.instruction.data == bytes([0x74, 0x03])
        assert outcome.instruction.mnemonic == "je"

    def test_condition_selects_the_opcode_nibble(self):
        outcome = encode_jcc(ea=0x1000, target=0x1002, condition=Condition.NE)

        assert outcome.ok
        assert outcome.instruction.data[0] == 0x75

    def test_maximum_forward_rel8_target_still_fits(self):
        outcome = encode_jcc(ea=0x1000, target=0x1000 + 129, condition=Condition.L)

        assert outcome.ok
        assert outcome.instruction.data == bytes([0x7C, 0x7F])


class TestEncodeJccRel32:
    """Near-form ``0F 80+cc cd`` encoding is six bytes, not five."""

    def test_one_past_rel8_range_promotes_to_six_byte_form(self):
        outcome = encode_jcc(ea=0x1000, target=0x1000 + 130, condition=Condition.E)

        assert outcome.ok
        # next_ip = 0x1006; disp = 0x1082 - 0x1006 = 0x7C
        assert outcome.instruction.data == bytes([0x0F, 0x84, 0x7C, 0x00, 0x00, 0x00])
        assert outcome.instruction.displacement == 0x7C

    def test_explicit_width_32_is_honoured(self):
        outcome = encode_jcc(ea=0x1000, target=0x1006, condition=Condition.NE, width=32)

        assert outcome.ok
        assert outcome.instruction.data == bytes([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00])


class TestEncodeJccAbstention:
    def test_width_8_out_of_reach_abstains(self):
        outcome = encode_jcc(ea=0x1000, target=0x9000, condition=Condition.E, width=8)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNREPRESENTABLE_BRANCH

    def test_unsupported_bitness_abstains(self):
        outcome = encode_jcc(
            ea=0x1000, target=0x1005, condition=Condition.E, bitness=16
        )

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNSUPPORTED_ARCHITECTURE


class TestNopPadding:
    """Multi-byte NOP fill for the unused tail of an owned region.

    Filling with 0x90 repeated would also be correct machine code, but it
    decodes as N separate instructions. The Intel-recommended long forms keep
    the region a handful of items so the post-patch instruction-head shape is
    small enough to assert on.
    """

    def test_zero_length_is_an_empty_sequence(self):
        outcome = encode_nop_padding(ea=0x1000, length=0)

        assert outcome.ok
        assert outcome.sequence.data == b""
        assert outcome.sequence.instructions == ()

    @pytest.mark.parametrize(
        ("length", "expected"),
        [
            (1, bytes([0x90])),
            (2, bytes([0x66, 0x90])),
            (3, bytes([0x0F, 0x1F, 0x00])),
            (4, bytes([0x0F, 0x1F, 0x40, 0x00])),
            (5, bytes([0x0F, 0x1F, 0x44, 0x00, 0x00])),
            (6, bytes([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00])),
            (7, bytes([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00])),
            (8, bytes([0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00])),
            (9, bytes([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00])),
        ],
    )
    def test_single_instruction_forms(self, length, expected):
        outcome = encode_nop_padding(ea=0x1000, length=length)

        assert outcome.ok
        assert outcome.sequence.data == expected
        assert len(outcome.sequence.instructions) == 1

    def test_ten_bytes_chunks_into_nine_plus_one(self):
        outcome = encode_nop_padding(ea=0x1000, length=10)

        assert outcome.ok
        assert len(outcome.sequence.instructions) == 2
        assert outcome.sequence.instructions[0].ea == 0x1000
        assert len(outcome.sequence.instructions[0].data) == 9
        assert outcome.sequence.instructions[1].ea == 0x1009
        assert outcome.sequence.instructions[1].data == bytes([0x90])

    def test_padding_always_fills_exactly_the_requested_length(self):
        for length in range(0, 65):
            outcome = encode_nop_padding(ea=0x1000, length=length)
            assert outcome.ok, length
            assert len(outcome.sequence.data) == length, length

    def test_instruction_addresses_are_contiguous(self):
        outcome = encode_nop_padding(ea=0x2000, length=31)

        assert outcome.ok
        cursor = 0x2000
        for instruction in outcome.sequence.instructions:
            assert instruction.ea == cursor
            cursor += len(instruction.data)
        assert cursor == 0x2000 + 31

    def test_negative_length_abstains(self):
        outcome = encode_nop_padding(ea=0x1000, length=-1)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INVALID_REGION


class TestPlanDirectJumpRegion:
    """Mode A's simplest lowering: an owned terminator span becomes one jump.

    The planner owns the whole region. Whatever the branch does not use is
    padded, so the emitted image always measures exactly the region -- a short
    write would leave live bytes from the old terminator behind.
    """

    def test_region_is_filled_exactly_with_branch_then_padding(self):
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1005, target=0x1003)

        assert outcome.ok
        assert outcome.sequence.size == 5
        # rel8 reaches: next_ip = 0x1002, disp = 1
        assert outcome.sequence.data[:2] == bytes([0xEB, 0x01])
        assert outcome.sequence.data[2:] == bytes([0x0F, 0x1F, 0x00])

    def test_exact_two_byte_region_needs_no_padding(self):
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1002, target=0x1010)

        assert outcome.ok
        assert outcome.sequence.size == 2
        assert len(outcome.sequence.instructions) == 1

    def test_far_target_promotes_to_rel32_and_still_fills(self):
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1008, target=0x9000)

        assert outcome.ok
        assert outcome.sequence.size == 8
        assert outcome.sequence.data[0] == 0xE9

    def test_region_too_small_for_any_branch_abstains(self):
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1001, target=0x1010)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INSUFFICIENT_SPACE

    def test_region_too_small_for_the_required_width_abstains(self):
        # Only 2 bytes available, but the target needs rel32.
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1002, target=0x9000)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INSUFFICIENT_SPACE

    def test_empty_region_abstains(self):
        outcome = plan_direct_jump_region(start_ea=0x1000, end_ea=0x1000, target=0x1010)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INVALID_REGION

    def test_inverted_region_abstains(self):
        outcome = plan_direct_jump_region(start_ea=0x1005, end_ea=0x1000, target=0x1010)

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INVALID_REGION


class TestPlanConditionalRegion:
    """``jcc <true>; jmp <false>; pad`` -- the two-successor Mode A stencil.

    Each branch is encoded at the address it will actually occupy, so the
    second branch's displacement depends on the width chosen for the first.
    """

    def test_both_branches_reach_with_short_forms(self):
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x1010,
            condition=Condition.E,
            true_target=0x1050,
            false_target=0x1080,
        )

        assert outcome.ok
        assert outcome.sequence.size == 0x10
        # je rel8 at 0x1000: next_ip 0x1002, disp 0x4E
        assert outcome.sequence.data[0:2] == bytes([0x74, 0x4E])
        # jmp rel8 at 0x1002: next_ip 0x1004, disp 0x7C
        assert outcome.sequence.data[2:4] == bytes([0xEB, 0x7C])

    def test_second_branch_displacement_accounts_for_first_branch_width(self):
        # Forces the jcc to rel32 (6 bytes), so the jmp sits at start + 6.
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x1020,
            condition=Condition.E,
            true_target=0x8000,
            false_target=0x1010,
        )

        assert outcome.ok
        assert outcome.sequence.data[0:2] == bytes([0x0F, 0x84])
        jmp = outcome.sequence.instructions[1]
        assert jmp.ea == 0x1006
        # rel8 at 0x1006: next_ip 0x1008, disp = 0x1010 - 0x1008 = 8
        assert jmp.data == bytes([0xEB, 0x08])

    def test_minimum_four_byte_region_fits_two_short_branches(self):
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x1004,
            condition=Condition.NE,
            true_target=0x1020,
            false_target=0x1030,
        )

        assert outcome.ok
        assert outcome.sequence.size == 4
        assert len(outcome.sequence.instructions) == 2

    def test_region_too_small_for_the_stencil_abstains(self):
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x1003,
            condition=Condition.E,
            true_target=0x1020,
            false_target=0x1030,
        )

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.INSUFFICIENT_SPACE

    def test_unreachable_target_abstains_rather_than_truncating(self):
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x1020,
            condition=Condition.E,
            true_target=0x1050,
            false_target=0x1000 + (1 << 32),
            bitness=64,
        )

        assert not outcome.ok
        assert outcome.reason is AbstentionReason.UNREPRESENTABLE_BRANCH


class TestDecode:
    """Independent decode of exactly the byte forms this encoder emits.

    Not a general x86 decoder -- see the module docstring's "no dependency to
    pin" rationale. It only has to recognise what ``encode_jmp``/``encode_jcc``/
    ``encode_nop_padding`` could have produced, because its purpose is
    self-verification of emitted bytes (``NativeEncodingEvidence.
    independent_decode_hash``), not general disassembly.
    """

    def test_decodes_jmp_rel8(self):
        shape = decode(0x1000, bytes([0xEB, 0x03]))
        assert len(shape.heads) == 1
        head = shape.heads[0]
        assert (head.ea, head.length, head.mnemonic) == (0x1000, 2, "jmp")
        assert head.successors == (0x1005,)

    def test_decodes_jmp_rel32(self):
        outcome = encode_jmp(ea=0x1000, target=0x1000 + 0x10000, width=32)
        shape = decode(0x1000, outcome.instruction.data)
        assert len(shape.heads) == 1
        head = shape.heads[0]
        assert (head.ea, head.length, head.mnemonic) == (0x1000, 5, "jmp")
        assert head.successors == (0x1000 + 0x10000,)

    def test_decodes_jcc_rel8(self):
        outcome = encode_jcc(ea=0x2000, target=0x2010, condition=Condition.E)
        shape = decode(0x2000, outcome.instruction.data)
        head = shape.heads[0]
        assert (head.ea, head.length, head.mnemonic) == (0x2000, 2, "je")
        assert head.successors == (0x2010,)

    def test_decodes_jcc_rel32(self):
        outcome = encode_jcc(
            ea=0x2000, target=0x2000 + 0x10000, condition=Condition.NE, width=32
        )
        shape = decode(0x2000, outcome.instruction.data)
        head = shape.heads[0]
        assert (head.ea, head.length, head.mnemonic) == (0x2000, 6, "jne")

    def test_decodes_nop_padding_of_several_lengths(self):
        for length in (1, 2, 3, 5, 9, 11, 17):
            padding = encode_nop_padding(0x3000, length)
            assert padding.ok
            shape = decode(0x3000, padding.sequence.data)
            assert sum(h.length for h in shape.heads) == length
            assert all(h.mnemonic == "nop" for h in shape.heads)

    def test_decodes_a_conditional_region_stencil(self):
        outcome = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x100C,
            condition=Condition.E,
            true_target=0x1020,
            false_target=0x1030,
        )
        assert outcome.ok
        shape = decode(0x1000, outcome.sequence.data)
        mnemonics = [h.mnemonic for h in shape.heads]
        assert mnemonics[0] == "je"
        assert mnemonics[1] == "jmp"
        assert all(m == "nop" for m in mnemonics[2:])
        assert sum(h.length for h in shape.heads) == 0x0C

    def test_raises_on_bytes_it_did_not_emit(self):
        with pytest.raises(ValueError):
            decode(0x1000, bytes([0x90, 0xCC]))  # 0xCC (int3) is not in our vocabulary


class TestMinimalX86BranchEncoderSatisfiesEncodingProvider:
    """The existing encoder module implements ``EncodingProvider`` -- see the
    Task 5 layer-correction block: ``transforms.native_patch_lowering`` depends
    on the Protocol declared in ``d810.capabilities.native_patch``, never on
    this module directly."""

    def test_isinstance_check_passes(self):
        assert isinstance(MinimalX86BranchEncoder(), EncodingProvider)

    def test_encode_direct_jump_matches_plan_direct_jump_region(self):
        provider = MinimalX86BranchEncoder()
        result = provider.encode_direct_jump(0x1000, 0x1002, 0x1010, bitness=64)

        assert result.ok
        plan = plan_direct_jump_region(0x1000, 0x1002, 0x1010)
        assert result.replacement_bytes == plan.sequence.data
        assert len(result.expected_after_shape.heads) >= 1
        assert result.expected_after_shape.heads[0].mnemonic == "jmp"

    def test_encode_direct_jump_abstains_with_the_provider_reason(self):
        provider = MinimalX86BranchEncoder()
        # A single byte cannot fit any representable branch encoding.
        result = provider.encode_direct_jump(
            0x1000, 0x1001, 0x1000 + (1 << 40), bitness=64
        )

        assert not result.ok
        assert result.reason == AbstentionReason.UNREPRESENTABLE_BRANCH.value

    def test_encode_conditional_matches_plan_conditional_region(self):
        provider = MinimalX86BranchEncoder()
        result = provider.encode_conditional(
            0x1000,
            0x100C,
            condition="E",
            true_target_ea=0x1020,
            false_target_ea=0x1030,
            bitness=64,
        )

        assert result.ok
        plan = plan_conditional_region(
            start_ea=0x1000,
            end_ea=0x100C,
            condition=Condition.E,
            true_target=0x1020,
            false_target=0x1030,
        )
        assert result.replacement_bytes == plan.sequence.data

    def test_encode_conditional_rejects_an_unknown_condition_name(self):
        provider = MinimalX86BranchEncoder()
        result = provider.encode_conditional(
            0x1000,
            0x100C,
            condition="NOT_A_CONDITION",
            true_target_ea=0x1020,
            false_target_ea=0x1030,
            bitness=64,
        )

        assert not result.ok
        assert result.reason == AbstentionReason.UNREPRESENTABLE_BRANCH.value

    def test_decode_method_delegates_to_module_level_decode(self):
        provider = MinimalX86BranchEncoder()
        data = bytes([0xEB, 0x03])
        assert provider.decode(0x1000, data, bitness=64) == decode(0x1000, data)
