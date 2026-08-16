"""Minimal explicit x86/x86-64 branch encoder.

Section 12 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` picks a tiny hand-rolled
encoder as the version-1 provider, ahead of IDA's ``AssembleLine`` and ahead of
Keystone, because ``jmp``/``jcc``/NOP is the whole vocabulary Mode A needs and a
hand-rolled encoder has no syntax surface and no dependency to pin.

Two rules govern everything here:

* **Bytes only.** A provider receives a final instruction EA and returns bytes
  plus the decoded shape it believes it emitted. It never reads or writes the
  database. This module must not import ``ida_*``; keeping it IDA-free is what
  makes it unit-testable and what keeps ``AssembleLine`` swappable behind the
  same signature later.
* **Fail closed.** Anything this encoder cannot represent exactly returns an
  abstention with a stable reason. It never raises for an unrepresentable
  branch, never silently widens a caller-requested width, and never picks a
  nearby target.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass

from d810.capabilities.native_patch import (
    NativeEncodingResult,
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)

__all__ = [
    "AbstentionReason",
    "Condition",
    "EncodeOutcome",
    "EncodedInstruction",
    "EncodedSequence",
    "MinimalX86BranchEncoder",
    "SequenceOutcome",
    "decode",
    "encode_jcc",
    "encode_jmp",
    "encode_nop_padding",
    "plan_conditional_region",
    "plan_direct_jump_region",
]

# Intel-recommended multi-byte NOP forms, indexed by encoded length. Filling a
# region with repeated 0x90 is equally valid machine code but produces one
# instruction head per byte, which makes the post-patch item shape large and
# noisy to assert on.
_NOP_FORMS = {
    1: bytes([0x90]),
    2: bytes([0x66, 0x90]),
    3: bytes([0x0F, 0x1F, 0x00]),
    4: bytes([0x0F, 0x1F, 0x40, 0x00]),
    5: bytes([0x0F, 0x1F, 0x44, 0x00, 0x00]),
    6: bytes([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]),
    7: bytes([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]),
    8: bytes([0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
    9: bytes([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
}
_MAX_NOP_FORM = max(_NOP_FORMS)

_SUPPORTED_BITNESS = (32, 64)

_JMP_REL8_OPCODE = 0xEB
_JMP_REL32_OPCODE = 0xE9
_JCC_REL8_BASE = 0x70
_JCC_REL32_BASE = 0x80

_JMP_REL8_SIZE = 2
_JMP_REL32_SIZE = 5
_JCC_REL8_SIZE = 2
_JCC_REL32_SIZE = 6


class Condition(enum.IntEnum):
    """x86 condition codes, valued by their ``tttn`` encoding nibble.

    Aliases (``Z`` for ``E``, ``C`` for ``B``, ...) are real enum aliases, so
    iterating ``Condition`` yields the sixteen canonical predicates exactly once.
    """

    O = 0x0  # noqa: E741 - x86 mnemonic, not the digit
    NO = 0x1
    B = 0x2
    AE = 0x3
    E = 0x4
    NE = 0x5
    BE = 0x6
    A = 0x7
    S = 0x8
    NS = 0x9
    P = 0xA
    NP = 0xB
    L = 0xC
    GE = 0xD
    LE = 0xE
    G = 0xF

    # Aliases; these do not appear when iterating the enum.
    C = 0x2
    NAE = 0x2
    NB = 0x3
    NC = 0x3
    Z = 0x4
    NZ = 0x5
    NA = 0x6
    NBE = 0x7
    PE = 0xA
    PO = 0xB
    NGE = 0xC
    NL = 0xD
    NG = 0xE
    NLE = 0xF

    def inverted(self) -> Condition:
        """Return the predicate that is true exactly when this one is false.

        The ``tttn`` encoding pairs each condition with its negation in adjacent
        slots, so inversion is a single XOR and is always exact -- there is no
        condition whose negation is unrepresentable.
        """
        return Condition(self.value ^ 1)

    @property
    def mnemonic(self) -> str:
        return _CONDITION_MNEMONICS[self.value]


_CONDITION_MNEMONICS = {
    0x0: "jo",
    0x1: "jno",
    0x2: "jb",
    0x3: "jae",
    0x4: "je",
    0x5: "jne",
    0x6: "jbe",
    0x7: "ja",
    0x8: "js",
    0x9: "jns",
    0xA: "jp",
    0xB: "jnp",
    0xC: "jl",
    0xD: "jge",
    0xE: "jle",
    0xF: "jg",
}


class AbstentionReason(str, enum.Enum):
    """Stable abstention reasons shared with the native patch plan vocabulary.

    These names are contract, not diagnostics: they are the same strings section
    16 of the report lists as the plan's stable enum values, so a receipt emitted
    here can be compared against a plan-level abstention without translation.
    """

    UNREPRESENTABLE_BRANCH = "UNREPRESENTABLE_BRANCH"
    UNSUPPORTED_ARCHITECTURE = "UNSUPPORTED_ARCHITECTURE"
    INVALID_REGION = "INVALID_REGION"
    INSUFFICIENT_SPACE = "INSUFFICIENT_SPACE"


@dataclass(frozen=True, slots=True)
class EncodedInstruction:
    """One encoded instruction and the shape the encoder claims it emitted.

    ``displacement`` is the value actually encoded into the operand, relative to
    the end of this instruction. It is retained so a preflight can re-derive the
    target independently rather than trusting ``target``.
    """

    ea: int
    data: bytes
    mnemonic: str
    target: int | None = None
    displacement: int | None = None

    @property
    def end_ea(self) -> int:
        return self.ea + len(self.data)


@dataclass(frozen=True, slots=True)
class EncodeOutcome:
    """Either an encoded instruction or a reason the encoder abstained."""

    instruction: EncodedInstruction | None = None
    reason: AbstentionReason | None = None

    @property
    def ok(self) -> bool:
        return self.instruction is not None


@dataclass(frozen=True, slots=True)
class EncodedSequence:
    """A contiguous run of encoded instructions starting at ``ea``."""

    ea: int
    instructions: tuple[EncodedInstruction, ...]

    @property
    def data(self) -> bytes:
        return b"".join(instruction.data for instruction in self.instructions)

    @property
    def size(self) -> int:
        return sum(len(instruction.data) for instruction in self.instructions)

    @property
    def end_ea(self) -> int:
        return self.ea + self.size


@dataclass(frozen=True, slots=True)
class SequenceOutcome:
    """Either an encoded run of instructions or a reason the encoder abstained."""

    sequence: EncodedSequence | None = None
    reason: AbstentionReason | None = None

    @property
    def ok(self) -> bool:
        return self.sequence is not None


def _abstain(reason: AbstentionReason) -> EncodeOutcome:
    return EncodeOutcome(instruction=None, reason=reason)


def _abstain_sequence(reason: AbstentionReason) -> SequenceOutcome:
    return SequenceOutcome(sequence=None, reason=reason)


def _addresses_are_valid(bitness: int, *addresses: int) -> bool:
    limit = 1 << bitness
    return all(0 <= address < limit for address in addresses)


def _fits_signed(value: int, bits: int) -> bool:
    bound = 1 << (bits - 1)
    return -bound <= value < bound


def _encode_relative(
    ea: int,
    target: int,
    bitness: int,
    width: int | None,
    mnemonic: str,
    forms: dict[int, tuple[int, Callable[[int], bytes]]],
) -> EncodeOutcome:
    """Shared width selection and displacement arithmetic for relative branches.

    ``forms`` maps a displacement width to the total instruction size and a
    builder for that form. Size is carried per form rather than derived because
    ``jmp rel32`` is five bytes while ``jcc rel32`` is six, and getting that
    wrong shifts every displacement by one.
    """
    if bitness not in _SUPPORTED_BITNESS:
        return _abstain(AbstentionReason.UNSUPPORTED_ARCHITECTURE)
    if not _addresses_are_valid(bitness, ea, target):
        return _abstain(AbstentionReason.UNSUPPORTED_ARCHITECTURE)
    if width is not None and width not in forms:
        return _abstain(AbstentionReason.UNREPRESENTABLE_BRANCH)

    candidate_widths = tuple(sorted(forms)) if width is None else (width,)
    for candidate in candidate_widths:
        size, build = forms[candidate]
        displacement = target - (ea + size)
        if not _fits_signed(displacement, candidate):
            continue
        return EncodeOutcome(
            instruction=EncodedInstruction(
                ea=ea,
                data=build(displacement),
                mnemonic=mnemonic,
                target=target,
                displacement=displacement,
            )
        )

    return _abstain(AbstentionReason.UNREPRESENTABLE_BRANCH)


def encode_jmp(
    ea: int,
    target: int,
    *,
    width: int | None = None,
    bitness: int = 64,
) -> EncodeOutcome:
    """Encode an unconditional near jump at ``ea`` to ``target``.

    ``width`` selects the displacement width in bits. ``None`` picks the
    shortest encoding that reaches, which is what a padded region wants; an
    explicit 8 or 32 is honoured exactly, because a caller replacing a
    fixed-size region needs a fixed-size branch and a silent promotion from
    rel8 to rel32 would overrun the region it measured.
    """
    return _encode_relative(
        ea=ea,
        target=target,
        bitness=bitness,
        width=width,
        mnemonic="jmp",
        forms={
            8: (
                _JMP_REL8_SIZE,
                lambda disp: (
                    bytes([_JMP_REL8_OPCODE]) + disp.to_bytes(1, "little", signed=True)
                ),
            ),
            32: (
                _JMP_REL32_SIZE,
                lambda disp: (
                    bytes([_JMP_REL32_OPCODE]) + disp.to_bytes(4, "little", signed=True)
                ),
            ),
        },
    )


def encode_nop_padding(ea: int, length: int) -> SequenceOutcome:
    """Encode exactly ``length`` bytes of NOP padding starting at ``ea``.

    Emits the longest recommended form that still fits, repeatedly, so a large
    region costs a handful of instruction heads rather than one per byte. The
    result always measures exactly ``length``; a caller sizing a fixed region
    can rely on that without re-measuring.
    """
    if length < 0:
        return _abstain_sequence(AbstentionReason.INVALID_REGION)

    instructions: list[EncodedInstruction] = []
    cursor = ea
    remaining = length
    while remaining > 0:
        chunk = min(remaining, _MAX_NOP_FORM)
        data = _NOP_FORMS[chunk]
        instructions.append(EncodedInstruction(ea=cursor, data=data, mnemonic="nop"))
        cursor += chunk
        remaining -= chunk

    return SequenceOutcome(
        sequence=EncodedSequence(ea=ea, instructions=tuple(instructions))
    )


def encode_jcc(
    ea: int,
    target: int,
    *,
    condition: Condition,
    width: int | None = None,
    bitness: int = 64,
) -> EncodeOutcome:
    """Encode a conditional near jump at ``ea`` to ``target``.

    The caller supplies the predicate that must hold for the branch to be
    taken. Building a jump-over stencil means passing ``condition.inverted()``;
    the encoder does not infer intent from the surrounding region.
    """
    return _encode_relative(
        ea=ea,
        target=target,
        bitness=bitness,
        width=width,
        mnemonic=condition.mnemonic,
        forms={
            8: (
                _JCC_REL8_SIZE,
                lambda disp: (
                    bytes([_JCC_REL8_BASE | int(condition)])
                    + disp.to_bytes(1, "little", signed=True)
                ),
            ),
            32: (
                _JCC_REL32_SIZE,
                lambda disp: (
                    bytes([0x0F, _JCC_REL32_BASE | int(condition)])
                    + disp.to_bytes(4, "little", signed=True)
                ),
            ),
        },
    )


def _pad_to_region(
    start_ea: int,
    region_size: int,
    branches: tuple[EncodedInstruction, ...],
) -> SequenceOutcome:
    """Append NOP padding so ``branches`` measure exactly ``region_size``."""
    used = sum(len(branch.data) for branch in branches)
    padding = encode_nop_padding(ea=start_ea + used, length=region_size - used)
    if not padding.ok:
        return padding
    return SequenceOutcome(
        sequence=EncodedSequence(
            ea=start_ea,
            instructions=branches + padding.sequence.instructions,
        )
    )


def _region_size(start_ea: int, end_ea: int) -> int | None:
    if end_ea <= start_ea:
        return None
    return end_ea - start_ea


def plan_direct_jump_region(
    start_ea: int,
    end_ea: int,
    target: int,
    *,
    bitness: int = 64,
) -> SequenceOutcome:
    """Lower an owned terminator region ``[start_ea, end_ea)`` to one jump.

    The branch is placed at ``start_ea`` and the remainder of the region is
    padded, so the emitted image always measures exactly the region. A short
    write would leave a live tail of the original terminator decoding after the
    new branch.

    This function is pure. It does not verify that ``target`` is an instruction
    head, that the region is owned, or that nothing branches into its interior;
    those are database facts and belong to preflight.
    """
    size = _region_size(start_ea, end_ea)
    if size is None:
        return _abstain_sequence(AbstentionReason.INVALID_REGION)

    encoded_any = False
    for width in (8, 32):
        outcome = encode_jmp(start_ea, target, width=width, bitness=bitness)
        if not outcome.ok:
            continue
        encoded_any = True
        if len(outcome.instruction.data) > size:
            continue
        return _pad_to_region(start_ea, size, (outcome.instruction,))

    # An encodable branch that will not fit is a region problem; a branch that
    # no width can express is a reach problem. The caller acts differently on
    # each, so they must not collapse into one reason.
    return _abstain_sequence(
        AbstentionReason.INSUFFICIENT_SPACE
        if encoded_any
        else AbstentionReason.UNREPRESENTABLE_BRANCH
    )


def plan_conditional_region(
    start_ea: int,
    end_ea: int,
    *,
    condition: Condition,
    true_target: int,
    false_target: int,
    bitness: int = 64,
) -> SequenceOutcome:
    """Lower an owned region to a conditional control-transfer image.

    When ``false_target`` is the region end, preserve native fallthrough and
    emit one Jcc plus padding. Otherwise emit ``jcc <true>; jmp <false>; pad``;
    widths are searched shortest-first over both branches together because the
    second branch's displacement depends on the first branch's width.

    ``condition`` is the predicate under which ``true_target`` is taken. A
    caller wanting the jump-over shape passes ``condition.inverted()``
    and swaps the targets; this function does not infer that intent.
    """
    size = _region_size(start_ea, end_ea)
    if size is None:
        return _abstain_sequence(AbstentionReason.INVALID_REGION)

    # The common native shape already owns its false arm as physical
    # fallthrough. Retargeting only the taken arm needs one Jcc, not the more
    # general Jcc+Jmp stencil. Keeping this form is essential for ordinary
    # two- and six-byte x86 conditional terminators.
    if false_target == end_ea:
        encoded_any = False
        for conditional_width in (8, 32):
            conditional = encode_jcc(
                start_ea,
                true_target,
                condition=condition,
                width=conditional_width,
                bitness=bitness,
            )
            if not conditional.ok:
                continue
            encoded_any = True
            if len(conditional.instruction.data) > size:
                continue
            return _pad_to_region(start_ea, size, (conditional.instruction,))
        return _abstain_sequence(
            AbstentionReason.INSUFFICIENT_SPACE
            if encoded_any
            else AbstentionReason.UNREPRESENTABLE_BRANCH
        )

    encoded_any = False
    for conditional_width in (8, 32):
        conditional = encode_jcc(
            start_ea,
            true_target,
            condition=condition,
            width=conditional_width,
            bitness=bitness,
        )
        if not conditional.ok:
            continue
        fallthrough_ea = start_ea + len(conditional.instruction.data)
        for direct_width in (8, 32):
            direct = encode_jmp(
                fallthrough_ea,
                false_target,
                width=direct_width,
                bitness=bitness,
            )
            if not direct.ok:
                continue
            encoded_any = True
            total = len(conditional.instruction.data) + len(direct.instruction.data)
            if total > size:
                continue
            return _pad_to_region(
                start_ea,
                size,
                (conditional.instruction, direct.instruction),
            )

    return _abstain_sequence(
        AbstentionReason.INSUFFICIENT_SPACE
        if encoded_any
        else AbstentionReason.UNREPRESENTABLE_BRANCH
    )


# ---------------------------------------------------------------------------
# decode() -- independent decode of exactly what this module can emit.
#
# Not a general x86 decoder. Its only job is self-verification of bytes this
# encoder plausibly produced (NativeEncodingEvidence.independent_decode_hash),
# so it recognises exactly the jmp/jcc/NOP forms above and raises on anything
# else -- encountering an unrecognised form here means the caller handed it
# bytes that did not come from this encoder, which is a hard error, not an
# abstention.
# ---------------------------------------------------------------------------

_NOP_FORMS_BY_LENGTH = tuple(sorted(_NOP_FORMS.items(), key=lambda item: -item[0]))


def _decode_one(cursor: int, data: bytes, offset: int) -> EncodedInstruction:
    """Decode exactly one instruction from ``data`` at ``offset``.

    Raises ``ValueError`` when the bytes at ``offset`` are not a form this
    encoder emits.
    """
    remaining = len(data) - offset
    first = data[offset]

    if first == _JMP_REL8_OPCODE and remaining >= _JMP_REL8_SIZE:
        disp = int.from_bytes(data[offset + 1 : offset + 2], "little", signed=True)
        return EncodedInstruction(
            ea=cursor,
            data=bytes(data[offset : offset + _JMP_REL8_SIZE]),
            mnemonic="jmp",
            target=cursor + _JMP_REL8_SIZE + disp,
            displacement=disp,
        )
    if first == _JMP_REL32_OPCODE and remaining >= _JMP_REL32_SIZE:
        disp = int.from_bytes(data[offset + 1 : offset + 5], "little", signed=True)
        return EncodedInstruction(
            ea=cursor,
            data=bytes(data[offset : offset + _JMP_REL32_SIZE]),
            mnemonic="jmp",
            target=cursor + _JMP_REL32_SIZE + disp,
            displacement=disp,
        )
    if _JCC_REL8_BASE <= first < _JCC_REL8_BASE + 0x10 and remaining >= _JCC_REL8_SIZE:
        nibble = first - _JCC_REL8_BASE
        disp = int.from_bytes(data[offset + 1 : offset + 2], "little", signed=True)
        return EncodedInstruction(
            ea=cursor,
            data=bytes(data[offset : offset + _JCC_REL8_SIZE]),
            mnemonic=_CONDITION_MNEMONICS[nibble],
            target=cursor + _JCC_REL8_SIZE + disp,
            displacement=disp,
        )
    if (
        first == 0x0F
        and remaining >= _JCC_REL32_SIZE
        and _JCC_REL32_BASE <= data[offset + 1] < _JCC_REL32_BASE + 0x10
    ):
        nibble = data[offset + 1] - _JCC_REL32_BASE
        disp = int.from_bytes(data[offset + 2 : offset + 6], "little", signed=True)
        return EncodedInstruction(
            ea=cursor,
            data=bytes(data[offset : offset + _JCC_REL32_SIZE]),
            mnemonic=_CONDITION_MNEMONICS[nibble],
            target=cursor + _JCC_REL32_SIZE + disp,
            displacement=disp,
        )
    for length, form in _NOP_FORMS_BY_LENGTH:
        if remaining >= length and bytes(data[offset : offset + length]) == form:
            return EncodedInstruction(
                ea=cursor, data=bytes(data[offset : offset + length]), mnemonic="nop"
            )

    raise ValueError(
        f"cannot decode byte {first:#x} at {cursor:#x}: not a jmp/jcc/nop form "
        "this encoder emits"
    )


def decode(
    ea: int, data: bytes, *, bitness: int = 64
) -> NativeInstructionSequenceShape:
    """Independently decode ``data`` at ``ea`` into a portable shape.

    Implements ``d810.capabilities.native_patch.EncodingProvider.decode``.
    ``bitness`` is accepted for Protocol conformance but unused: every form
    this encoder emits decodes identically regardless of address width.
    """
    del bitness
    heads: list[NativeInstructionHead] = []
    cursor = ea
    offset = 0
    while offset < len(data):
        instruction = _decode_one(cursor, data, offset)
        successors = (
            (instruction.target,)
            if instruction.target is not None
            else (cursor + len(instruction.data),)
        )
        heads.append(
            NativeInstructionHead(
                ea=cursor,
                length=len(instruction.data),
                mnemonic=instruction.mnemonic,
                operand_shapes=("rel",) if instruction.target is not None else (),
                successors=successors,
            )
        )
        cursor += len(instruction.data)
        offset += len(instruction.data)
    return NativeInstructionSequenceShape(heads=tuple(heads))


# ---------------------------------------------------------------------------
# MinimalX86BranchEncoder -- the concrete EncodingProvider this module was
# always going to need. Declared here rather than moved: the Task 5
# layer-correction block requires `transforms.native_patch_lowering` to
# depend on the `EncodingProvider` Protocol in `d810.capabilities.native_patch`
# instead of importing this module upward; this class is what the composition
# root injects to satisfy that Protocol at runtime.
# ---------------------------------------------------------------------------


def _sequence_outcome_to_result(
    outcome: SequenceOutcome, ea: int
) -> NativeEncodingResult:
    if not outcome.ok:
        return NativeEncodingResult(ok=False, reason=outcome.reason.value)
    return NativeEncodingResult(
        ok=True,
        replacement_bytes=outcome.sequence.data,
        expected_after_shape=decode(ea, outcome.sequence.data),
    )


class MinimalX86BranchEncoder:
    """``EncodingProvider`` implementation over the module-level planners.

    ``condition`` strings are looked up by :class:`Condition` member/alias
    name (``"E"``, ``"NE"``, ``"AE"``, ...) -- exactly ``Condition.__members__``
    -- so any name or documented x86 alias this module already recognises is
    accepted; anything else abstains with ``UNREPRESENTABLE_BRANCH`` rather
    than raising, matching this module's fail-closed contract.
    """

    def encode_direct_jump(
        self, start_ea: int, end_ea: int, target_ea: int, *, bitness: int
    ) -> NativeEncodingResult:
        outcome = plan_direct_jump_region(start_ea, end_ea, target_ea, bitness=bitness)
        return _sequence_outcome_to_result(outcome, start_ea)

    def encode_nop_fill(
        self, start_ea: int, end_ea: int, *, bitness: int
    ) -> NativeEncodingResult:
        # An empty region abstains rather than succeeding with zero bytes: a
        # caller that computed a degenerate region has a bug, and returning a
        # vacuously-ok result would let it write nothing and record a receipt
        # claiming the edge was erased.
        if end_ea <= start_ea:
            return NativeEncodingResult(
                ok=False, reason=AbstentionReason.INVALID_REGION.value
            )
        outcome = encode_nop_padding(start_ea, end_ea - start_ea)
        return _sequence_outcome_to_result(outcome, start_ea)

    def encode_conditional(
        self,
        start_ea: int,
        end_ea: int,
        *,
        condition: str,
        true_target_ea: int,
        false_target_ea: int,
        bitness: int,
    ) -> NativeEncodingResult:
        try:
            resolved = Condition[condition]
        except KeyError:
            return NativeEncodingResult(
                ok=False, reason=AbstentionReason.UNREPRESENTABLE_BRANCH.value
            )
        outcome = plan_conditional_region(
            start_ea,
            end_ea,
            condition=resolved,
            true_target=true_target_ea,
            false_target=false_target_ea,
            bitness=bitness,
        )
        return _sequence_outcome_to_result(outcome, start_ea)

    def decode(
        self, ea: int, data: bytes, *, bitness: int = 64
    ) -> NativeInstructionSequenceShape:
        return decode(ea, data, bitness=bitness)
