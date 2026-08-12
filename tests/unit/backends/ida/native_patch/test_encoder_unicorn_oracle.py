"""Execution oracle for the branch encoder.

The capstone oracle in ``test_encoder_capstone_oracle.py`` checks that emitted
bytes *disassemble* to the intended branch. Capstone is not installed in the
project's Docker test runtime, so that module skips in CI and its guarantee only
holds on a developer host.

Unicorn is present in the runtime, and it answers a stronger question: not "does
this decode to a jump to X" but "does executing this actually transfer control to
X". A wrong condition nibble, an off-by-one displacement, or a miscounted
instruction size all show up as control landing somewhere unintended.

The condition sweep is the part worth having. Each predicate is checked against
flag states where it must be taken *and* flag states where it must fall through,
with the expected answer derived from the x86 flag semantics independently of the
encoder's opcode table. That is what catches a transposed condition nibble --
which a decode-only oracle can miss when both the encoder and the test agree on
the same wrong mnemonic.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.encoder import (
    Condition,
    encode_jcc,
    encode_jmp,
    encode_nop_padding,
    plan_conditional_region,
)

unicorn = pytest.importorskip("unicorn")
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc  # noqa: E402
from unicorn.x86_const import UC_X86_REG_EFLAGS, UC_X86_REG_RIP  # noqa: E402

pytestmark = pytest.mark.pure_python

PAGE = 0x400000
PAGE_SIZE = 0x2000
# Keep every branch target inside the mapped page so a stray instruction fetch
# faults loudly instead of silently ending the emulation.
BASE = PAGE + 0x100

# x86 EFLAGS bit positions.
_CF, _PF, _ZF, _SF, _OF = 0x001, 0x004, 0x040, 0x080, 0x800
_RESERVED = 0x002  # bit 1 reads as 1 on real hardware


def _condition_holds(condition: Condition, flags: int) -> bool:
    """Ground truth for each predicate, derived from flags, not from opcodes."""
    cf, pf = bool(flags & _CF), bool(flags & _PF)
    zf, sf = bool(flags & _ZF), bool(flags & _SF)
    of = bool(flags & _OF)
    return {
        Condition.O: of,
        Condition.NO: not of,
        Condition.B: cf,
        Condition.AE: not cf,
        Condition.E: zf,
        Condition.NE: not zf,
        Condition.BE: cf or zf,
        Condition.A: not cf and not zf,
        Condition.S: sf,
        Condition.NS: not sf,
        Condition.P: pf,
        Condition.NP: not pf,
        Condition.L: sf != of,
        Condition.GE: sf == of,
        Condition.LE: zf or sf != of,
        Condition.G: not zf and sf == of,
    }[condition]


def _run(data: bytes, *, at: int = BASE, flags: int = _RESERVED, count: int = 1) -> int:
    """Execute ``count`` instructions at ``at`` and return the resulting RIP."""
    emulator = Uc(UC_ARCH_X86, UC_MODE_64)
    emulator.mem_map(PAGE, PAGE_SIZE)
    emulator.mem_write(at, data)
    emulator.reg_write(UC_X86_REG_EFLAGS, flags)
    emulator.emu_start(at, PAGE + PAGE_SIZE, 0, count)
    return emulator.reg_read(UC_X86_REG_RIP)


# Representative flag states covering every single-flag case and the
# signed-comparison combinations that pair SF against OF.
_FLAG_STATES = [
    _RESERVED,
    _RESERVED | _CF,
    _RESERVED | _ZF,
    _RESERVED | _SF,
    _RESERVED | _OF,
    _RESERVED | _PF,
    _RESERVED | _SF | _OF,
    _RESERVED | _ZF | _SF,
    _RESERVED | _CF | _ZF,
]


class TestJmpTransfersControl:
    @pytest.mark.parametrize("delta", [-0x40, -2, 0x10, 0x7F, 0x400])
    def test_unconditional_jump_lands_on_target(self, delta):
        target = BASE + delta
        outcome = encode_jmp(ea=BASE, target=target)
        assert outcome.ok

        assert _run(outcome.instruction.data) == target


class TestJccTransfersControl:
    """Every predicate, taken and not-taken, against independent flag truth."""

    @pytest.mark.parametrize("condition", list(Condition))
    @pytest.mark.parametrize("flags", _FLAG_STATES)
    def test_branch_is_taken_exactly_when_the_predicate_holds(self, condition, flags):
        target = BASE + 0x40
        outcome = encode_jcc(ea=BASE, target=target, condition=condition)
        assert outcome.ok

        landed = _run(outcome.instruction.data, flags=flags)

        if _condition_holds(condition, flags):
            assert landed == target
        else:
            assert landed == BASE + len(outcome.instruction.data)

    @pytest.mark.parametrize("condition", list(Condition))
    def test_inverted_predicate_branches_the_other_way(self, condition):
        target = BASE + 0x40
        flags = _RESERVED | _ZF | _CF | _SF
        straight = encode_jcc(ea=BASE, target=target, condition=condition)
        inverted = encode_jcc(ea=BASE, target=target, condition=condition.inverted())
        assert straight.ok and inverted.ok

        straight_taken = _run(straight.instruction.data, flags=flags) == target
        inverted_taken = _run(inverted.instruction.data, flags=flags) == target

        assert straight_taken != inverted_taken


class TestNopPaddingAdvancesExactly:
    @pytest.mark.parametrize("length", list(range(1, 33)))
    def test_padding_advances_rip_by_its_own_length(self, length):
        outcome = encode_nop_padding(ea=BASE, length=length)
        assert outcome.ok

        landed = _run(
            outcome.sequence.data,
            count=len(outcome.sequence.instructions),
        )

        assert landed == BASE + length


class TestConditionalRegionRoutesBothWays:
    """The Mode A stencil must route to the true target and the false target."""

    @pytest.mark.parametrize("condition", list(Condition))
    def test_stencil_routes_to_both_successors(self, condition):
        true_target = BASE + 0x80
        false_target = BASE + 0xC0
        outcome = plan_conditional_region(
            BASE,
            BASE + 0x20,
            condition=condition,
            true_target=true_target,
            false_target=false_target,
        )
        assert outcome.ok
        data = outcome.sequence.data

        # Derive the flag states from the predicate rather than hardcoding a
        # pair. A hardcoded "not taken" state is wrong for half the signed
        # predicates -- SF=0/OF=1 satisfies L, for instance.
        taken = next(f for f in _FLAG_STATES if _condition_holds(condition, f))
        not_taken = next(f for f in _FLAG_STATES if not _condition_holds(condition, f))

        assert _run(data, flags=taken) == true_target
        # Fall through the jcc, then execute the following jmp.
        assert _run(data, flags=not_taken, count=2) == false_target


class TestOracleCanFail:
    """A verification test that always passes verifies nothing.

    These deliberately corrupt correct output and require the oracle to notice,
    which is what makes the passing cases above meaningful.
    """

    def test_corrupted_displacement_is_detected(self):
        outcome = encode_jmp(ea=BASE, target=BASE + 0x20)
        assert outcome.ok
        corrupted = bytearray(outcome.instruction.data)
        corrupted[1] ^= 0x10

        assert _run(bytes(corrupted)) != BASE + 0x20

    def test_transposed_condition_nibble_is_detected(self):
        # je -> jne: same size, same displacement, opposite predicate.
        outcome = encode_jcc(ea=BASE, target=BASE + 0x20, condition=Condition.E)
        assert outcome.ok
        corrupted = bytearray(outcome.instruction.data)
        corrupted[0] ^= 0x01

        flags = _RESERVED | _ZF
        assert _run(outcome.instruction.data, flags=flags) == BASE + 0x20
        assert _run(bytes(corrupted), flags=flags) != BASE + 0x20
