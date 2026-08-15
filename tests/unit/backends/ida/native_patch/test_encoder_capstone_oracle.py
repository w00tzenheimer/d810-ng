"""Independent-decoder oracle for the branch encoder.

``test_encoder.py`` asserts byte values that were derived by hand from the Intel
manual. Those tests and the encoder can be wrong in the same direction, so they
prove self-consistency rather than correctness. This module re-derives the
answer with a disassembler that shares no code with the encoder and compares.

Section 14.2 of the report requires ``NativeEncodingEvidence`` to carry both an
emitted hash and an *independent decode* hash for exactly this reason. Capstone
is that independent decode at unit-test time; IDA's own decoder is the one that
matters at preflight, and the gateway checks it again there against live bytes.

**This module is supplementary, not the oracle of record.** Capstone is not a
declared d810 dependency -- it is absent from ``pyproject.toml`` and from
``docker/Dockerfile.test-runtime`` -- so this file runs only on hosts that happen
to have it and skips everywhere else, including the Docker test runtime. The
oracle that actually gates the encoder is
``test_encoder_unicorn_oracle.py``, which uses the declared ``emulation`` extra
and checks control flow by execution rather than by decode.

Keep both. They fail differently: this one catches an instruction that decodes to
the wrong shape, the unicorn oracle catches one that decodes fine but branches to
the wrong place.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.encoder import (
    Condition,
    encode_jcc,
    encode_jmp,
    encode_nop_padding,
    plan_conditional_region,
    plan_direct_jump_region,
)

capstone = pytest.importorskip("capstone")

pytestmark = pytest.mark.pure_python

BASE = 0x401000


@pytest.fixture(scope="module")
def disassembler():
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def _decode(disassembler, ea: int, data: bytes):
    return list(disassembler.disasm(data, ea))


# Deltas chosen to straddle both rel8 boundaries in both directions and to
# reach well into rel32 territory.
_JMP_DELTAS = [*range(-300, 301), -70_000, 70_000, -(1 << 20), 1 << 20]


@pytest.mark.parametrize("delta", _JMP_DELTAS)
def test_encoded_jmp_decodes_to_the_requested_target(disassembler, delta):
    target = BASE + delta
    outcome = encode_jmp(ea=BASE, target=target)
    assert outcome.ok

    decoded = _decode(disassembler, BASE, outcome.instruction.data)

    assert len(decoded) == 1
    assert decoded[0].mnemonic == "jmp"
    assert decoded[0].size == len(outcome.instruction.data)
    assert int(decoded[0].op_str, 16) == target


@pytest.mark.parametrize("condition", list(Condition))
@pytest.mark.parametrize("delta", [-200, -10, 4, 100, 5000])
def test_encoded_jcc_decodes_to_the_requested_target(disassembler, condition, delta):
    target = BASE + delta
    outcome = encode_jcc(ea=BASE, target=target, condition=condition)
    assert outcome.ok

    decoded = _decode(disassembler, BASE, outcome.instruction.data)

    assert len(decoded) == 1
    assert decoded[0].size == len(outcome.instruction.data)
    assert int(decoded[0].op_str, 16) == target
    assert decoded[0].mnemonic == outcome.instruction.mnemonic


@pytest.mark.parametrize("length", list(range(0, 65)))
def test_nop_padding_decodes_as_nops_covering_the_whole_span(disassembler, length):
    outcome = encode_nop_padding(ea=BASE, length=length)
    assert outcome.ok

    decoded = _decode(disassembler, BASE, outcome.sequence.data)

    assert sum(insn.size for insn in decoded) == length
    assert all("nop" in insn.mnemonic for insn in decoded)
    # The encoder's own instruction count must match what a decoder sees, or
    # the post-patch item shape a preflight predicts will be wrong.
    assert len(decoded) == len(outcome.sequence.instructions)


@pytest.mark.parametrize("size", list(range(2, 40)))
@pytest.mark.parametrize("delta", [-5000, -50, 8, 60, 5000])
def test_direct_jump_region_decodes_and_covers_the_region(disassembler, size, delta):
    outcome = plan_direct_jump_region(BASE, BASE + size, BASE + delta)
    if not outcome.ok:
        pytest.skip(f"planner abstained: {outcome.reason}")

    data = outcome.sequence.data
    decoded = _decode(disassembler, BASE, data)

    assert len(data) == size
    assert sum(insn.size for insn in decoded) == size
    assert decoded[0].mnemonic == "jmp"
    assert int(decoded[0].op_str, 16) == BASE + delta


@pytest.mark.parametrize("size", list(range(4, 40)))
@pytest.mark.parametrize(
    ("true_delta", "false_delta"),
    [(80, 120), (-40, 200), (5000, -5000), (3, 9)],
)
def test_conditional_region_decodes_and_covers_the_region(
    disassembler, size, true_delta, false_delta
):
    outcome = plan_conditional_region(
        BASE,
        BASE + size,
        condition=Condition.E,
        true_target=BASE + true_delta,
        false_target=BASE + false_delta,
    )
    if not outcome.ok:
        pytest.skip(f"planner abstained: {outcome.reason}")

    data = outcome.sequence.data
    decoded = _decode(disassembler, BASE, data)

    assert len(data) == size
    assert sum(insn.size for insn in decoded) == size
    assert decoded[0].mnemonic == "je"
    assert int(decoded[0].op_str, 16) == BASE + true_delta
    if false_delta == size:
        assert all(insn.mnemonic == "nop" for insn in decoded[1:])
    else:
        assert decoded[1].mnemonic == "jmp"
        assert int(decoded[1].op_str, 16) == BASE + false_delta
