"""RFLAGS-based opaque predicates (lpccp-20s3).

The obfuscator emits `pushfq; pop rax; test rax, rax; jz` -- a branch that is
decidable from the architecture but that Hex-Rays will not prove, so it survives
as a bogus loop in the output.
"""

from __future__ import annotations

import pytest

from d810.analyses.flag_predicates import (
    RFLAGS_RESERVED_SET_BIT,
    flags_compare_zero_is_taken,
    flags_register_can_be_zero,
)


def test_rflags_can_never_be_zero():
    assert flags_register_can_be_zero() is False


def test_the_reason_is_bit_one():
    """Bit 1 of EFLAGS/RFLAGS is reserved and always reads as 1 on x86/x86-64."""
    assert RFLAGS_RESERVED_SET_BIT == 1
    assert (1 << RFLAGS_RESERVED_SET_BIT) == 0b10


def test_equality_against_zero_is_never_taken():
    """jz/je against #0 can never fire, because RFLAGS != 0 always."""
    assert flags_compare_zero_is_taken(equal_test=True) is False


def test_inequality_against_zero_is_always_taken():
    """jnz/jne against #0 always fires. A jz-only rule misses 2 of 7 sites."""
    assert flags_compare_zero_is_taken(equal_test=False) is True


@pytest.mark.parametrize("equal_test", [True, False])
def test_outcome_is_total_and_boolean(equal_test):
    """Both directions are decided; neither returns 'unknown'."""
    assert isinstance(flags_compare_zero_is_taken(equal_test=equal_test), bool)


def test_the_two_directions_disagree():
    assert flags_compare_zero_is_taken(equal_test=True) is not (
        flags_compare_zero_is_taken(equal_test=False)
    )
