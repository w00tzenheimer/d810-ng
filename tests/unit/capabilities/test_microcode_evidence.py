"""MicrocodeEvidenceProvider seam: registration, fail-loud, accessor round-trip."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.capabilities import providers as P

# Arbitrary distinct stand-in opcode/mop tags; only their round-trip identity
# through the provider is exercised here (no live IDA values needed).
_FAKE_CONSTANTS = P.MicrocodeConstants(
    m_mov=1,
    m_goto=2,
    m_nop=3,
    m_jnz=4,
    m_jz=5,
    m_jae=6,
    m_jb=7,
    m_ja=8,
    m_jbe=9,
    m_jg=10,
    m_jge=11,
    m_jl=12,
    m_jle=13,
    mop_z=14,
    mop_n=15,
    mop_S=16,
    mop_r=17,
    mop_b=18,
)


def setup_function():
    P.reset_providers_for_tests()


def teardown_function():
    P.reset_providers_for_tests()


def test_get_microcode_evidence_fail_loud_when_unregistered():
    with pytest.raises(LookupError):
        P.get_microcode_evidence()


def test_register_and_get_roundtrip():
    prov = P.MicrocodeEvidenceProvider(
        get_function_entry_ea=lambda mba: int(mba.entry_ea),
        get_mba_maturity=lambda mba: int(mba.maturity),
        get_block_count=lambda mba: mba.qty,
        block_adjacency=lambda mba, qty: {},
        is_glbopt1=lambda mba: int(mba.maturity) == 8,
        glbopt1_maturity=lambda mba: 8,
        mmat_zero=lambda mba: 0,
        microcode_constants=lambda mba=None: _FAKE_CONSTANTS,
    )
    P.register_microcode_evidence(prov)
    got = P.get_microcode_evidence()
    assert got is prov
    # accessors are byte-identical to the inlined mba.entry_ea / mba.maturity reads,
    # working on a live mba OR a FlowGraph projection (here: a SimpleNamespace stand-in).
    fake = SimpleNamespace(entry_ea=0x1800134A5, maturity=8, qty=3)
    assert got.get_function_entry_ea(fake) == 0x1800134A5
    assert got.get_mba_maturity(fake) == 8
    assert got.get_block_count(fake) == 3
    assert got.block_adjacency(fake, 3) == {}
    assert got.is_glbopt1(fake) is True
    assert got.glbopt1_maturity(fake) == 8
    assert got.mmat_zero(fake) == 0
    constants = got.microcode_constants(fake)
    assert constants is _FAKE_CONSTANTS
    assert constants.m_jnz == 4
    assert constants.mop_S == 16


def test_reset_clears_microcode_evidence():
    P.register_microcode_evidence(
        P.MicrocodeEvidenceProvider(
            lambda m: 0,
            lambda m: 0,
            lambda m: 0,
            lambda m, q: {},
            lambda m: False,
            lambda m: 8,
            lambda m: 0,
            lambda m=None: _FAKE_CONSTANTS,
        )
    )
    P.reset_providers_for_tests()
    with pytest.raises(LookupError):
        P.get_microcode_evidence()
