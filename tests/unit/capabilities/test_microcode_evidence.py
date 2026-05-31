"""MicrocodeEvidenceProvider seam: registration, fail-loud, accessor round-trip."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.capabilities import providers as P


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
    )
    P.register_microcode_evidence(prov)
    got = P.get_microcode_evidence()
    assert got is prov
    # accessors are byte-identical to the inlined mba.entry_ea / mba.maturity reads,
    # working on a live mba OR a FlowGraph projection (here: a SimpleNamespace stand-in).
    fake = SimpleNamespace(entry_ea=0x1800134A5, maturity=8)
    assert got.get_function_entry_ea(fake) == 0x1800134A5
    assert got.get_mba_maturity(fake) == 8


def test_reset_clears_microcode_evidence():
    P.register_microcode_evidence(
        P.MicrocodeEvidenceProvider(lambda m: 0, lambda m: 0)
    )
    P.reset_providers_for_tests()
    with pytest.raises(LookupError):
        P.get_microcode_evidence()
