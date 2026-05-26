"""Verify ``HodurProfileGateBackend`` back-compat re-export after slice 4b.

The canonical home is ``d810.capabilities.profile_gate`` per the
llvm-lisa-restructure plan.  The original definition site at
``d810.optimizers.microcode.flow.flattening.hodur.profile_gate`` keeps
the symbol importable for back-compat (the Protocol is the type
annotation on the in-file ``DEFAULT_HODUR_PROFILE_GATE`` constant and
on the ``accepts_exact_sub7ffd_glbopt1`` parameter default).

This test lives under ``tests/system/runtime/`` (not ``tests/unit/``)
because verifying the re-export REQUIRES importing
``d810.optimizers.microcode.flow.flattening.hodur.profile_gate``,
which the ``unit-tests-no-optimizers`` import-linter contract forbids.
"""
from __future__ import annotations

from d810.capabilities.profile_gate import (
    HodurProfileGateBackend as CanonicalHodurProfileGateBackend,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile_gate import (
    AttributeHodurProfileGate,
    DEFAULT_HODUR_PROFILE_GATE,
    HodurProfileGateBackend as OldShimHodurProfileGateBackend,
)


def test_old_shim_reexports_canonical_protocol_object() -> None:
    """The old hodur import path must yield the same Protocol object as the canonical home."""
    assert OldShimHodurProfileGateBackend is CanonicalHodurProfileGateBackend


def test_default_profile_gate_is_a_concrete_instance() -> None:
    """The module-level ``DEFAULT_HODUR_PROFILE_GATE`` constant remains a real instance."""
    assert isinstance(DEFAULT_HODUR_PROFILE_GATE, AttributeHodurProfileGate)


def test_concrete_gate_satisfies_protocol_surface() -> None:
    """``AttributeHodurProfileGate`` exposes the ``accepts_function`` method the Protocol requires."""
    gate: CanonicalHodurProfileGateBackend = AttributeHodurProfileGate()
    assert callable(gate.accepts_function)
