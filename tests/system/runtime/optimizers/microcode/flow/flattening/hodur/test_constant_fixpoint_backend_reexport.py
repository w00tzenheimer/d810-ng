"""Verify ``ConstantFixpointCapability`` back-compat re-export.

The canonical home is ``d810.capabilities.constant_fixpoint`` per the
llvm-lisa-restructure plan.  The 7 production consumers under
``hodur/`` continue to import from the old path; that path must yield
the same Protocol object as the canonical home.

Slice 3 introduced the move under the original name
``ConstantFixpointBackend``.  Slice 6 renamed the canonical class to
``ConstantFixpointCapability`` (matching the ``*Capability`` discipline
established by slice 5's ``UseDefSafetyCapability``) and kept the old
name as a back-compat alias.  Both names must be importable from BOTH
the canonical home AND the HR-side shim.

This test lives under ``tests/system/runtime/`` (not ``tests/unit/``)
because verifying the re-export REQUIRES importing
``d810.passes.constant_fixpoint_backend``,
which the ``unit-tests-no-optimizers`` import-linter contract forbids.
"""
from __future__ import annotations

from d810.capabilities.constant_fixpoint import (
    ConstantFixpointBackend as CanonicalLegacyAlias,
    ConstantFixpointCapability as CanonicalCapability,
)
from d810.passes.constant_fixpoint_backend import (
    ConstantFixpointBackend as OldShimLegacyAlias,
    ConstantFixpointCapability as OldShimCapability,
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND,
    HodurConstantFixpointBackend,
)


def test_old_shim_reexports_canonical_capability_object() -> None:
    """The old hodur import path's canonical-name re-export must yield
    the same Protocol object as the canonical home."""
    assert OldShimCapability is CanonicalCapability


def test_old_shim_legacy_alias_is_canonical_capability() -> None:
    """The legacy ``ConstantFixpointBackend`` name (still exposed by both
    the canonical module and the HR-side shim) must be an alias of
    ``ConstantFixpointCapability``; the 7 existing Hodur consumers
    depend on this alias."""
    assert OldShimLegacyAlias is CanonicalCapability
    assert CanonicalLegacyAlias is CanonicalCapability


def test_default_hodur_backend_is_a_concrete_instance() -> None:
    """The module-level ``DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND``
    constant remains a real instance."""
    assert isinstance(
        DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND, HodurConstantFixpointBackend
    )


def test_concrete_backend_satisfies_capability_surface() -> None:
    """``HodurConstantFixpointBackend`` exposes the ``compute`` method
    the capability requires."""
    backend: CanonicalCapability = HodurConstantFixpointBackend()
    assert callable(backend.compute)
