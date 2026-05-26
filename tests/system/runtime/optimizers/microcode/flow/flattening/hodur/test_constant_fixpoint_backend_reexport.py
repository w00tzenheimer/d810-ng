"""Verify ``ConstantFixpointBackend`` back-compat re-export after slice 3.

The canonical home is ``d810.capabilities.constant_fixpoint`` per the
llvm-lisa-restructure plan.  The 7 production consumers under
``hodur/`` continue to import from the old path; that path must yield
the same Protocol object as the canonical home.

This test lives under ``tests/system/runtime/`` (not ``tests/unit/``)
because verifying the re-export REQUIRES importing
``d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend``,
which the ``unit-tests-no-optimizers`` import-linter contract forbids.
"""
from __future__ import annotations

from d810.capabilities.constant_fixpoint import (
    ConstantFixpointBackend as CanonicalConstantFixpointBackend,
)
from d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend import (
    ConstantFixpointBackend as OldShimConstantFixpointBackend,
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND,
    HodurConstantFixpointBackend,
)


def test_old_shim_reexports_canonical_protocol_object() -> None:
    """The old hodur import path must yield the same Protocol object as the canonical home."""
    assert OldShimConstantFixpointBackend is CanonicalConstantFixpointBackend


def test_default_hodur_backend_is_a_concrete_instance() -> None:
    """The module-level ``DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND`` constant remains a real instance."""
    assert isinstance(
        DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND, HodurConstantFixpointBackend
    )


def test_concrete_backend_satisfies_protocol_surface() -> None:
    """``HodurConstantFixpointBackend`` exposes the ``compute`` method the Protocol requires."""
    backend: CanonicalConstantFixpointBackend = HodurConstantFixpointBackend()
    assert callable(backend.compute)
