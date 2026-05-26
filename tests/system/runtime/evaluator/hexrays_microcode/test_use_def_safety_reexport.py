"""Verify ``UseDefSafetyCapability`` back-compat re-export after slice 5.

The canonical home is ``d810.capabilities.use_def_safety`` per the
llvm-lisa-restructure plan.  The original definition site at
``d810.evaluator.hexrays_microcode.use_def_dominance`` keeps the
symbols importable for back-compat:

  * ``UseDefSafetyCapability`` (new name) -- direct re-export
  * ``UseDefSafetyBackend`` (legacy name) -- alias of the above
  * ``SeveranceViolation`` (result type) -- re-export of canonical
  * ``HexRaysUseDefSafetyBackend`` (concrete impl) -- stays where it is

The 2 production consumers
(``hodur/strategies/handler_chain_composer.py``,
``hodur/strategies/linearized_flow_graph.py``) currently import the
legacy name; this test asserts that path continues to yield the same
Protocol object as the canonical home.

Lives under ``tests/system/runtime/`` (not ``tests/unit/``) because
the back-compat shim imports live ``ida_hexrays``; unit tests cannot
import the HR side per the project's pytest constraints.
"""
from __future__ import annotations

from d810.capabilities.use_def_safety import (
    SeveranceViolation as CanonicalSeveranceViolation,
    UseDefSafetyCapability as CanonicalUseDefSafetyCapability,
)
from d810.evaluator.hexrays_microcode.use_def_dominance import (
    HexRaysUseDefSafetyBackend,
    SeveranceViolation as OldShimSeveranceViolation,
    UseDefSafetyBackend as OldShimUseDefSafetyBackend,
    UseDefSafetyCapability as OldShimUseDefSafetyCapability,
)


def test_old_shim_reexports_canonical_capability_object() -> None:
    """``d810.evaluator...use_def_dominance.UseDefSafetyCapability`` and the canonical
    home must yield the same Protocol object."""
    assert OldShimUseDefSafetyCapability is CanonicalUseDefSafetyCapability


def test_old_shim_legacy_alias_is_canonical_capability() -> None:
    """Legacy name ``UseDefSafetyBackend`` is preserved as an alias of
    ``UseDefSafetyCapability``; the 2 existing Hodur consumers depend on this."""
    assert OldShimUseDefSafetyBackend is CanonicalUseDefSafetyCapability


def test_old_shim_reexports_canonical_severance_violation() -> None:
    """``SeveranceViolation`` accessed via the old shim and the canonical home must
    be the same dataclass."""
    assert OldShimSeveranceViolation is CanonicalSeveranceViolation


def test_concrete_backend_satisfies_capability_surface() -> None:
    """``HexRaysUseDefSafetyBackend`` exposes the ``redirect_use_def_violations``
    method the capability requires."""
    backend: CanonicalUseDefSafetyCapability = HexRaysUseDefSafetyBackend()
    assert callable(backend.redirect_use_def_violations)
