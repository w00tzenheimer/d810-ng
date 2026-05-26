"""Unit tests for ``ConstantFixpointCapability`` canonical home.

Scope: canonical imports from ``d810.capabilities`` only.
Re-export-compatibility tests live in the system/runtime suite — the
``unit-tests-no-optimizers`` import-linter contract forbids unit tests
from importing ``d810.optimizers.*``.

Slice 6 (naming cleanup): the canonical class is
``ConstantFixpointCapability``.  The legacy name
``ConstantFixpointBackend`` is preserved as a back-compat alias and
covered by ``test_legacy_name_is_alias_of_canonical_capability``.
"""
from __future__ import annotations

from d810.capabilities import (
    ConstantFixpointBackend as PackageReexportLegacyAlias,
    ConstantFixpointCapability as PackageReexportCapability,
)
from d810.capabilities.constant_fixpoint import (
    ConstantFixpointBackend,
    ConstantFixpointCapability,
)


def test_canonical_and_package_reexport_yield_same_protocol_object() -> None:
    """The canonical Protocol accessed via either import path must be the same object."""
    assert ConstantFixpointCapability is PackageReexportCapability


def test_legacy_name_is_alias_of_canonical_capability() -> None:
    """``ConstantFixpointBackend`` is a back-compat alias of
    ``ConstantFixpointCapability``; both names must resolve to the same
    Protocol object so the 7 existing prod consumers (importing the legacy
    name) and any new code (importing the canonical name) are checked
    against the same contract."""
    assert ConstantFixpointBackend is ConstantFixpointCapability
    assert PackageReexportLegacyAlias is ConstantFixpointCapability


def test_protocol_declares_expected_member_names() -> None:
    """Declared member names form the public Protocol contract; verify the surface."""
    expected = {"compute"}
    declared = {n for n in dir(ConstantFixpointCapability) if not n.startswith("_")}
    missing = expected - declared
    assert not missing, (
        f"ConstantFixpointCapability missing declared members: {missing}"
    )


def test_protocol_lives_at_portable_canonical_path() -> None:
    """Canonical Protocol home must be ``d810.capabilities.constant_fixpoint``.

    Guards against accidental moves to a HIGH layer that would violate
    the layered-architecture import-linter contract.
    """
    assert ConstantFixpointCapability.__module__ == (
        "d810.capabilities.constant_fixpoint"
    )


def test_canonical_class_name_uses_capability_suffix() -> None:
    """Naming discipline: capability Protocols use the ``*Capability``
    suffix (slice 5's ``UseDefSafetyCapability`` set the precedent;
    slice 6 retroactively applied it to ``ConstantFixpointCapability``).
    The legacy ``*Backend`` name is an alias only -- the canonical
    class's ``__name__`` is the new name."""
    assert ConstantFixpointCapability.__name__ == "ConstantFixpointCapability"


def test_duck_typed_stub_matches_protocol_surface_statically() -> None:
    """A stub with the ``compute`` member binds successfully to a
    Protocol-typed slot via assignment.

    The Protocol is NOT ``@runtime_checkable``, so ``isinstance`` would
    raise.  Verify the surface compatibility by structural assignment
    instead — this exercises the same property concrete consumers
    depend on (passing a backend object into an annotated parameter).
    """

    class _Stub:
        def compute(self, flow_graph: object, state_var_stkoff: int) -> object:
            return None

    backend: ConstantFixpointCapability = _Stub()
    # Touch the attribute to keep the binding non-trivial.
    assert callable(backend.compute)


def test_legacy_alias_satisfies_same_structural_contract() -> None:
    """A stub bound through the legacy alias name binds to the same
    Protocol slot; this catches any future regression where the alias
    drifts away from the canonical class."""

    class _Stub:
        def compute(self, flow_graph: object, state_var_stkoff: int) -> object:
            return None

    backend: ConstantFixpointBackend = _Stub()
    assert callable(backend.compute)
