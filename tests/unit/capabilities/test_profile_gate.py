"""Unit tests for ``HodurProfileGateBackend`` canonical home.

Scope: canonical imports from ``d810.capabilities`` only.
Re-export-compatibility tests live in the system/runtime suite -- the
``unit-tests-no-optimizers`` import-linter contract forbids unit tests
from importing ``d810.optimizers.*``.
"""
from __future__ import annotations

from d810.capabilities import HodurProfileGateBackend as PackageReexport
from d810.capabilities.profile_gate import HodurProfileGateBackend


def test_canonical_and_package_reexport_yield_same_protocol_object() -> None:
    """The Protocol class accessed via either canonical path must be the same object."""
    assert HodurProfileGateBackend is PackageReexport


def test_protocol_declares_expected_member_names() -> None:
    """Declared member names form the public Protocol contract; verify the surface."""
    expected = {"accepts_function"}
    declared = {n for n in dir(HodurProfileGateBackend) if not n.startswith("_")}
    missing = expected - declared
    assert not missing, f"HodurProfileGateBackend missing declared members: {missing}"


def test_protocol_lives_at_portable_canonical_path() -> None:
    """Canonical Protocol home must be ``d810.capabilities.profile_gate``.

    Guards against accidental moves to a HIGH layer that would violate
    the layered-architecture import-linter contract.
    """
    assert HodurProfileGateBackend.__module__ == "d810.capabilities.profile_gate"


def test_duck_typed_stub_matches_protocol_surface_statically() -> None:
    """A stub with the ``accepts_function`` member binds successfully to a
    Protocol-typed slot via assignment.

    The Protocol is NOT ``@runtime_checkable``, so ``isinstance`` would
    raise.  Verify the surface compatibility by structural assignment
    instead -- this exercises the same property concrete consumers
    depend on (passing a backend object into an annotated parameter).
    """

    class _Stub:
        def accepts_function(
            self,
            live_function: object,
            *,
            expected_entry_ea: int,
            required_maturity: str,
        ) -> bool:
            return False

    backend: HodurProfileGateBackend = _Stub()
    assert callable(backend.accepts_function)
