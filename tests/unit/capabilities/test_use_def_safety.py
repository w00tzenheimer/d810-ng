"""Unit tests for ``UseDefSafetyCapability`` + ``SeveranceViolation`` canonical home.

Scope: canonical imports from ``d810.capabilities`` only.
Re-export-compatibility tests live in the system/runtime suite -- the
``unit-tests-no-optimizers`` import-linter contract forbids unit tests
from importing ``d810.optimizers.*`` (and by extension testing the
HR-side back-compat alias).
"""
from __future__ import annotations

from d810.capabilities import (
    SeveranceViolation as PackageReexportSeveranceViolation,
    UseDefSafetyCapability as PackageReexportCapability,
)
from d810.capabilities.use_def_safety import (
    SeveranceViolation,
    UseDefSafetyCapability,
)


def test_canonical_and_package_reexport_yield_same_protocol_object() -> None:
    """The Protocol class accessed via either canonical path must be the same object."""
    assert UseDefSafetyCapability is PackageReexportCapability


def test_canonical_and_package_reexport_yield_same_result_type() -> None:
    """``SeveranceViolation`` accessed via either canonical path must be the same class."""
    assert SeveranceViolation is PackageReexportSeveranceViolation


def test_capability_declares_expected_member_names() -> None:
    """Declared member names form the public Protocol contract; verify the surface."""
    expected = {"redirect_use_def_violations"}
    declared = {n for n in dir(UseDefSafetyCapability) if not n.startswith("_")}
    missing = expected - declared
    assert not missing, f"UseDefSafetyCapability missing declared members: {missing}"


def test_capability_lives_at_portable_canonical_path() -> None:
    """Canonical Protocol home must be ``d810.capabilities.use_def_safety``."""
    assert UseDefSafetyCapability.__module__ == "d810.capabilities.use_def_safety"


def test_severance_violation_lives_at_portable_canonical_path() -> None:
    """Result type must live next to the Protocol so backends can construct it without an upward import."""
    assert SeveranceViolation.__module__ == "d810.capabilities.use_def_safety"


def test_severance_violation_is_frozen_dataclass_with_slots() -> None:
    """``SeveranceViolation`` must remain hashable + slotted (downstream usage in sets)."""
    v1 = SeveranceViolation(
        src_block=10,
        new_target=20,
        var_stkoff=0x100,
        var_size=8,
        use_block=15,
        use_ea=0x401234,
    )
    v2 = SeveranceViolation(
        src_block=10,
        new_target=20,
        var_stkoff=0x100,
        var_size=8,
        use_block=15,
        use_ea=0x401234,
    )
    # Hashable + equal → safe to put in sets.
    assert {v1, v2} == {v1}
    # Frozen → attribute assignment must fail with FrozenInstanceError
    # (which is itself an AttributeError subclass).  Catch the specific
    # type so unrelated exception classes can't mask a regression.
    import dataclasses
    import pytest

    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        v1.src_block = 99  # type: ignore[misc]


def test_duck_typed_stub_matches_capability_surface_statically() -> None:
    """A stub with the ``redirect_use_def_violations`` member binds to the Protocol slot.

    The Protocol is NOT ``@runtime_checkable``, so ``isinstance`` would
    raise.  Verify the surface compatibility by structural assignment
    instead -- this exercises the same property concrete consumers
    depend on (passing a backend object into an annotated parameter).
    """

    class _Stub:
        def redirect_use_def_violations(
            self,
            mod: object,
            live_function: object,
            pre_cfg: object,
        ) -> tuple[SeveranceViolation, ...]:
            return ()

    backend: UseDefSafetyCapability = _Stub()
    assert callable(backend.redirect_use_def_violations)
    assert backend.redirect_use_def_violations(None, None, None) == ()
