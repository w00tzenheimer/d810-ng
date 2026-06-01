"""Unit tests for ``UnflatteningStrategy`` canonical home.

Scope: canonical import from ``d810.capabilities.unflattening_strategy``
plus the ``d810.families.state_machine_cff`` back-compat re-exports.
Re-export-compatibility tests live in the system/runtime suite under
``tests/system/runtime/optimizers/...`` because the
``unit-tests-no-optimizers`` import-linter contract forbids unit tests
from importing ``d810.optimizers.*``.
"""
from __future__ import annotations

from d810.capabilities.unflattening_strategy import UnflatteningStrategy
from d810.families.state_machine_cff import (
    UnflatteningStrategy as PackageReexport,
)
from d810.families.state_machine_cff.protocols import (
    UnflatteningStrategy as ModuleReexport,
)


class _StubStrategy:
    """Minimal duck-typed strategy used to exercise structural Protocol checks."""

    @property
    def name(self) -> str:
        return "stub"

    @property
    def family(self) -> str:
        return "test-fake"

    def is_applicable(self, snapshot: object) -> bool:
        return False

    def plan(self, snapshot: object) -> object | None:
        return None


def test_canonical_and_package_reexport_yield_same_protocol_object() -> None:
    """The Protocol class accessed via either canonical path must be the same object."""
    assert UnflatteningStrategy is PackageReexport
    assert UnflatteningStrategy is ModuleReexport


def test_unflattening_strategy_is_runtime_checkable() -> None:
    """A duck-typed stub with the four required members satisfies the Protocol at runtime."""
    assert isinstance(_StubStrategy(), UnflatteningStrategy)


def test_unflattening_strategy_runtime_check_rejects_missing_members() -> None:
    """A stub missing required attributes/methods must NOT satisfy the Protocol."""

    class _PartialStrategy:
        @property
        def name(self) -> str:
            return "partial"

        @property
        def family(self) -> str:
            return "partial"

        # Intentionally missing ``is_applicable`` and ``plan``.

    assert not isinstance(_PartialStrategy(), UnflatteningStrategy)


def test_protocol_declares_expected_member_names() -> None:
    """Declared member names form the public Protocol contract; verify the surface."""
    expected = {"name", "family", "is_applicable", "plan"}
    declared = {
        name for name in dir(UnflatteningStrategy) if not name.startswith("_")
    }
    missing = expected - declared
    assert not missing, f"UnflatteningStrategy missing declared members: {missing}"


def test_protocol_lives_at_portable_canonical_path() -> None:
    """Canonical Protocol home must be ``d810.capabilities.unflattening_strategy``.

    The Protocol is a pure INTERFACE (imports only ``d810.core.typing``)
    so its lowest legal home is the ``d810.capabilities`` layer.  Guards
    against accidental moves to a HIGH layer that would violate the
    target-layer-taxonomy import-linter contract.
    """
    assert UnflatteningStrategy.__module__ == (
        "d810.capabilities.unflattening_strategy"
    )
