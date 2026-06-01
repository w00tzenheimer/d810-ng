"""Protocols for state-machine CFF family runtimes.

Both Protocols below use ``Any`` (not ``object``) for non-primitive
parameter / return types.  Python Protocol method parameters are
contravariant: a concrete ``def plan(self, snapshot: AnalysisSnapshot)``
would NOT satisfy a Protocol method ``def plan(self, snapshot: object)``
under a strict type-checker (LSP requires implementations to accept the
SUPER-type, not the SUB-type, of what the contract requires).  ``Any``
is the type-checker escape hatch: it is treated as both wider and
narrower than every type, so concrete implementations annotated against
rich engine types (``AnalysisSnapshot``, ``PlanFragment``, etc.) are
accepted as Protocol-compatible.

Runtime ``isinstance`` checks are structural under ``@runtime_checkable``
and unaffected by the parameter typing here.

These Protocols are pure INTERFACES (they import only ``d810.core.typing``)
so their canonical home is ``d810.capabilities`` -- the lowest legal layer
for interfaces.  Both the ``d810.families.state_machine_cff`` mid-layer and
the ``d810.optimizers.microcode.flow.flattening.engine`` high layer import
them DOWNWARD from here.  ``d810.families.state_machine_cff.protocols``
keeps a back-compat re-export.
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

__all__ = ["StateMachineFamilyRuntimeServices", "UnflatteningStrategy"]


class StateMachineFamilyRuntimeServices(Protocol):
    """Services supplied by a concrete state-machine family profile."""

    def runtime_policy(self, profile: Any) -> Any: ...

    def run_post_pipeline(
        self,
        profile: Any,
        family_result: Any,
    ) -> int: ...


@runtime_checkable
class UnflatteningStrategy(Protocol):
    """Interface that every concrete unflattening strategy must satisfy.

    The ``snapshot`` parameter and ``plan()`` return type are annotated
    as ``Any`` at this portable home to keep the ``d810.families`` layer
    free of upward dependencies on
    ``d810.optimizers.microcode.flow.flattening.engine``.  Concrete
    strategies in the engine layer continue to use the rich types
    ``AnalysisSnapshot`` / ``PlanFragment``; Protocol satisfaction is
    structural so the type-widening here does not affect runtime
    ``isinstance`` semantics.
    """

    @property
    def name(self) -> str:
        """Short, unique identifier for this strategy."""
        ...

    @property
    def family(self) -> str:
        """Strategy family label."""
        ...

    def is_applicable(self, snapshot: Any) -> bool:
        """Return True when this strategy can produce a non-empty plan."""
        ...

    def plan(self, snapshot: Any) -> Any:
        """Produce one or more ``PlanFragment`` instances (or None)."""
        ...
