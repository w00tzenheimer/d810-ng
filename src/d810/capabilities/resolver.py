"""Typed capability resolver threaded into pipeline passes.

This is the north-star ``capabilities`` object: passes call
``capabilities.optional(ValRangeCapability)`` /
``capabilities.require(UseDefSafetyCapability)`` to obtain a backend-provided
capability instance keyed by its Protocol type.  The pipeline shell builds the
set from the live backend (e.g. the §1a entry registers
``HexRaysValRangeCapability(mba)`` under ``ValRangeCapability``) and threads it
into :class:`d810.passes.pass_pipeline.FunctionPipelineContext`.

Portable (no IDA, no backend imports): it only stores opaque instances keyed by
their Protocol type, so a concrete backend instance that structurally satisfies
a capability Protocol is registered under that Protocol type.
"""
from __future__ import annotations

__all__ = ["CapabilitySet", "CapabilityNotProvided"]


class CapabilityNotProvided(RuntimeError):
    """Raised by :meth:`CapabilitySet.require` when a capability is absent."""


class CapabilitySet:
    """Resolve capability instances by their Protocol type.

    Empty by default, so a pipeline run with no capabilities is a no-op for any
    pass that only queries ``optional`` (returns ``None``).
    """

    __slots__ = ("_by_type",)

    def __init__(self, instances=None) -> None:
        self._by_type: dict = dict(instances or {})

    def optional(self, capability_type):
        """Return the registered instance for ``capability_type``, or ``None``."""
        return self._by_type.get(capability_type)

    def require(self, capability_type):
        """Return the registered instance, or raise :class:`CapabilityNotProvided`."""
        instance = self._by_type.get(capability_type)
        if instance is None:
            name = getattr(capability_type, "__name__", capability_type)
            raise CapabilityNotProvided(f"required capability {name!r} not provided")
        return instance

    def with_capability(self, capability_type, instance) -> "CapabilitySet":
        """Return a new set with ``capability_type -> instance`` added (immutable update)."""
        merged = dict(self._by_type)
        merged[capability_type] = instance
        return CapabilitySet(merged)

    def __contains__(self, capability_type) -> bool:
        return capability_type in self._by_type
