"""Back-compat re-export of the shared unflattening plan-fragment types.

The canonical home for ``PlanFragmentMetadata``, ``OwnershipScope``,
``BenefitMetrics``, ``PlanFragment``, ``StageResult``, and
``VerificationGate`` is now :mod:`d810.transforms.plan_fragment` (a
layer-low module that importers can depend on downward).  This module
re-exports those names for the existing import sites under
``optimizers.microcode.flow.flattening.engine`` and ``hodur/``.

It also re-exports ``UnflatteningStrategy`` from its canonical home
``d810.families.state_machine_cff.protocols`` and exposes ``SemanticGate``
lazily via ``__getattr__`` so that importing this module does not pull in
IDA-only dependencies.

New code should import the plan-fragment types from
:mod:`d810.transforms.plan_fragment` and ``UnflatteningStrategy`` from
``d810.families.state_machine_cff.protocols``.
"""
from __future__ import annotations

# Canonical home for ``UnflatteningStrategy`` is
# ``d810.families.state_machine_cff.protocols`` per the
# llvm-lisa-restructure plan.  This module re-exports it for
# back-compat with the dozen existing import sites under
# ``optimizers.microcode.flow.flattening.engine`` and ``hodur/``.
# New code should import from the canonical location.
from d810.families.state_machine_cff.protocols import UnflatteningStrategy
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    PlanFragmentMetadata,
    StageResult,
    VerificationGate,
)

__all__ = [
    "FAMILY_CLEANUP",
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "BenefitMetrics",
    "OwnershipScope",
    "PlanFragment",
    "PlanFragmentMetadata",
    "StageResult",
    "UnflatteningStrategy",
    "VerificationGate",
]


def __getattr__(name: str):
    if name == "SemanticGate":
        try:
            from d810.analyses.control_flow.graph_checks import SemanticGate
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("ida_"):
                raise AttributeError(
                    "SemanticGate is unavailable without IDA dependencies"
                ) from exc
            raise

        return SemanticGate
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
