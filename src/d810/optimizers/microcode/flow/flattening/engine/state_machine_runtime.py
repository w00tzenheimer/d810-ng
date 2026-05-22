"""Runtime facade for profile-driven state-machine unflattening families."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol

from .runtime import (
    FamilyContext,
    FamilyPassResult,
    FamilyRuntimePolicy,
    run_configured_family_pass,
)

__all__ = [
    "StateMachineFamilyPassResult",
    "StateMachineFamilyRuntimeServices",
    "run_state_machine_family_pass",
]


class StateMachineFamilyRuntimeServices(Protocol):
    """Services supplied by a concrete state-machine family profile."""

    def runtime_policy(self, profile: object) -> FamilyRuntimePolicy: ...

    def run_post_pipeline(
        self,
        profile: object,
        family_result: FamilyPassResult,
    ) -> int: ...


@dataclass(frozen=True)
class StateMachineFamilyPassResult:
    """State-machine pass result after profile post-pipeline hooks."""

    family_result: FamilyPassResult
    total_changes: int

    @property
    def analysis(self):
        return self.family_result.analysis

    @property
    def planned(self):
        return self.family_result.planned

    @property
    def executed(self):
        return self.family_result.executed

    @property
    def pipeline(self):
        return self.family_result.pipeline

    @property
    def results(self):
        return self.family_result.results

    @property
    def provenance(self):
        return self.family_result.provenance


def run_state_machine_family_pass(
    *,
    family: object,
    profile: object,
    context: FamilyContext,
    services: StateMachineFamilyRuntimeServices,
) -> StateMachineFamilyPassResult:
    """Run detect -> snapshot -> plan -> execute -> profile hooks."""
    family_result = run_configured_family_pass(
        family,
        context,
        services.runtime_policy(profile),
    )
    total_changes = services.run_post_pipeline(profile, family_result)
    return StateMachineFamilyPassResult(
        family_result=family_result,
        total_changes=total_changes,
    )
