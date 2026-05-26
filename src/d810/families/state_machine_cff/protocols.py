"""Protocols for state-machine CFF family runtimes."""
from __future__ import annotations

from d810.core.typing import Protocol

__all__ = ["StateMachineFamilyRuntimeServices"]


class StateMachineFamilyRuntimeServices(Protocol):
    """Services supplied by a concrete state-machine family profile."""

    def runtime_policy(self, profile: object) -> object: ...

    def run_post_pipeline(
        self,
        profile: object,
        family_result: object,
    ) -> int: ...
