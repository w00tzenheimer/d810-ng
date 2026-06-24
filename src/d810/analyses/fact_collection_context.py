"""Shared context for fact collectors."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.provider_phase import (
    ProviderPhase,
    ProviderPhaseSnapshot,
    provider_level_id,
    provider_level_label,
    provider_phase_snapshot_from_level,
)
from d810.core.typing import Any


@dataclass(frozen=True)
class FactCollectionContext:
    """Provider-neutral fact collection call context."""

    func_ea: int
    provider_phase: ProviderPhase
    phase: str

    @property
    def provider_level(self) -> int:
        return provider_level_id(self.provider_phase)

    @property
    def provider_label(self) -> str:
        return provider_level_label(self.provider_phase)


def coerce_fact_collection_context(
    context: FactCollectionContext | None,
    *,
    func_ea: int | None = None,
    provider_phase: ProviderPhase | None = None,
    phase: str = "pre_d810",
    legacy_fields: dict[str, Any] | None = None,
) -> FactCollectionContext:
    """Return a fact collection context from the canonical or legacy API."""

    fields = legacy_fields if legacy_fields is not None else {}
    legacy_level = fields.pop("maturity", None)
    if fields:
        names = ", ".join(sorted(fields))
        raise TypeError(f"Unexpected fact collection field(s): {names}")
    if context is not None:
        return context
    if func_ea is None:
        raise TypeError("func_ea is required when context is not provided")
    if provider_phase is None:
        if legacy_level is None:
            raise TypeError(
                "provider_phase is required when context is not provided"
            )
        provider_phase = provider_phase_snapshot_from_level(
            int(legacy_level),
        )
    return FactCollectionContext(
        func_ea=int(func_ea),
        provider_phase=provider_phase,
        phase=str(phase),
    )


def fact_provider_label(context: FactCollectionContext) -> str:
    """Return the persisted provider phase label for facts."""

    return context.provider_label


def fact_provider_level(context: FactCollectionContext) -> int:
    """Return the provider-native phase id for facts."""

    return context.provider_level


__all__ = [
    "FactCollectionContext",
    "coerce_fact_collection_context",
    "fact_provider_label",
    "fact_provider_level",
]
