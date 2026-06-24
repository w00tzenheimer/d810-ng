"""Shared context for control-flow reconnaissance collectors."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.provider_phase import (
    ProviderPhase,
    provider_level_id,
    provider_phase_snapshot_from_level,
)
from d810.core.typing import Any


@dataclass(frozen=True)
class ReconCollectionContext:
    """Provider-neutral recon collector call context."""

    func_ea: int
    provider_phase: ProviderPhase

    @property
    def provider_level(self) -> int:
        return provider_level_id(self.provider_phase)


def coerce_recon_collection_context(
    context: ReconCollectionContext | None,
    *,
    func_ea: int | None = None,
    provider_phase: ProviderPhase | None = None,
    legacy_fields: dict[str, Any] | None = None,
) -> ReconCollectionContext:
    """Return a recon context from the canonical or legacy collector API."""

    fields = legacy_fields if legacy_fields is not None else {}
    legacy_level = fields.pop("maturity", None)
    if fields:
        names = ", ".join(sorted(fields))
        raise TypeError(f"Unexpected recon collection field(s): {names}")
    if context is not None:
        return context
    if func_ea is None:
        raise TypeError("func_ea is required when context is not provided")
    if provider_phase is None:
        if legacy_level is None:
            raise TypeError(
                "provider_phase is required when context is not provided"
            )
        provider_phase = provider_phase_snapshot_from_level(int(legacy_level))
    return ReconCollectionContext(
        func_ea=int(func_ea),
        provider_phase=provider_phase,
    )


__all__ = [
    "ReconCollectionContext",
    "coerce_recon_collection_context",
]
