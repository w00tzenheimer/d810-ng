"""Provider-neutral phase identifiers.

Adapters that own a concrete analysis provider, such as Hex-Rays microcode or
ctree, translate provider-specific phase numbers into this small contract before
calling provider-neutral layers.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.maturity_labels import MaturityNumbering, mmat_name
from d810.core.typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ProviderPhase(Protocol):
    """Phase identifier supplied by an adapter layer."""

    provider_name: str
    provider_level: int
    friendly_provider_level: str
    ir_maturity: Any | None


@dataclass(frozen=True)
class ProviderPhaseSnapshot:
    """Concrete provider phase value for callers that need one."""

    provider_name: str
    provider_level: int
    friendly_provider_level: str
    ir_maturity: Any | None = None


def provider_level_id(provider_phase: ProviderPhase) -> int:
    """Return the provider-native numeric phase id."""

    return int(provider_phase.provider_level)


def provider_level_label(provider_phase: ProviderPhase) -> str:
    """Return the provider-native stable phase label."""

    return str(provider_phase.friendly_provider_level)


def provider_phase_snapshot_from_level(
    provider_level: int,
    *,
    provider_name: str = "legacy",
    provider_label: str | None = None,
    ir_maturity: Any | None = None,
    numbering: MaturityNumbering = MaturityNumbering.WITH_ZERO,
) -> ProviderPhaseSnapshot:
    """Build a concrete phase snapshot from a legacy provider level."""

    level = int(provider_level)
    return ProviderPhaseSnapshot(
        provider_name=provider_name,
        provider_level=level,
        friendly_provider_level=provider_label or mmat_name(level, numbering=numbering),
        ir_maturity=ir_maturity,
    )
