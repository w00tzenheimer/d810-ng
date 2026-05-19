"""Provider-neutral phase identifiers.

Adapters that own a concrete analysis provider, such as Hex-Rays microcode or
ctree, translate provider-specific phase numbers into this small contract before
calling provider-neutral layers.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol, runtime_checkable


@runtime_checkable
class ProviderPhase(Protocol):
    """Phase identifier supplied by an adapter layer."""

    provider_name: str
    provider_level: int
    friendly_provider_level: str


@dataclass(frozen=True)
class ProviderPhaseSnapshot:
    """Concrete provider phase value for callers that need one."""

    provider_name: str
    provider_level: int
    friendly_provider_level: str
