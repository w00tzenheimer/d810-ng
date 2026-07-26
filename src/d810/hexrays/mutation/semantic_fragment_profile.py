"""Typed live-publication profiles for semantic fragment transactions."""

from __future__ import annotations

from enum import Enum


class SemanticFragmentPublicationProfile(str, Enum):
    """Select the SDK authority available to one fragment transaction."""

    CFG_READY = "cfg_ready"
    GENERATED_GRAPH_FREE = "generated_graph_free"

    @property
    def graph_free(self) -> bool:
        return self is SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE


__all__ = ["SemanticFragmentPublicationProfile"]
