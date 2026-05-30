"""Hodur family policy: profile dataclass + env-driven strategy selection (LS13 C3).

The POLICY half of the former ``optimizers/.../hodur/profile.py`` -- the runtime
policy dataclass and the pure env-var helpers that select / filter strategy
classes.  This half is backend-neutral (only ``os`` + ``dataclasses``); the
strategy *classes* themselves (which import ``ida_hexrays``) and
``default_hodur_profile()`` stay in ``profile.py``, which re-imports these names
back (reverse-shim).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["HodurUnflatteningProfile"]


@dataclass(frozen=True, slots=True)
class HodurUnflatteningProfile:
    """Runtime policy and strategy ordering for the Hodur profile."""

    strategy_classes: tuple[type, ...]
    entrypoint_strategy_classes: tuple[type, ...]
    experimental_strategy_classes: tuple[type, ...]
    legacy_strategy_classes: tuple[type, ...]
    detector: str
    evidence_adapters: tuple[str, ...]
    audit_hooks: tuple[str, ...]
    post_apply_hooks: tuple[str, ...]
    executor_safeguard_profile: str = "hodur"

    def uses_evidence_adapter(self, name: str) -> bool:
        """Return whether this profile declares a named evidence adapter."""
        return name in self.evidence_adapters

    def enables_audit_hook(self, name: str) -> bool:
        """Return whether this profile declares a named audit hook."""
        return name in self.audit_hooks

    def enables_post_apply_hook(self, name: str) -> bool:
        """Return whether this profile declares a named post-apply hook."""
        return name in self.post_apply_hooks


def _env_name_set(name: str) -> set[str]:
    return {
        value.strip()
        for value in os.environ.get(name, "").split(",")
        if value.strip()
    }


def _filter_strategies(strategies: tuple[type, ...]) -> tuple[type, ...]:
    """Filter strategies via env vars D810_HODUR_ONLY / D810_HODUR_SKIP."""
    only = _env_name_set("D810_HODUR_ONLY")
    skip = _env_name_set("D810_HODUR_SKIP")
    out = tuple(strategies)
    if only:
        out = tuple(strategy for strategy in out if strategy.__name__ in only)
    if skip:
        out = tuple(strategy for strategy in out if strategy.__name__ not in skip)
    return out


def _legacy_semantic_region_enabled() -> bool:
    return (
        os.getenv("D810_HODUR_ENABLE_SEMANTIC_STRUCTURED_REGION", "").strip() == "1"
        or "SemanticStructuredRegionStrategy" in _env_name_set("D810_HODUR_ONLY")
    )


def _standalone_srw_enabled() -> bool:
    return (
        os.getenv("D810_RECON_ENABLE_STANDALONE_SRW", "").strip() == "1"
        and os.getenv("D810_RECON_SKIP_SRW_STRATEGY", "").strip() != "1"
    )
