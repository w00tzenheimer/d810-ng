"""Stable pass-id registry for PipelineConfig v2."""
from __future__ import annotations

from d810.core.typing import Callable
from d810.passes.pass_pipeline import PipelineConfig, PipelinePass, PassSpec


class PassRegistryError(RuntimeError):
    """Base error for pass registry contract failures."""


class DuplicatePassIdError(PassRegistryError):
    """A pass id was registered more than once."""


class UnknownPassIdError(PassRegistryError):
    """A PipelineConfig referenced an unregistered pass id."""


class PassRegistry:
    """Factory registry keyed by stable pass id."""

    def __init__(self) -> None:
        self._factories: dict[str, Callable[..., PipelinePass]] = {}

    def register(
        self, pass_id: str, pass_factory: Callable[..., PipelinePass]
    ) -> None:
        """Register ``pass_factory`` under ``pass_id``."""
        if not pass_id:
            raise PassRegistryError("pass_id must be non-empty")
        if pass_id in self._factories:
            raise DuplicatePassIdError(f"duplicate pass id: {pass_id!r}")
        self._factories[pass_id] = pass_factory

    def factory_for(self, pass_id: str) -> Callable[..., PipelinePass]:
        """Return the registered factory for ``pass_id``."""
        try:
            return self._factories[pass_id]
        except KeyError as exc:
            raise UnknownPassIdError(f"unknown pass id: {pass_id!r}") from exc

    def build_spec(self, config: PipelineConfig) -> PassSpec:
        """Build a PassSpec from a durable PipelineConfig."""
        return PassSpec(
            config.pass_id,
            self.factory_for(config.pass_id),
            config.requirements,
            config.safety_policy,
            maturity_gates=config.maturity_gates,
            granularity=config.granularity,
            analyses=config.analyses,
            preservation=config.preservation,
            scheduler_policy=config.scheduler_policy,
            backend_route=config.backend_route,
            contract=config.contract,
            rules=config.rules,
        )
