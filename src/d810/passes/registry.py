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
        self._configured_factories: dict[
            str, Callable[[PipelineConfig], PipelinePass]
        ] = {}
        self._config_templates: dict[str, PipelineConfig] = {}
        self._transforms: dict[str, tuple[str, ...]] = {}

    def _record_catalog_metadata(
        self,
        pass_id: str,
        *,
        config_template: PipelineConfig | None,
        transforms: tuple[str, ...],
    ) -> None:
        template = config_template or PipelineConfig(pass_id=pass_id)
        if template.pass_id != pass_id:
            raise PassRegistryError(
                "config template pass id does not match registration: "
                f"{template.pass_id!r} != {pass_id!r}"
            )
        normalized = tuple(
            dict.fromkeys(
                str(transform).strip()
                for transform in transforms
                if str(transform).strip()
            )
        )
        self._config_templates[pass_id] = template
        self._transforms[pass_id] = normalized

    def register(
        self,
        pass_id: str,
        pass_factory: Callable[..., PipelinePass],
        *,
        config_template: PipelineConfig | None = None,
        transforms: tuple[str, ...] = (),
    ) -> None:
        """Register ``pass_factory`` under ``pass_id``."""
        if not pass_id:
            raise PassRegistryError("pass_id must be non-empty")
        if pass_id in self._factories or pass_id in self._configured_factories:
            raise DuplicatePassIdError(f"duplicate pass id: {pass_id!r}")
        self._factories[pass_id] = pass_factory
        self._record_catalog_metadata(
            pass_id,
            config_template=config_template,
            transforms=transforms,
        )

    def register_configured(
        self,
        pass_id: str,
        pass_factory: Callable[[PipelineConfig], PipelinePass],
        *,
        config_template: PipelineConfig | None = None,
        transforms: tuple[str, ...] = (),
    ) -> None:
        """Register a pass factory that is built from its ``PipelineConfig``."""
        if not pass_id:
            raise PassRegistryError("pass_id must be non-empty")
        if pass_id in self._factories or pass_id in self._configured_factories:
            raise DuplicatePassIdError(f"duplicate pass id: {pass_id!r}")
        self._configured_factories[pass_id] = pass_factory
        self._record_catalog_metadata(
            pass_id,
            config_template=config_template,
            transforms=transforms,
        )

    def registered_pass_ids(self) -> tuple[str, ...]:
        """Return stable registered pass IDs in deterministic catalog order."""
        return tuple(sorted(self._config_templates))

    def config_template_for(self, pass_id: str) -> PipelineConfig:
        """Return the immutable canonical config template for one pass ID."""
        try:
            return self._config_templates[pass_id]
        except KeyError as exc:
            raise UnknownPassIdError(f"unknown pass id: {pass_id!r}") from exc

    def transforms_for(self, pass_id: str) -> tuple[str, ...]:
        self.config_template_for(pass_id)
        return self._transforms[pass_id]

    def is_configured(self, pass_id: str) -> bool:
        self.config_template_for(pass_id)
        return pass_id in self._configured_factories

    def factory_for(self, pass_id: str) -> Callable[..., PipelinePass]:
        """Return the registered factory for ``pass_id``."""
        try:
            return self._factories[pass_id]
        except KeyError as exc:
            raise UnknownPassIdError(f"unknown pass id: {pass_id!r}") from exc

    def build_spec(self, config: PipelineConfig) -> PassSpec:
        """Build a PassSpec from a durable PipelineConfig."""
        pass_factory: Callable[..., PipelinePass]
        configured_factory = self._configured_factories.get(config.pass_id)
        if configured_factory is None:
            pass_factory = self.factory_for(config.pass_id)
        else:
            configured_factory(config)
            pass_factory = lambda: configured_factory(config)
        return PassSpec(
            config.pass_id,
            pass_factory,
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
            workflow_stage=config.workflow_stage,
            options=config.options,
        )
