"""Stable pass-id registry for PipelineConfig v2."""

from __future__ import annotations

from d810.core.pass_editor_spec import PassEditorSpec
from d810.core.typing import Callable
from d810.passes.execution_stages import ExecutionStageDescriptor
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
        self._stages: dict[str, tuple[ExecutionStageDescriptor, ...]] = {}
        self._transform_ids: dict[str, tuple[str, ...]] = {}
        self._editor_specs: dict[str, PassEditorSpec | None] = {}
        self._public: set[str] = set()

    def _record_catalog_metadata(
        self,
        pass_id: str,
        *,
        config_template: PipelineConfig | None,
        stages: tuple[ExecutionStageDescriptor, ...],
        transform_ids: tuple[str, ...],
        editor_spec: PassEditorSpec | None,
        public: bool,
    ) -> None:
        template = config_template or PipelineConfig(pass_id=pass_id)
        if template.pass_id != pass_id:
            raise PassRegistryError(
                "config template pass id does not match registration: "
                f"{template.pass_id!r} != {pass_id!r}"
            )
        seen_stage_ids: set[str] = set()
        for stage in stages:
            if not isinstance(stage, ExecutionStageDescriptor):
                raise PassRegistryError(
                    "stages must contain ExecutionStageDescriptor values"
                )
            if stage.pass_id != pass_id:
                raise PassRegistryError(
                    f"stage {stage.stage_id!r} owning pass {stage.pass_id!r} "
                    f"does not match registration {pass_id!r}"
                )
            if stage.stage_id in seen_stage_ids:
                raise PassRegistryError(
                    f"duplicate stage id {stage.stage_id!r} in pass {pass_id!r}"
                )
            seen_stage_ids.add(stage.stage_id)
        normalized_transform_ids = tuple(transform_ids)
        if len(set(normalized_transform_ids)) != len(normalized_transform_ids):
            raise PassRegistryError(f"duplicate transform id in pass {pass_id!r}")
        unknown_transform_ids = tuple(
            transform_id
            for transform_id in normalized_transform_ids
            if transform_id not in seen_stage_ids
        )
        if unknown_transform_ids:
            raise PassRegistryError(
                f"transform ids must reference registered stages for {pass_id!r}: "
                f"{list(unknown_transform_ids)}"
            )
        self._config_templates[pass_id] = template
        self._stages[pass_id] = tuple(stages)
        self._transform_ids[pass_id] = normalized_transform_ids
        self._editor_specs[pass_id] = editor_spec
        if public:
            self._public.add(pass_id)

    def register(
        self,
        pass_id: str,
        pass_factory: Callable[..., PipelinePass],
        *,
        config_template: PipelineConfig | None = None,
        stages: tuple[ExecutionStageDescriptor, ...] = (),
        transform_ids: tuple[str, ...] = (),
        editor_spec: PassEditorSpec | None = None,
        public: bool = True,
    ) -> None:
        """Register ``pass_factory`` under ``pass_id``."""
        if not pass_id:
            raise PassRegistryError("pass_id must be non-empty")
        if pass_id in self._factories or pass_id in self._configured_factories:
            raise DuplicatePassIdError(f"duplicate pass id: {pass_id!r}")
        self._record_catalog_metadata(
            pass_id,
            config_template=config_template,
            stages=stages,
            transform_ids=transform_ids,
            editor_spec=editor_spec,
            public=public,
        )
        self._factories[pass_id] = pass_factory

    def register_configured(
        self,
        pass_id: str,
        pass_factory: Callable[[PipelineConfig], PipelinePass],
        *,
        config_template: PipelineConfig | None = None,
        stages: tuple[ExecutionStageDescriptor, ...] = (),
        transform_ids: tuple[str, ...] = (),
        editor_spec: PassEditorSpec | None = None,
        public: bool = True,
    ) -> None:
        """Register a pass factory that is built from its ``PipelineConfig``."""
        if not pass_id:
            raise PassRegistryError("pass_id must be non-empty")
        if pass_id in self._factories or pass_id in self._configured_factories:
            raise DuplicatePassIdError(f"duplicate pass id: {pass_id!r}")
        self._record_catalog_metadata(
            pass_id,
            config_template=config_template,
            stages=stages,
            transform_ids=transform_ids,
            editor_spec=editor_spec,
            public=public,
        )
        self._configured_factories[pass_id] = pass_factory

    def registered_pass_ids(self) -> tuple[str, ...]:
        """Return stable registered pass IDs in deterministic catalog order."""
        return tuple(sorted(self._config_templates))

    def public_pass_ids(self) -> tuple[str, ...]:
        """Return only user-authorable pass IDs in deterministic order."""
        return tuple(sorted(self._public))

    def config_template_for(self, pass_id: str) -> PipelineConfig:
        """Return the immutable canonical config template for one pass ID."""
        try:
            return self._config_templates[pass_id]
        except KeyError as exc:
            raise UnknownPassIdError(f"unknown pass id: {pass_id!r}") from exc

    def stages_for(self, pass_id: str) -> tuple[ExecutionStageDescriptor, ...]:
        """Return ordered stable execution stages owned by one pass."""
        self.config_template_for(pass_id)
        return self._stages[pass_id]

    def transform_ids_for(self, pass_id: str) -> tuple[str, ...]:
        """Return stable user-selectable transform IDs owned by one pass."""
        self.config_template_for(pass_id)
        return self._transform_ids[pass_id]

    def editor_spec_for(self, pass_id: str) -> PassEditorSpec | None:
        """Return the closed config-v2 editor contract for one pass."""
        self.config_template_for(pass_id)
        return self._editor_specs[pass_id]

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

            def pass_factory() -> PipelinePass:
                return configured_factory(config)

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
            workflow_stage=config.workflow_stage,
            target=config.target,
            options=config.options,
        )
