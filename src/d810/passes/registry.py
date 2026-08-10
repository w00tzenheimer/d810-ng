"""Stable pass-id registry for PipelineConfig v2."""

from __future__ import annotations

from collections.abc import Mapping

from d810.core.pass_editor_spec import PassEditorKind, PassEditorSpec
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
        self._editor_contract_required: set[str] = set()

    @staticmethod
    def _editor_invisible_option_paths(
        value: object,
        *,
        path: tuple[str, ...],
        editable_paths: frozenset[tuple[str, ...]],
        container_paths: frozenset[tuple[str, ...]],
    ) -> tuple[tuple[str, ...], ...]:
        """Return config leaves that have no closed editor control.

        A top-level comparison is insufficient: a pass could expose
        ``limits.depth`` while silently retaining ``limits.json_only``.  The
        only mapping-only path currently allowed is a transform-options
        container, whose children are still checked against individual typed
        transform controls.
        """
        if isinstance(value, Mapping):
            if not value:
                if not path or path in container_paths or path in editable_paths:
                    return ()
                return (path,)
            invisible: list[tuple[str, ...]] = []
            for key, child in value.items():
                child_path = (*path, str(key))
                has_declared_child = any(
                    declared[: len(child_path)] == child_path
                    for declared in (*editable_paths, *container_paths)
                )
                if not has_declared_child:
                    invisible.append(child_path)
                    continue
                invisible.extend(
                    PassRegistry._editor_invisible_option_paths(
                        child,
                        path=child_path,
                        editable_paths=editable_paths,
                        container_paths=container_paths,
                    )
                )
            return tuple(invisible)
        return () if path in editable_paths else (path,)

    @staticmethod
    def _value_at_path(options: object, path: tuple[str, ...]) -> object:
        value = options
        for segment in path:
            if not isinstance(value, Mapping) or segment not in value:
                return _MISSING_OPTION
            value = value[segment]
        return value

    @staticmethod
    def _validate_catalog_selection(
        pass_id: str,
        *,
        path: tuple[str, ...],
        value: object,
        known_ids: frozenset[str],
        item_kind: str,
    ) -> tuple[str, ...]:
        """Validate an ordered user selection against declared catalog metadata."""
        rendered_path = ".".join(path)
        if not isinstance(value, list):
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} option {rendered_path!r} "
                "must be an ordered list of strings"
            )
        if any(not isinstance(item, str) or not item for item in value):
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} option {rendered_path!r} "
                "must contain non-empty string IDs"
            )
        selected = tuple(value)
        if len(set(selected)) != len(selected):
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} option {rendered_path!r} "
                f"contains duplicate {item_kind} IDs"
            )
        unknown = sorted(set(selected).difference(known_ids))
        if unknown:
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} option {rendered_path!r} "
                f"contains unknown {item_kind} ID(s): {unknown}"
            )
        return selected

    def _validate_public_option_values(
        self,
        pass_id: str,
        options: Mapping[str, object],
        editor_spec: PassEditorSpec,
    ) -> None:
        """Check typed values and catalog membership before runtime sees config."""
        for field in editor_spec.fields:
            value = self._value_at_path(options, field.path)
            if value is _MISSING_OPTION:
                continue
            try:
                field.validate_value(value)
            except ValueError as exc:
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} option {'.'.join(field.path)!r} "
                    f"is invalid: {exc}"
                ) from exc

        if editor_spec.kind is PassEditorKind.RULE_CATALOG:
            value = self._value_at_path(options, editor_spec.rule_option_path)
            if value is _MISSING_OPTION:
                return
            self._validate_catalog_selection(
                pass_id,
                path=editor_spec.rule_option_path,
                value=value,
                known_ids=frozenset(item.rule_id for item in editor_spec.rules),
                item_kind="rule",
            )
            return

        if editor_spec.kind is not PassEditorKind.TRANSFORM_CATALOG:
            return
        transform_path = ("transforms",)
        raw_selection = self._value_at_path(options, transform_path)
        selected_ids: tuple[str, ...] = ()
        if raw_selection is not _MISSING_OPTION:
            selected_ids = self._validate_catalog_selection(
                pass_id,
                path=transform_path,
                value=raw_selection,
                known_ids=frozenset(item.transform_id for item in editor_spec.transforms),
                item_kind="transform",
            )
        raw_options = self._value_at_path(options, ("transform_options",))
        if raw_options is _MISSING_OPTION:
            return
        if not isinstance(raw_options, Mapping):
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} option 'transform_options' "
                "must be an object"
            )
        option_ids = frozenset(str(item) for item in raw_options)
        inactive = sorted(option_ids.difference(selected_ids))
        if inactive:
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} has transform options for "
                f"unselected transform ID(s): {inactive}"
            )
        fields_by_transform = {
            item.transform_id: item.option_fields for item in editor_spec.transforms
        }
        for transform_id, transform_options in raw_options.items():
            if not isinstance(transform_id, str):
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} transform option keys must be strings"
                )
            if not isinstance(transform_options, Mapping):
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} transform options for "
                    f"{transform_id!r} must be an object"
                )
            for field in fields_by_transform[transform_id]:
                value = self._value_at_path(transform_options, field.path)
                if value is _MISSING_OPTION:
                    continue
                try:
                    field.validate_value(value)
                except ValueError as exc:
                    path = ".".join(("transform_options", transform_id, *field.path))
                    raise PassRegistryError(
                        f"public config-v2 pass {pass_id!r} option {path!r} is invalid: {exc}"
                    ) from exc

    def _validate_public_editor_contract(
        self,
        pass_id: str,
        template: PipelineConfig,
        editor_spec: PassEditorSpec | None,
        *,
        require_defaults: bool,
    ) -> None:
        """Reject config-v2 data the fixed public editor cannot represent."""
        if editor_spec is None:
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} has no editor-visible metadata"
            )
        self._validate_public_option_values(pass_id, template.options, editor_spec)
        editor_invisible_paths = self._editor_invisible_option_paths(
            template.options,
            path=(),
            editable_paths=frozenset(editor_spec.editable_option_paths()),
            container_paths=frozenset(editor_spec.option_container_paths()),
        )
        if editor_invisible_paths:
            rendered_paths = [".".join(path) for path in editor_invisible_paths]
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} has editor-invisible option(s): "
                f"{rendered_paths}; every public option must be editor-visible"
            )
        if not require_defaults:
            return
        try:
            defaults = editor_spec.default_options()
        except ValueError as exc:
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} has incomplete editor metadata: {exc}"
            ) from exc
        for field in editor_spec.fields:
            expected = self._value_at_path(defaults, field.path)
            actual = self._value_at_path(template.options, field.path)
            if actual is _MISSING_OPTION:
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} does not seed editor-visible "
                    f"option {'.'.join(field.path)!r} with its runtime-effective default"
                )
            if actual != expected:
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} default for "
                    f"{'.'.join(field.path)!r} differs from its editor metadata"
                )
        if editor_spec.kind.value == "rule_catalog":
            expected = self._value_at_path(defaults, editor_spec.rule_option_path)
            actual = self._value_at_path(template.options, editor_spec.rule_option_path)
            if actual is _MISSING_OPTION or actual != expected:
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} default rule selection differs "
                    "from its editor metadata"
                )
        if editor_spec.kind.value == "transform_catalog":
            expected = self._value_at_path(defaults, ("transforms",))
            actual = self._value_at_path(template.options, ("transforms",))
            if actual is _MISSING_OPTION or actual != expected:
                raise PassRegistryError(
                    f"public config-v2 pass {pass_id!r} default transform selection "
                    "differs from its editor metadata"
                )
            for transform in editor_spec.transforms:
                if not transform.default_selected:
                    continue
                for field in transform.option_fields:
                    path = ("transform_options", transform.transform_id, *field.path)
                    expected = self._value_at_path(defaults, path)
                    actual = self._value_at_path(template.options, path)
                    if actual is _MISSING_OPTION or actual != expected:
                        raise PassRegistryError(
                            f"public config-v2 pass {pass_id!r} does not seed "
                            f"transform option {'.'.join(path)!r} with its "
                            "runtime-effective default"
                        )

    def _record_catalog_metadata(
        self,
        pass_id: str,
        *,
        config_template: PipelineConfig | None,
        stages: tuple[ExecutionStageDescriptor, ...],
        transform_ids: tuple[str, ...],
        editor_spec: PassEditorSpec | None,
        public: bool,
        config_aware: bool,
    ) -> None:
        explicit_config_template = config_template is not None
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
        if public and config_aware and not explicit_config_template:
            raise PassRegistryError(
                f"public config-v2 pass {pass_id!r} requires an explicit config template"
            )
        if public and config_aware:
            self._validate_public_editor_contract(
                pass_id,
                template,
                editor_spec,
                require_defaults=True,
            )
            self._editor_contract_required.add(pass_id)
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
            config_aware=False,
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
            config_aware=True,
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
        if config.pass_id in self._editor_contract_required:
            self._validate_public_editor_contract(
                config.pass_id,
                config,
                self._editor_specs[config.pass_id],
                require_defaults=False,
            )
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

    def validate_editor_contracts(self) -> tuple[()]:
        """Revalidate every public config-v2 editor contract deterministically."""
        for pass_id in self.public_pass_ids():
            if pass_id not in self._editor_contract_required:
                continue
            self._validate_public_editor_contract(
                pass_id,
                self._config_templates[pass_id],
                self._editor_specs[pass_id],
                require_defaults=True,
            )
        return ()


_MISSING_OPTION = object()
