"""IDA-independent registered-pass recipe composition and preflight."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping, Sequence

from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeDiagnostic,
    RecipePass,
    RecipeValidation,
)
from d810.passes.contract_manifest import (
    pass_contract_manifest,
    pipeline_contract_preflight_manifest,
)
from d810.passes.contract_preflight import preflight_pipeline_contract
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry, PassRegistryError, UnknownPassIdError
from d810.passes.state_machine_options import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    StateMachineCffOptions,
    replace_state_machine_cff_options,
    state_machine_cff_options_from_config,
)


RECIPE_SCHEMA_VERSION = 1


class RecipeEditError(ValueError):
    """A requested draft edit is outside the registered structured boundary."""


class _EmptyFacts:
    def has_analysis(self, name: str) -> bool:
        return False

    def has_fact(self, name: str) -> bool:
        return False

    def has_evidence(self, name: str) -> bool:
        return False

    def available_analyses(self) -> tuple[str, ...]:
        return ()

    def available_facts(self) -> tuple[str, ...]:
        return ()

    def available_evidence(self) -> tuple[str, ...]:
        return ()


def _canonical_json(value: object, *, trailing_newline: bool = False) -> str:
    rendered = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return rendered + ("\n" if trailing_newline else "")


def _display_name(pass_id: str) -> str:
    if pass_id == "constant-simplification":
        return "Simplify constants"
    words = str(pass_id).replace("_", " ").replace("-", " ").split()
    return " ".join(words).capitalize() or str(pass_id)


def _maturity_label(config: PipelineConfig) -> str:
    if config.maturity_gates:
        return ", ".join(sorted(stage.value for stage in config.maturity_gates))
    maturity = config.contract.maturity
    if maturity.preferred is not None:
        return maturity.preferred.value
    if maturity.min is not None and maturity.max is not None:
        return f"{maturity.min.value}..{maturity.max.value}"
    if maturity.min is not None:
        return f">={maturity.min.value}"
    if maturity.max is not None:
        return f"<={maturity.max.value}"
    return "any"


class RecipeService:
    """Compose immutable drafts strictly from registered pass templates."""

    def __init__(self, registry: PassRegistry) -> None:
        self._registry = registry

    def catalog(self) -> tuple[PassCatalogEntry, ...]:
        entries: list[PassCatalogEntry] = []
        for pass_id in self._registry.public_pass_ids():
            config = self._registry.config_template_for(pass_id)
            spec = self._registry.build_spec(config)
            editor_spec = self._registry.editor_spec_for(pass_id)
            if editor_spec is None:
                raise RecipeEditError(
                    f"public pass {pass_id!r} is missing a config-v2 editor spec"
                )
            entries.append(
                PassCatalogEntry(
                    pass_id=pass_id,
                    display_name=_display_name(pass_id),
                    contract_json=_canonical_json(pass_contract_manifest(spec)),
                    option_template_json=_canonical_json(dict(config.options)),
                    granularity=config.granularity.value,
                    maturity=_maturity_label(config),
                    backend_route=config.backend_route.value,
                    safety_policy=config.safety_policy.name,
                    transform_ids=self._registry.transform_ids_for(pass_id),
                    stage_ids=tuple(
                        stage.stage_id for stage in self._registry.stages_for(pass_id)
                    ),
                    configured=self._registry.is_configured(pass_id),
                    editor_spec=editor_spec,
                    workflow_stage=config.workflow_stage,
                )
            )
        return tuple(entries)

    def create_draft(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
        workbench_generation: int,
        source_path: str,
        runtime_path: str,
        configs: Sequence[PipelineConfig],
    ) -> PipelineRecipeDraft:
        recipe_passes: list[RecipePass] = []
        for ordinal, config in enumerate(configs):
            try:
                self._registry.build_spec(config)
            except (
                PassRegistryError,
                PipelineConfigError,
                TypeError,
                ValueError,
            ) as exc:
                raise RecipeEditError(
                    f"effective pipeline pass {config.pass_id!r} is not buildable: {exc}"
                ) from exc
            recipe_passes.append(
                RecipePass(
                    item_id=f"item-{ordinal}-{config.pass_id}",
                    pass_id=config.pass_id,
                    enabled=True,
                    config_json=_canonical_json(config.to_dict()),
                )
            )
        return PipelineRecipeDraft(
            draft_id=f"draft-{int(function_ea):x}-{int(workbench_generation)}",
            schema_version=RECIPE_SCHEMA_VERSION,
            revision=0,
            function_ea=int(function_ea),
            function_fingerprint=function_fingerprint,
            workbench_generation=int(workbench_generation),
            source_path=str(source_path),
            runtime_path=str(runtime_path),
            passes=tuple(recipe_passes),
        )

    def create_draft_from_override(
        self,
        override: FunctionPipelineOverride,
        *,
        function_ea: int,
        function_fingerprint: str | None,
        workbench_generation: int,
        source_path: str,
        runtime_path: str,
    ) -> PipelineRecipeDraft:
        """Revalidate and materialize the saved effective function recipe."""
        if int(override.schema_version) != RECIPE_SCHEMA_VERSION:
            raise RecipeEditError(
                f"unsupported function recipe schema {override.schema_version}"
            )
        if int(override.function_ea) != int(function_ea):
            raise RecipeEditError("saved recipe belongs to a different function")
        if override.function_fingerprint != function_fingerprint:
            raise RecipeEditError("saved recipe function fingerprint is stale")
        if str(override.source_path) != str(source_path):
            raise RecipeEditError("saved recipe source project is stale")
        if str(override.runtime_path) != str(runtime_path):
            raise RecipeEditError("saved recipe runtime project is stale")
        return self.create_draft(
            function_ea=function_ea,
            function_fingerprint=function_fingerprint,
            workbench_generation=workbench_generation,
            source_path=source_path,
            runtime_path=runtime_path,
            configs=self.deserialize_configs(override.pass_configs_json),
        )

    @staticmethod
    def _item_index(draft: PipelineRecipeDraft, item_id: str) -> int:
        for index, item in enumerate(draft.passes):
            if item.item_id == item_id:
                return index
        raise RecipeEditError(f"draft item {item_id!r} does not exist")

    @staticmethod
    def _replace_passes(
        draft: PipelineRecipeDraft,
        passes: Sequence[RecipePass],
    ) -> PipelineRecipeDraft:
        return dataclasses.replace(
            draft,
            revision=draft.revision + 1,
            passes=tuple(passes),
        )

    def add_pass(
        self,
        draft: PipelineRecipeDraft,
        pass_id: str,
    ) -> PipelineRecipeDraft:
        try:
            config = self._registry.config_template_for(pass_id)
            self._registry.build_spec(config)
        except UnknownPassIdError as exc:
            raise RecipeEditError(f"unknown registered pass {pass_id!r}") from exc
        except (PassRegistryError, PipelineConfigError, TypeError, ValueError) as exc:
            raise RecipeEditError(
                f"registered pass {pass_id!r} is not buildable: {exc}"
            ) from exc
        used = {item.item_id for item in draft.passes}
        serial = draft.revision + len(draft.passes) + 1
        item_id = f"item-{serial}-{pass_id}"
        while item_id in used:
            serial += 1
            item_id = f"item-{serial}-{pass_id}"
        return self._replace_passes(
            draft,
            (
                *draft.passes,
                RecipePass(item_id, pass_id, True, _canonical_json(config.to_dict())),
            ),
        )

    def remove_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
    ) -> PipelineRecipeDraft:
        index = self._item_index(draft, item_id)
        return self._replace_passes(
            draft,
            (*draft.passes[:index], *draft.passes[index + 1 :]),
        )

    def set_enabled(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        enabled: bool,
    ) -> PipelineRecipeDraft:
        index = self._item_index(draft, item_id)
        passes = list(draft.passes)
        passes[index] = dataclasses.replace(passes[index], enabled=bool(enabled))
        return self._replace_passes(draft, passes)

    def reorder_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        new_index: int,
    ) -> PipelineRecipeDraft:
        old_index = self._item_index(draft, item_id)
        if not 0 <= int(new_index) < len(draft.passes):
            raise RecipeEditError(f"draft index {new_index} is out of range")
        passes = list(draft.passes)
        item = passes.pop(old_index)
        passes.insert(int(new_index), item)
        return self._replace_passes(draft, passes)

    def replace_options(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        options: Mapping[str, object],
    ) -> PipelineRecipeDraft:
        index = self._item_index(draft, item_id)
        item = draft.passes[index]
        if item.pass_id in STATE_MACHINE_NATIVE_PASS_IDS:
            raise RecipeEditError(
                "state-CFF options are shared by the complete spine; use "
                "replace_state_cff_options"
            )
        template = self._registry.config_template_for(item.pass_id)
        current_payload = json.loads(item.config_json)
        current = PipelineConfig.from_dict(current_payload)
        if not template.options and not current.options:
            raise RecipeEditError(
                f"pass {item.pass_id!r} does not declare structured options"
            )
        payload = current.to_dict()
        payload["options"] = dict(options)
        try:
            updated = PipelineConfig.from_dict(payload)
            self._registry.build_spec(updated)
        except (PassRegistryError, PipelineConfigError, TypeError, ValueError) as exc:
            raise RecipeEditError(
                f"invalid options for {item.pass_id!r}: {exc}"
            ) from exc
        passes = list(draft.passes)
        passes[index] = dataclasses.replace(
            item,
            config_json=_canonical_json(updated.to_dict()),
        )
        return self._replace_passes(draft, passes)

    def replace_state_cff_options(
        self,
        draft: PipelineRecipeDraft,
        options: StateMachineCffOptions,
    ) -> PipelineRecipeDraft:
        """Replace one typed option across the complete canonical CFF spine."""
        indexed = tuple(
            (index, item)
            for index, item in enumerate(draft.passes)
            if item.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
        )
        pass_ids = tuple(item.pass_id for _, item in indexed)
        indexes = tuple(index for index, _ in indexed)
        contiguous = bool(indexes) and indexes == tuple(
            range(indexes[0], indexes[0] + len(indexes))
        )
        if pass_ids != STATE_MACHINE_NATIVE_PASS_IDS or not contiguous:
            raise RecipeEditError(
                "state-CFF option override requires the complete canonical "
                "state-CFF spine"
            )

        passes = list(draft.passes)
        for index, item in indexed:
            current = PipelineConfig.from_dict(json.loads(item.config_json))
            try:
                updated = replace_state_machine_cff_options(current, options)
                self._registry.build_spec(updated)
            except (
                PassRegistryError,
                PipelineConfigError,
                TypeError,
                ValueError,
            ) as exc:
                raise RecipeEditError(
                    f"invalid state-CFF options for {item.pass_id!r}: {exc}"
                ) from exc
            passes[index] = dataclasses.replace(
                item,
                config_json=_canonical_json(updated.to_dict()),
            )
        return self._replace_passes(draft, passes)

    def state_cff_options(
        self,
        draft: PipelineRecipeDraft,
    ) -> StateMachineCffOptions:
        """Read the single typed option set owned by the canonical CFF spine."""
        items = tuple(
            item
            for item in draft.passes
            if item.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
        )
        pass_ids = tuple(item.pass_id for item in items)
        indexes = tuple(draft.passes.index(item) for item in items)
        contiguous = bool(indexes) and indexes == tuple(
            range(indexes[0], indexes[0] + len(indexes))
        )
        if pass_ids != STATE_MACHINE_NATIVE_PASS_IDS or not contiguous:
            raise RecipeEditError(
                "state-CFF option access requires the complete canonical "
                "state-CFF spine"
            )
        try:
            options = tuple(
                state_machine_cff_options_from_config(
                    PipelineConfig.from_dict(json.loads(item.config_json))
                )
                for item in items
            )
        except (PipelineConfigError, TypeError, ValueError) as exc:
            raise RecipeEditError(f"invalid state-CFF options: {exc}") from exc
        if any(candidate != options[0] for candidate in options[1:]):
            raise RecipeEditError(
                "the canonical state-CFF spine must use the same typed options"
            )
        return options[0]

    def validate(
        self,
        draft: PipelineRecipeDraft,
        *,
        facts: object | None = None,
    ) -> RecipeValidation:
        diagnostics: list[RecipeDiagnostic] = []
        seen_item_ids: set[str] = set()
        enabled_specs: list[object] = []
        enabled_items: list[tuple[int, RecipePass]] = []

        for ordinal, item in enumerate(draft.passes):
            if item.item_id in seen_item_ids:
                diagnostics.append(
                    RecipeDiagnostic(
                        "duplicate-item-id",
                        f"Duplicate draft item ID: {item.item_id}",
                        ordinal,
                        item.pass_id,
                        None,
                        (),
                    )
                )
            seen_item_ids.add(item.item_id)
            try:
                payload = json.loads(item.config_json)
                if not isinstance(payload, Mapping):
                    raise PipelineConfigError("pass config must be an object")
                config = PipelineConfig.from_dict(payload)
                if config.pass_id != item.pass_id:
                    raise PipelineConfigError(
                        f"config pass_id {config.pass_id!r} does not match item pass_id {item.pass_id!r}"
                    )
                spec = self._registry.build_spec(config)
            except UnknownPassIdError as exc:
                diagnostics.append(
                    RecipeDiagnostic(
                        "unknown-pass-id",
                        str(exc),
                        ordinal,
                        item.pass_id,
                        None,
                        (),
                    )
                )
                continue
            except (
                json.JSONDecodeError,
                PassRegistryError,
                PipelineConfigError,
                TypeError,
                ValueError,
            ) as exc:
                diagnostics.append(
                    RecipeDiagnostic(
                        "invalid-pass-config",
                        str(exc),
                        ordinal,
                        item.pass_id,
                        None,
                        (),
                    )
                )
                continue
            if item.enabled:
                enabled_specs.append(spec)
                enabled_items.append((ordinal, item))

        if not enabled_specs:
            diagnostics.append(
                RecipeDiagnostic(
                    "empty-pipeline",
                    "Recipe must contain at least one enabled registered pass",
                    None,
                    None,
                    None,
                    (),
                )
            )
            manifest: object = []
        else:
            preflight = preflight_pipeline_contract(
                enabled_specs, facts or _EmptyFacts()
            )
            manifest = pipeline_contract_preflight_manifest(enabled_specs, preflight)
            for (ordinal, item), result in zip(enabled_items, preflight.results):
                for diagnostic in result.diagnostics:
                    missing = tuple(sorted(str(value) for value in diagnostic.missing))
                    namespace = str(diagnostic.namespace or "") or None
                    message = (
                        f"{namespace}: missing {', '.join(missing)}"
                        if namespace and missing
                        else str(diagnostic.detail or "Contract preflight blocked")
                    )
                    diagnostics.append(
                        RecipeDiagnostic(
                            "missing-contract-input",
                            message,
                            ordinal,
                            item.pass_id,
                            namespace,
                            missing,
                        )
                    )

        return RecipeValidation(
            draft_id=draft.draft_id,
            revision=draft.revision,
            satisfied=not diagnostics,
            diagnostics=tuple(diagnostics),
            manifest_json=_canonical_json(manifest),
        )

    def serialize_enabled_configs(self, draft: PipelineRecipeDraft) -> str:
        payload: list[object] = []
        for item in draft.passes:
            if not item.enabled:
                continue
            config_payload = json.loads(item.config_json)
            config = PipelineConfig.from_dict(config_payload)
            if config.pass_id != item.pass_id:
                raise RecipeEditError(
                    f"config pass_id {config.pass_id!r} does not match {item.pass_id!r}"
                )
            self._registry.build_spec(config)
            payload.append(config.to_dict())
        if not payload:
            raise RecipeEditError("recipe has no enabled registered passes")
        return _canonical_json(payload, trailing_newline=True)

    def deserialize_configs(self, payload_json: str) -> tuple[PipelineConfig, ...]:
        """Parse and revalidate a complete persisted recipe against the registry."""
        try:
            payload = json.loads(str(payload_json))
        except json.JSONDecodeError as exc:
            raise RecipeEditError(f"recipe JSON is invalid: {exc}") from exc
        if not isinstance(payload, list):
            raise RecipeEditError("persisted recipe must be a sequence of pass configs")
        if not payload:
            raise RecipeEditError("persisted recipe contains no pass configs")
        configs: list[PipelineConfig] = []
        for ordinal, item in enumerate(payload):
            if not isinstance(item, Mapping):
                raise RecipeEditError(
                    f"persisted recipe pass {ordinal} must be an object"
                )
            try:
                config = PipelineConfig.from_dict(item)
                self._registry.build_spec(config)
            except (
                UnknownPassIdError,
                PassRegistryError,
                PipelineConfigError,
                TypeError,
                ValueError,
            ) as exc:
                raise RecipeEditError(
                    f"persisted recipe pass {ordinal} is invalid: {exc}"
                ) from exc
            configs.append(config)
        return tuple(configs)


__all__ = ["RECIPE_SCHEMA_VERSION", "RecipeEditError", "RecipeService"]
