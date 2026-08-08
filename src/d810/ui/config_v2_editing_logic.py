"""Pure projection and action logic for structured config-v2 editing."""

from __future__ import annotations

import copy
import dataclasses
import enum
import json

from d810.manager.config_v2_edit_models import (
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.manager.workbench_recipe_models import PassCatalogEntry


_PASS_PURPOSES = {
    "constant-simplification": "Fold provably constant program values.",
    "mba-simplify": "Simplify selected mixed-boolean arithmetic transforms.",
    "recover-dispatcher": "Recover dispatcher structure and state.",
    "recover-state-transitions": "Recover state-transition edges.",
    "plan-semantic-regions": "Plan semantic regions for safe lowering.",
    "lower-state-machine": "Lower a recovered state machine.",
    "cleanup-residual-dispatcher": "Remove residual dispatcher structure.",
    "jump-fixer": "Repair direct control-flow jumps after rewrites.",
    "indirect-call-resolver": "Resolve eligible indirect calls.",
    "identity-call-resolver": "Resolve identity-preserving indirect calls.",
    "indirect-branch-resolver": "Resolve eligible indirect branches.",
    "single-trip-loop-peel": "Peel a verified single-trip loop.",
    "simple-flattening-cleanup-unflattener": "Remove simple residual flattening structure.",
    "mba-state-preconditioner": "Prepare state facts for MBA-backed recovery.",
}


class ConfigV2EditorScreen(str, enum.Enum):
    OVERVIEW = "overview"
    INSPECTOR = "inspector"
    BUILDER = "builder"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2SerializerRow:
    field_id: str
    label: str
    value_kind: str
    path: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2ActionState:
    action_id: str
    enabled: bool
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2DocumentPipelineRow:
    index: int
    pass_id: str
    options_json: str
    config_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PipelineRow:
    index: int
    pass_id: str
    display_name: str
    purpose: str
    runs_during: str
    selected_transform_summary: str
    option_summary: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PipelineOverview:
    description: str
    rows: tuple[ConfigV2PipelineRow, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2TransformRow:
    transform_id: str
    selected: bool


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PassInspectorView:
    pass_index: int
    pass_id: str
    display_name: str
    purpose: str
    runs_during: str
    selected_transforms: tuple[ConfigV2TransformRow, ...]
    transforms_editable: bool
    options: dict[str, object]
    contract: dict[str, object]
    contract_chips: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RoutingView:
    is_auto: bool
    require: str | None
    preferred: tuple[tuple[str, float], ...]
    denied: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RawDocumentView:
    document: dict[str, object]
    preserved_fields: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2FooterView:
    dirty: bool
    validation_label: str
    validation_detail: str
    save_enabled: bool


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2EditorView:
    overview: ConfigV2PipelineOverview
    inspectors: tuple[ConfigV2PassInspectorView, ...]
    routing: ConfigV2RoutingView
    raw_document: ConfigV2RawDocumentView
    footer: ConfigV2FooterView


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2DocumentView:
    description: str
    pipeline_rows: tuple[ConfigV2DocumentPipelineRow, ...]
    routing_json: str
    complete_document_json: str
    unsupported_document_json: str


def _pretty_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def project_config_v2_document(
    draft: ConfigV2ProjectDraft,
) -> ConfigV2DocumentView:
    document = json.loads(draft.document_json)
    if not isinstance(document, dict):
        raise ValueError("config-v2 project document must be an object")
    additional = document.get("additional_configuration")
    if not isinstance(additional, dict):
        raise ValueError("additional_configuration must be an object")
    pipeline = additional.get("pipeline_v2")
    if not isinstance(pipeline, list):
        raise ValueError("pipeline_v2 must be an ordered list")

    rows: list[ConfigV2DocumentPipelineRow] = []
    for index, entry in enumerate(pipeline):
        if not isinstance(entry, dict):
            raise ValueError(f"pipeline_v2[{index}] must be an object")
        pass_id = entry.get("pass_id")
        if not isinstance(pass_id, str) or not pass_id:
            raise ValueError(f"pipeline_v2[{index}] has no stable pass ID")
        options = entry.get("options", {})
        if not isinstance(options, dict):
            raise ValueError(f"pipeline_v2[{index}].options must be an object")
        rows.append(
            ConfigV2DocumentPipelineRow(
                index=index,
                pass_id=pass_id,
                options_json=_pretty_json(options),
                config_json=_pretty_json(entry),
            )
        )

    routing = additional.get("router_resolution", {})
    if not isinstance(routing, dict):
        raise ValueError("router_resolution must be an object")

    unsupported = copy.deepcopy(document)
    unsupported.pop("description", None)
    unsupported_additional = unsupported.get("additional_configuration")
    if isinstance(unsupported_additional, dict):
        unsupported_additional.pop("pipeline_v2", None)
        unsupported_additional.pop("router_resolution", None)

    return ConfigV2DocumentView(
        description=str(document.get("description", "")),
        pipeline_rows=tuple(rows),
        routing_json=_pretty_json(routing),
        complete_document_json=_pretty_json(document),
        unsupported_document_json=_pretty_json(unsupported),
    )


def _config_v2_document_parts(
    draft: ConfigV2ProjectDraft,
) -> tuple[dict[str, object], dict[str, object], list[object]]:
    document = json.loads(draft.document_json)
    if not isinstance(document, dict):
        raise ValueError("config-v2 project document must be an object")
    additional = document.get("additional_configuration")
    if not isinstance(additional, dict):
        raise ValueError("additional_configuration must be an object")
    pipeline = additional.get("pipeline_v2")
    if not isinstance(pipeline, list):
        raise ValueError("pipeline_v2 must be an ordered list")
    return document, additional, pipeline


def _configured_options(entry: object, index: int) -> tuple[str, dict[str, object]]:
    if not isinstance(entry, dict):
        raise ValueError(f"pipeline_v2[{index}] must be an object")
    pass_id = entry.get("pass_id")
    if not isinstance(pass_id, str) or not pass_id:
        raise ValueError(f"pipeline_v2[{index}] has no stable pass ID")
    options = entry.get("options", {})
    if not isinstance(options, dict):
        raise ValueError(f"pipeline_v2[{index}].options must be an object")
    return pass_id, options


def _contract(entry: PassCatalogEntry) -> dict[str, object]:
    contract = json.loads(entry.contract_json)
    if not isinstance(contract, dict):
        raise ValueError(f"catalog contract for {entry.pass_id!r} must be an object")
    return contract


def _selected_transform_ids(options: dict[str, object]) -> set[str] | None:
    transforms = options.get("transforms")
    if not isinstance(transforms, list):
        return None
    return {
        transform_id for transform_id in transforms if isinstance(transform_id, str)
    }


def _transform_summary(entry: PassCatalogEntry, selected_ids: set[str] | None) -> str:
    if not entry.transform_ids:
        return "No individually selectable transforms"
    selected_count = len(set(entry.transform_ids) & (selected_ids or set()))
    if selected_count == 1:
        return "1 selected transform"
    return f"{selected_count} selected transforms"


def _option_summary(options: dict[str, object]) -> str:
    if not options:
        return "No options"
    return ", ".join(sorted(options))


def _routing_view(additional: dict[str, object]) -> ConfigV2RoutingView:
    routing = additional.get("router_resolution")
    if routing is None:
        return ConfigV2RoutingView(True, None, (), ())
    if not isinstance(routing, dict):
        raise ValueError("router_resolution must be an object")
    require = routing.get("require")
    preferred = routing.get("prefer", {})
    denied = routing.get("deny", [])
    if require is not None and not isinstance(require, str):
        raise ValueError("router_resolution.require must be a string or null")
    if not isinstance(preferred, dict):
        raise ValueError("router_resolution.prefer must be an object")
    if not isinstance(denied, list) or not all(
        isinstance(item, str) for item in denied
    ):
        raise ValueError("router_resolution.deny must be an ordered list of strings")
    preferred_rows: list[tuple[str, float]] = []
    for profile, weight in preferred.items():
        if (
            not isinstance(profile, str)
            or isinstance(weight, bool)
            or not isinstance(weight, (int, float))
        ):
            raise ValueError("router_resolution.prefer must map strings to numbers")
        preferred_rows.append((profile, float(weight)))
    return ConfigV2RoutingView(False, require, tuple(preferred_rows), tuple(denied))


def _footer_view(
    draft: ConfigV2ProjectDraft, validation: ConfigV2ProjectValidation
) -> ConfigV2FooterView:
    current = (
        validation.draft_id == draft.draft_id and validation.revision == draft.revision
    )
    save_enabled = current and validation.valid
    if save_enabled:
        label = "Ready to save."
        detail = ""
    else:
        label = "Validate before saving."
        if not current:
            detail = "Validation does not match the current draft."
        else:
            detail = "; ".join(item.message for item in validation.diagnostics)
    return ConfigV2FooterView(
        dirty=draft.document_json != draft.original_document_json,
        validation_label=label,
        validation_detail=detail,
        save_enabled=save_enabled,
    )


def project_config_v2_editor_view(
    draft: ConfigV2ProjectDraft,
    validation: ConfigV2ProjectValidation,
    catalog: tuple[PassCatalogEntry, ...],
) -> ConfigV2EditorView:
    """Project a config-v2 draft into stable operator-facing presentation data."""

    document, additional, pipeline = _config_v2_document_parts(draft)
    catalog_by_pass_id = {entry.pass_id: entry for entry in catalog}
    overview_rows: list[ConfigV2PipelineRow] = []
    inspectors: list[ConfigV2PassInspectorView] = []
    for index, configured_entry in enumerate(pipeline):
        pass_id, options = _configured_options(configured_entry, index)
        catalog_entry = catalog_by_pass_id.get(pass_id)
        if catalog_entry is None:
            raise ValueError(f"pipeline_v2[{index}] has unknown pass ID {pass_id!r}")
        selected_ids = _selected_transform_ids(options)
        purpose = _PASS_PURPOSES.get(pass_id, "Registered config-v2 pass.")
        overview_rows.append(
            ConfigV2PipelineRow(
                index=index,
                pass_id=pass_id,
                display_name=catalog_entry.display_name,
                purpose=purpose,
                runs_during=catalog_entry.maturity,
                selected_transform_summary=_transform_summary(
                    catalog_entry, selected_ids
                ),
                option_summary=_option_summary(options),
            )
        )
        inspectors.append(
            ConfigV2PassInspectorView(
                pass_index=index,
                pass_id=pass_id,
                display_name=catalog_entry.display_name,
                purpose=purpose,
                runs_during=catalog_entry.maturity,
                selected_transforms=tuple(
                    ConfigV2TransformRow(
                        transform_id, transform_id in (selected_ids or set())
                    )
                    for transform_id in catalog_entry.transform_ids
                ),
                transforms_editable=bool(catalog_entry.transform_ids)
                and selected_ids is not None,
                options=options,
                contract=_contract(catalog_entry),
                contract_chips=(
                    ("Scope", catalog_entry.granularity),
                    ("Backend", catalog_entry.backend_route),
                    ("Safety", catalog_entry.safety_policy),
                ),
            )
        )

    preserved = copy.deepcopy(document)
    preserved.pop("description", None)
    preserved_additional = preserved.get("additional_configuration")
    if isinstance(preserved_additional, dict):
        preserved_additional.pop("pipeline_v2", None)
        preserved_additional.pop("router_resolution", None)
    return ConfigV2EditorView(
        overview=ConfigV2PipelineOverview(
            description=str(document.get("description", "")), rows=tuple(overview_rows)
        ),
        inspectors=tuple(inspectors),
        routing=_routing_view(additional),
        raw_document=ConfigV2RawDocumentView(
            document=document,
            preserved_fields=preserved,
        ),
        footer=_footer_view(draft, validation),
    )


def project_serializer_rows(
    serializers: tuple[ConfigV2FieldSerializer, ...],
) -> tuple[ConfigV2SerializerRow, ...]:
    return tuple(
        ConfigV2SerializerRow(
            field_id=item.field.value,
            label=item.label,
            value_kind=item.value_kind,
            path=".".join(item.document_path),
        )
        for item in serializers
    )


def config_v2_action_states(
    draft: ConfigV2ProjectDraft,
    validation: ConfigV2ProjectValidation,
) -> tuple[ConfigV2ActionState, ...]:
    exact = (
        validation.draft_id == draft.draft_id and validation.revision == draft.revision
    )
    if not exact:
        reason = "Validate the current draft before saving."
    elif not validation.valid:
        reason = "; ".join(item.message for item in validation.diagnostics)
    else:
        reason = ""
    return (
        ConfigV2ActionState("validate", True, ""),
        ConfigV2ActionState("save_project", exact and validation.valid, reason),
    )


__all__ = [
    "ConfigV2ActionState",
    "ConfigV2DocumentView",
    "ConfigV2DocumentPipelineRow",
    "ConfigV2EditorScreen",
    "ConfigV2EditorView",
    "ConfigV2FooterView",
    "ConfigV2PassInspectorView",
    "ConfigV2PipelineRow",
    "ConfigV2PipelineOverview",
    "ConfigV2RawDocumentView",
    "ConfigV2RoutingView",
    "ConfigV2SerializerRow",
    "ConfigV2TransformRow",
    "config_v2_action_states",
    "project_config_v2_document",
    "project_config_v2_editor_view",
    "project_serializer_rows",
]
