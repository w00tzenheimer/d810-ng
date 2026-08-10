"""Pure projection and action logic for structured config-v2 editing."""

from __future__ import annotations

import copy
import dataclasses
import enum
import json

from d810.core.pass_editor_spec import (
    FieldControlKind,
    FieldEditorSpec,
    PassEditorKind,
    PassEditorSpec,
)
from d810.core.typing import AbstractSet
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


class ConfigV2InspectorPrimarySection(str, enum.Enum):
    NONE = "none"
    RULES = "rules"
    TRANSFORMS = "transforms"
    OPTIONS = "options"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PassInspectorLayoutView:
    primary_section: ConfigV2InspectorPrimarySection
    show_rule_catalog: bool
    show_transform_catalog: bool
    show_options: bool
    show_summary_message: bool
    summary_message: str
    can_view_contract: bool


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
class ConfigV2TransformView:
    """One visible leaf in a fixed pass-owned transform catalog."""

    transform_id: str
    label: str
    description: str
    reference: str
    maturities: tuple[str, ...]
    selected: bool
    default_selected: bool
    verification: str
    verification_reason: str
    advisory: str
    advisory_reason: str
    cost: str
    cost_detail: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2TransformSubfamilyView:
    """Visible descendants for one explicit transform subfamily."""

    family_id: str
    subfamily_id: str
    label: str
    target_id: str
    selected_count: int
    visible_count: int
    check_state: str
    transforms: tuple[ConfigV2TransformView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2TransformFamilyView:
    """Visible descendants for one explicit transform family."""

    family_id: str
    label: str
    target_id: str
    selected_count: int
    visible_count: int
    check_state: str
    subfamilies: tuple[ConfigV2TransformSubfamilyView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2TransformCatalogView:
    """Qt-free tree model and action scope for one transform editor."""

    pass_editor_spec: PassEditorSpec
    query: str
    selected_ids: tuple[str, ...]
    all_transform_ids: tuple[str, ...]
    visible_transform_ids: tuple[str, ...]
    families: tuple[ConfigV2TransformFamilyView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RuleView:
    """One visible leaf in a fixed pass-owned rule catalog."""

    rule_id: str
    label: str
    description: str
    reference: str
    maturities: tuple[str, ...]
    selected: bool
    default_selected: bool
    experimental: bool
    experimental_reason: str
    verification: str
    verification_reason: str
    advisory: str
    advisory_reason: str
    cost: str
    cost_detail: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RuleSubfamilyView:
    """Visible descendants for one explicit rule subfamily."""

    family_id: str
    subfamily_id: str
    label: str
    target_id: str
    selected_count: int
    visible_count: int
    check_state: str
    rules: tuple[ConfigV2RuleView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RuleFamilyView:
    """Visible descendants for one explicit rule family."""

    family_id: str
    label: str
    target_id: str
    selected_count: int
    visible_count: int
    check_state: str
    subfamilies: tuple[ConfigV2RuleSubfamilyView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RuleCatalogView:
    """Qt-free tree model and action scope for one fixed rule editor."""

    pass_editor_spec: PassEditorSpec
    query: str
    selected_ids: tuple[str, ...]
    all_rule_ids: tuple[str, ...]
    visible_rule_ids: tuple[str, ...]
    families: tuple[ConfigV2RuleFamilyView, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PassInspectorView:
    pass_index: int
    pass_id: str
    display_name: str
    purpose: str
    runs_during: str
    transform_catalog: ConfigV2TransformCatalogView | None
    options: dict[str, object]
    contract: dict[str, object]
    contract_chips: tuple[tuple[str, str], ...]
    # Rule catalogs were added after the lightweight pipeline overview began
    # constructing inspector rows.  Keep the presentation-only addition
    # optional so an already-loaded overview cannot fail during a hot reload.
    rule_catalog: ConfigV2RuleCatalogView | None = None
    layout: ConfigV2PassInspectorLayoutView | None = None


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


def _option_path_value(
    options: dict[str, object], path: tuple[str, ...]
) -> object | None:
    value: object = options
    for segment in path:
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def _selected_rule_ids(
    options: dict[str, object], spec: PassEditorSpec
) -> set[str] | None:
    if spec.kind is not PassEditorKind.RULE_CATALOG:
        return None
    rules = _option_path_value(options, spec.rule_option_path)
    if not isinstance(rules, list):
        rules = _option_path_value(spec.default_options(), spec.rule_option_path)
    if not isinstance(rules, list):
        return None
    return {rule_id for rule_id in rules if isinstance(rule_id, str)}


def _transform_summary(entry: PassCatalogEntry, selected_ids: set[str] | None) -> str:
    if not entry.transform_ids:
        return "No individually selectable transforms"
    selected_count = len(set(entry.transform_ids) & (selected_ids or set()))
    if selected_count == 1:
        return "1 selected transform"
    return f"{selected_count} selected transforms"


def _rule_summary(entry: PassCatalogEntry, selected_ids: set[str] | None) -> str:
    if entry.editor_spec.kind is not PassEditorKind.RULE_CATALOG:
        return "No individually selectable rules"
    selected_count = len(
        {item.rule_id for item in entry.editor_spec.rules}.intersection(selected_ids or set())
    )
    if selected_count == 1:
        return "1 selected rule"
    return f"{selected_count} selected rules"


def _selection_summary(entry: PassCatalogEntry, options: dict[str, object]) -> str:
    if entry.editor_spec.kind is PassEditorKind.RULE_CATALOG:
        return _rule_summary(entry, _selected_rule_ids(options, entry.editor_spec))
    return _transform_summary(entry, _selected_transform_ids(options))


def _catalog_check_state(*, selected_count: int, visible_count: int) -> str:
    if not selected_count:
        return "unchecked"
    if selected_count == visible_count:
        return "checked"
    return "partial"


def _matches_transform_query(
    transform: object,
    query: str,
) -> bool:
    if not query:
        return True
    fields = (
        transform.transform_id,
        transform.label,
        transform.family_id,
        transform.family_label,
        transform.subfamily_id or "",
        transform.subfamily_label or "",
        transform.description,
        transform.reference,
        transform.verification.value,
        transform.advisory.value,
        transform.cost.value,
    )
    return any(query in field.casefold() for field in fields)


def project_transform_catalog(
    spec: PassEditorSpec,
    selected_ids: AbstractSet[str],
    *,
    query: str,
) -> ConfigV2TransformCatalogView:
    """Project explicit metadata into a filterable family/subfamily tree.

    Defaults are presentation-only.  The caller's existing selection is never
    expanded or otherwise mutated while the catalog is projected.
    """
    if spec.kind is not PassEditorKind.TRANSFORM_CATALOG:
        raise ValueError("transform catalog projection requires a transform_catalog spec")
    normalized_query = str(query).strip().casefold()
    all_transform_ids = tuple(item.transform_id for item in spec.transforms)
    known_selected_ids = frozenset(selected_ids).intersection(all_transform_ids)
    family_specs: dict[str, dict[str, object]] = {}
    visible_transform_ids: list[str] = []
    for item in spec.transforms:
        if not _matches_transform_query(item, normalized_query):
            continue
        visible_transform_ids.append(item.transform_id)
        family = family_specs.setdefault(
            item.family_id,
            {
                "label": item.family_label,
                "subfamilies": {},
            },
        )
        subfamily_id = item.subfamily_id or "__ungrouped__"
        subfamily_label = item.subfamily_label or item.family_label
        subfamilies = family["subfamilies"]
        assert isinstance(subfamilies, dict)
        leaves = subfamilies.setdefault(subfamily_id, (subfamily_label, []))
        leaves[1].append(item)

    families: list[ConfigV2TransformFamilyView] = []
    for family_id, family in family_specs.items():
        subfamilies = family["subfamilies"]
        assert isinstance(subfamilies, dict)
        projected_subfamilies: list[ConfigV2TransformSubfamilyView] = []
        family_selected_count = 0
        family_visible_count = 0
        for subfamily_id, (subfamily_label, transforms) in subfamilies.items():
            leaf_views = tuple(
                ConfigV2TransformView(
                    transform_id=item.transform_id,
                    label=item.label,
                    description=item.description,
                    reference=item.reference,
                    maturities=item.maturities,
                    selected=item.transform_id in known_selected_ids,
                    default_selected=item.default_selected,
                    verification=item.verification.value,
                    verification_reason=item.verification_reason,
                    advisory=item.advisory.value,
                    advisory_reason=item.advisory_reason,
                    cost=item.cost.value,
                    cost_detail=item.cost_detail,
                )
                for item in transforms
            )
            selected_count = sum(item.selected for item in leaf_views)
            visible_count = len(leaf_views)
            family_selected_count += selected_count
            family_visible_count += visible_count
            projected_subfamilies.append(
                ConfigV2TransformSubfamilyView(
                    family_id=family_id,
                    subfamily_id=subfamily_id,
                    label=subfamily_label,
                    target_id=f"subfamily:{family_id}:{subfamily_id}",
                    selected_count=selected_count,
                    visible_count=visible_count,
                    check_state=_catalog_check_state(
                        selected_count=selected_count,
                        visible_count=visible_count,
                    ),
                    transforms=leaf_views,
                )
            )
        families.append(
            ConfigV2TransformFamilyView(
                family_id=family_id,
                label=str(family["label"]),
                target_id=f"family:{family_id}",
                selected_count=family_selected_count,
                visible_count=family_visible_count,
                check_state=_catalog_check_state(
                    selected_count=family_selected_count,
                    visible_count=family_visible_count,
                ),
                subfamilies=tuple(projected_subfamilies),
            )
        )
    return ConfigV2TransformCatalogView(
        pass_editor_spec=spec,
        query=normalized_query,
        selected_ids=tuple(
            transform_id
            for transform_id in all_transform_ids
            if transform_id in known_selected_ids
        ),
        all_transform_ids=all_transform_ids,
        visible_transform_ids=tuple(visible_transform_ids),
        families=tuple(families),
    )


def apply_transform_catalog_selection(
    view: ConfigV2TransformCatalogView,
    selected_ids: AbstractSet[str],
    *,
    target_id: str,
    selected: bool,
) -> tuple[str, ...]:
    """Apply one operator selection to the catalog action scope.

    ``visible`` and family/subfamily targets intentionally operate on the
    current filtered tree; ``all`` is the explicit whole-pass overflow action.
    """
    if target_id == "all":
        targets = view.all_transform_ids
    elif target_id == "visible":
        targets = view.visible_transform_ids
    elif target_id.startswith("family:"):
        family_id = target_id.removeprefix("family:")
        family = next(
            (item for item in view.families if item.family_id == family_id),
            None,
        )
        if family is None:
            raise ValueError(f"unknown visible transform family {family_id!r}")
        targets = tuple(
            transform.transform_id
            for subfamily in family.subfamilies
            for transform in subfamily.transforms
        )
    elif target_id.startswith("subfamily:"):
        subfamily = next(
            (
                item
                for family in view.families
                for item in family.subfamilies
                if item.target_id == target_id
            ),
            None,
        )
        if subfamily is None:
            raise ValueError(f"unknown visible transform subfamily {target_id!r}")
        targets = tuple(item.transform_id for item in subfamily.transforms)
    elif target_id in view.all_transform_ids:
        targets = (target_id,)
    else:
        raise ValueError(f"unknown transform catalog target {target_id!r}")

    updated = set(selected_ids).intersection(view.all_transform_ids)
    if selected:
        updated.update(targets)
    else:
        updated.difference_update(targets)
    return tuple(
        transform_id for transform_id in view.all_transform_ids if transform_id in updated
    )


def transform_option_fields(
    spec: PassEditorSpec,
    selected_ids: AbstractSet[str],
) -> tuple[FieldEditorSpec, ...]:
    """Return fixed controls for the transforms currently selected by an operator.

    A transform owns these fields, but the project document owns their full
    path.  The replacement retains the typed control and metadata while making
    its label/path unambiguous in the pass inspector.
    """
    if spec.kind is not PassEditorKind.TRANSFORM_CATALOG:
        return ()
    selected = frozenset(selected_ids)
    fields: list[FieldEditorSpec] = []
    for transform in spec.transforms:
        if transform.transform_id not in selected:
            continue
        for field in transform.option_fields:
            fields.append(
                dataclasses.replace(
                    field,
                    field_id=f"{transform.transform_id}:{field.field_id}",
                    label=f"{transform.label}: {field.label}",
                    path=("transform_options", transform.transform_id, *field.path),
                )
            )
    return tuple(fields)


def _matches_rule_query(rule: object, query: str) -> bool:
    if not query:
        return True
    fields = (
        rule.rule_id,
        rule.label,
        rule.family_id,
        rule.family_label,
        rule.subfamily_id or "",
        rule.subfamily_label or "",
        rule.description,
        rule.reference,
        rule.verification.value,
        rule.advisory.value,
        rule.cost.value,
        rule.experimental_reason,
    )
    return any(query in field.casefold() for field in fields)


def project_rule_catalog(
    spec: PassEditorSpec,
    selected_ids: AbstractSet[str],
    *,
    query: str,
) -> ConfigV2RuleCatalogView:
    """Project explicit rule metadata into a filterable family/subfamily tree."""
    if spec.kind is not PassEditorKind.RULE_CATALOG:
        raise ValueError("rule catalog projection requires a rule_catalog spec")
    normalized_query = str(query).strip().casefold()
    all_rule_ids = tuple(item.rule_id for item in spec.rules)
    known_selected_ids = frozenset(selected_ids).intersection(all_rule_ids)
    family_specs: dict[str, dict[str, object]] = {}
    visible_rule_ids: list[str] = []
    for item in spec.rules:
        if not _matches_rule_query(item, normalized_query):
            continue
        visible_rule_ids.append(item.rule_id)
        family = family_specs.setdefault(
            item.family_id,
            {"label": item.family_label, "subfamilies": {}},
        )
        subfamily_id = item.subfamily_id or "__ungrouped__"
        subfamily_label = item.subfamily_label or item.family_label
        subfamilies = family["subfamilies"]
        assert isinstance(subfamilies, dict)
        leaves = subfamilies.setdefault(subfamily_id, (subfamily_label, []))
        leaves[1].append(item)

    families: list[ConfigV2RuleFamilyView] = []
    for family_id, family in family_specs.items():
        subfamilies = family["subfamilies"]
        assert isinstance(subfamilies, dict)
        projected_subfamilies: list[ConfigV2RuleSubfamilyView] = []
        family_selected_count = 0
        family_visible_count = 0
        for subfamily_id, (subfamily_label, rules) in subfamilies.items():
            leaf_views = tuple(
                ConfigV2RuleView(
                    rule_id=item.rule_id,
                    label=item.label,
                    description=item.description,
                    reference=item.reference,
                    maturities=item.maturities,
                    selected=item.rule_id in known_selected_ids,
                    default_selected=item.default_selected,
                    experimental=item.experimental,
                    experimental_reason=item.experimental_reason,
                    verification=item.verification.value,
                    verification_reason=item.verification_reason,
                    advisory=item.advisory.value,
                    advisory_reason=item.advisory_reason,
                    cost=item.cost.value,
                    cost_detail=item.cost_detail,
                )
                for item in rules
            )
            selected_count = sum(item.selected for item in leaf_views)
            visible_count = len(leaf_views)
            family_selected_count += selected_count
            family_visible_count += visible_count
            projected_subfamilies.append(
                ConfigV2RuleSubfamilyView(
                    family_id=family_id,
                    subfamily_id=subfamily_id,
                    label=subfamily_label,
                    target_id=f"subfamily:{family_id}:{subfamily_id}",
                    selected_count=selected_count,
                    visible_count=visible_count,
                    check_state=_catalog_check_state(
                        selected_count=selected_count,
                        visible_count=visible_count,
                    ),
                    rules=leaf_views,
                )
            )
        families.append(
            ConfigV2RuleFamilyView(
                family_id=family_id,
                label=str(family["label"]),
                target_id=f"family:{family_id}",
                selected_count=family_selected_count,
                visible_count=family_visible_count,
                check_state=_catalog_check_state(
                    selected_count=family_selected_count,
                    visible_count=family_visible_count,
                ),
                subfamilies=tuple(projected_subfamilies),
            )
        )
    return ConfigV2RuleCatalogView(
        pass_editor_spec=spec,
        query=normalized_query,
        selected_ids=tuple(rule_id for rule_id in all_rule_ids if rule_id in known_selected_ids),
        all_rule_ids=all_rule_ids,
        visible_rule_ids=tuple(visible_rule_ids),
        families=tuple(families),
    )


def _registered_rule_target_ids(
    view: ConfigV2RuleCatalogView,
    target_id: str,
) -> tuple[str, ...]:
    if target_id.startswith("family:"):
        family_id = target_id.removeprefix("family:")
        targets = tuple(
            rule.rule_id
            for rule in view.pass_editor_spec.rules
            if rule.family_id == family_id
        )
    elif target_id.startswith("subfamily:"):
        family_id, separator, subfamily_id = target_id.removeprefix(
            "subfamily:"
        ).partition(":")
        targets = tuple(
            rule.rule_id
            for rule in view.pass_editor_spec.rules
            if separator
            and rule.family_id == family_id
            and (rule.subfamily_id or "__ungrouped__") == subfamily_id
        )
    else:
        raise ValueError(f"unsupported registered group target {target_id!r}")
    if not targets:
        raise ValueError(f"unknown registered rule catalog target {target_id!r}")
    return targets


def apply_rule_catalog_selection(
    view: ConfigV2RuleCatalogView,
    selected_ids: AbstractSet[str],
    *,
    target_id: str,
    selected: bool,
) -> tuple[str, ...]:
    """Apply one intentional selection to the catalog action scope."""
    if target_id == "all":
        targets = view.all_rule_ids
    elif target_id == "visible":
        targets = view.visible_rule_ids
    elif target_id.startswith(("family:", "subfamily:")):
        targets = _registered_rule_target_ids(view, target_id)
    elif target_id in view.all_rule_ids:
        targets = (target_id,)
    else:
        raise ValueError(f"unknown rule catalog target {target_id!r}")

    updated = set(selected_ids).intersection(view.all_rule_ids)
    if selected:
        updated.update(targets)
    else:
        updated.difference_update(targets)
    return tuple(rule_id for rule_id in view.all_rule_ids if rule_id in updated)


def apply_rule_catalog_selection_to_options(
    options: dict[str, object],
    spec: PassEditorSpec,
    selected_rule_ids: tuple[str, ...],
) -> dict[str, object]:
    """Write a rule selection at its pass-declared config-v2 path only."""
    if spec.kind is not PassEditorKind.RULE_CATALOG:
        raise ValueError("rule selection requires a rule_catalog spec")
    known_rule_ids = {item.rule_id for item in spec.rules}
    unknown_rule_ids = set(selected_rule_ids).difference(known_rule_ids)
    if unknown_rule_ids:
        raise ValueError(
            "rule selection contains unknown rule IDs: "
            + ", ".join(sorted(unknown_rule_ids))
        )
    updated = copy.deepcopy(options)
    target: dict[str, object] = updated
    for segment in spec.rule_option_path[:-1]:
        existing = target.get(segment)
        if existing is None:
            child: dict[str, object] = {}
            target[segment] = child
            target = child
        elif isinstance(existing, dict):
            target = existing
        else:
            raise ValueError(
                f"rule option path segment {segment!r} must contain an object"
            )
    target[spec.rule_option_path[-1]] = list(selected_rule_ids)
    return updated


def typed_field_option_value(
    options: dict[str, object],
    field: FieldEditorSpec,
) -> object:
    """Read a declared field path without treating absent values as data."""

    value: object = options
    for item in field.path:
        if not isinstance(value, dict) or item not in value:
            return copy.deepcopy(field.default) if field.has_default else None
        value = value[item]
    return value


def _normalize_typed_field_value(field: FieldEditorSpec, value: object) -> object:
    if field.control is FieldControlKind.BOOLEAN:
        return bool(value)
    if field.control is FieldControlKind.INTEGER:
        if isinstance(value, bool):
            raise ValueError(f"{field.label} must be an integer")
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field.label} must be an integer") from exc
        if field.minimum is not None and number < field.minimum:
            raise ValueError(f"{field.label} must be at least {field.minimum}")
        if field.maximum is not None and number > field.maximum:
            raise ValueError(f"{field.label} must be at most {field.maximum}")
        return number
    if field.control is FieldControlKind.ENUM:
        if value not in field.choices:
            raise ValueError(f"{field.label} must be one of the declared choices")
        return str(value)
    if field.control is FieldControlKind.TEXT:
        return str(value)
    if field.control is FieldControlKind.STRING_LIST:
        return [
            item.strip() for item in str(value).split(",") if item.strip()
        ]
    raise ValueError(f"{field.label} has an unsupported editor control")


def apply_typed_field_option(
    options: dict[str, object],
    field: FieldEditorSpec,
    value: object,
) -> dict[str, object]:
    """Apply one declared typed value while preserving all other options."""

    updated = copy.deepcopy(options)
    target = updated
    for item in field.path[:-1]:
        child = target.get(item)
        if not isinstance(child, dict):
            child = {}
            target[item] = child
        target = child
    target[field.path[-1]] = _normalize_typed_field_value(field, value)
    return updated


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


def project_pass_inspector_layout(
    spec: PassEditorSpec,
    *,
    rule_catalog: ConfigV2RuleCatalogView | None,
    transform_catalog: ConfigV2TransformCatalogView | None,
    selected_transform_ids: AbstractSet[str],
) -> ConfigV2PassInspectorLayoutView:
    option_fields = tuple(spec.fields) + transform_option_fields(
        spec, selected_transform_ids
    )
    if rule_catalog is not None:
        primary = ConfigV2InspectorPrimarySection.RULES
    elif transform_catalog is not None:
        primary = ConfigV2InspectorPrimarySection.TRANSFORMS
    elif option_fields:
        primary = ConfigV2InspectorPrimarySection.OPTIONS
    else:
        primary = ConfigV2InspectorPrimarySection.NONE
    return ConfigV2PassInspectorLayoutView(
        primary_section=primary,
        show_rule_catalog=rule_catalog is not None,
        show_transform_catalog=transform_catalog is not None,
        show_options=bool(option_fields),
        show_summary_message=primary is ConfigV2InspectorPrimarySection.NONE,
        summary_message=(
            "This pass exposes no editable controls."
            if primary is ConfigV2InspectorPrimarySection.NONE
            else ""
        ),
        can_view_contract=True,
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
        selected_transform_ids = _selected_transform_ids(options)
        selected_rule_ids = _selected_rule_ids(options, catalog_entry.editor_spec)
        transform_catalog = (
            project_transform_catalog(
                catalog_entry.editor_spec,
                selected_transform_ids or frozenset(),
                query="",
            )
            if catalog_entry.editor_spec.kind is PassEditorKind.TRANSFORM_CATALOG
            else None
        )
        rule_catalog = (
            project_rule_catalog(
                catalog_entry.editor_spec,
                selected_rule_ids or frozenset(),
                query="",
            )
            if catalog_entry.editor_spec.kind is PassEditorKind.RULE_CATALOG
            else None
        )
        purpose = _PASS_PURPOSES.get(pass_id, "Registered config-v2 pass.")
        overview_rows.append(
            ConfigV2PipelineRow(
                index=index,
                pass_id=pass_id,
                display_name=catalog_entry.display_name,
                purpose=purpose,
                runs_during=catalog_entry.maturity,
                selected_transform_summary=_selection_summary(catalog_entry, options),
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
                transform_catalog=transform_catalog,
                rule_catalog=rule_catalog,
                layout=project_pass_inspector_layout(
                    catalog_entry.editor_spec,
                    rule_catalog=rule_catalog,
                    transform_catalog=transform_catalog,
                    selected_transform_ids=(selected_transform_ids or frozenset()),
                ),
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
    "ConfigV2InspectorPrimarySection",
    "ConfigV2PassInspectorLayoutView",
    "ConfigV2PassInspectorView",
    "ConfigV2PipelineRow",
    "ConfigV2PipelineOverview",
    "ConfigV2RawDocumentView",
    "ConfigV2RuleCatalogView",
    "ConfigV2RuleFamilyView",
    "ConfigV2RuleSubfamilyView",
    "ConfigV2RuleView",
    "ConfigV2RoutingView",
    "ConfigV2SerializerRow",
    "ConfigV2TransformCatalogView",
    "ConfigV2TransformFamilyView",
    "ConfigV2TransformSubfamilyView",
    "ConfigV2TransformView",
    "apply_typed_field_option",
    "apply_rule_catalog_selection",
    "apply_rule_catalog_selection_to_options",
    "apply_transform_catalog_selection",
    "config_v2_action_states",
    "project_config_v2_document",
    "project_config_v2_editor_view",
    "project_pass_inspector_layout",
    "project_rule_catalog",
    "project_transform_catalog",
    "project_serializer_rows",
    "typed_field_option_value",
    "transform_option_fields",
]
