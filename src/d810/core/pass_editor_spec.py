"""Closed, portable presentation contracts for config-v2 pass editors."""

from __future__ import annotations

import dataclasses
import enum
from copy import deepcopy


_UNSET = object()


class PassEditorKind(str, enum.Enum):
    """The fixed set of editor renderers supported by config-v2."""

    SUMMARY = "summary"
    FIELDS = "fields"
    TRANSFORM_CATALOG = "transform_catalog"
    RULE_CATALOG = "rule_catalog"


class FieldControlKind(str, enum.Enum):
    """The fixed scalar form controls supported by ``fields`` editors."""

    BOOLEAN = "boolean"
    INTEGER = "integer"
    ENUM = "enum"
    TEXT = "text"
    STRING_LIST = "string_list"


class AdvisoryTone(str, enum.Enum):
    """Operator-facing advisory styling without changing selection authority."""

    NONE = "none"
    INFO = "info"
    WARNING = "warning"
    DANGER = "danger"


class VerificationStatus(str, enum.Enum):
    """How a transform's semantic claim is established."""

    VERIFIED = "verified"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    KNOWN_INCORRECT = "known_incorrect"


class TransformCost(str, enum.Enum):
    """Known proof or measured execution-cost classifications."""

    UNKNOWN = "unknown"
    PROOF_EXPENSIVE = "proof_expensive"
    RUNTIME_LOW = "runtime_low"
    RUNTIME_MODERATE = "runtime_moderate"
    RUNTIME_HIGH = "runtime_high"


def _required(value: str, *, name: str) -> str:
    rendered = str(value).strip()
    if not rendered:
        raise ValueError(f"{name} must be non-empty")
    return rendered


@dataclasses.dataclass(frozen=True, slots=True)
class FieldEditorSpec:
    """One approved control for a pass-owned typed options form."""

    field_id: str
    label: str
    path: tuple[str, ...]
    control: FieldControlKind
    description: str = ""
    default: object = dataclasses.field(default=_UNSET, repr=False)
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    experimental: bool = False
    experimental_reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "field_id", _required(self.field_id, name="field_id"))
        object.__setattr__(self, "label", _required(self.label, name="label"))
        normalized_path = tuple(_required(item, name="field path") for item in self.path)
        if not normalized_path:
            raise ValueError("field path must be non-empty")
        object.__setattr__(self, "path", normalized_path)
        if not isinstance(self.control, FieldControlKind):
            raise ValueError("control must be a FieldControlKind")
        if self.control is FieldControlKind.ENUM and not self.choices:
            raise ValueError("enum field choices must be non-empty")
        # STRING_LIST may offer a vocabulary too: "pick several of these" is a
        # list with choices. Without it the only option is a free-text list,
        # which is how every jump-fixer rule stayed undiscoverable in the UI.
        if (
            self.control
            not in (FieldControlKind.ENUM, FieldControlKind.STRING_LIST)
            and self.choices
        ):
            raise ValueError("only enum and string-list fields may declare choices")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("field minimum must not exceed maximum")
        if not isinstance(self.experimental, bool):
            raise ValueError("experimental must be a bool")
        if self.experimental:
            object.__setattr__(
                self,
                "experimental_reason",
                _required(self.experimental_reason, name="experimental_reason"),
            )

    @property
    def has_default(self) -> bool:
        """Whether this public control declares its runtime-effective default."""
        return self.default is not _UNSET


@dataclasses.dataclass(frozen=True, slots=True)
class RuleEditorSpec:
    """Explicit public metadata for one individually selectable rule."""

    rule_id: str
    label: str
    family_id: str
    family_label: str
    subfamily_id: str | None
    subfamily_label: str | None
    description: str
    reference: str = ""
    maturities: tuple[str, ...] = ("any",)
    default_selected: bool = False
    experimental: bool = False
    experimental_reason: str = ""
    advisory: AdvisoryTone = AdvisoryTone.NONE
    advisory_reason: str = ""
    verification: VerificationStatus = VerificationStatus.UNAVAILABLE
    verification_reason: str = ""
    cost: TransformCost = TransformCost.UNKNOWN
    cost_detail: str = ""

    def __post_init__(self) -> None:
        for name in (
            "rule_id",
            "label",
            "family_id",
            "family_label",
            "description",
        ):
            object.__setattr__(self, name, _required(getattr(self, name), name=name))
        if (self.subfamily_id is None) != (self.subfamily_label is None):
            raise ValueError("subfamily_id and subfamily_label must be provided together")
        if self.subfamily_id is not None:
            object.__setattr__(
                self,
                "subfamily_id",
                _required(self.subfamily_id, name="subfamily_id"),
            )
            object.__setattr__(
                self,
                "subfamily_label",
                _required(self.subfamily_label, name="subfamily_label"),
            )
        normalized_maturities = tuple(
            _required(item, name="maturity") for item in self.maturities
        )
        if not normalized_maturities:
            raise ValueError("maturities must be non-empty")
        object.__setattr__(self, "maturities", normalized_maturities)
        if not isinstance(self.default_selected, bool):
            raise ValueError("default_selected must be a bool")
        if not isinstance(self.experimental, bool):
            raise ValueError("experimental must be a bool")
        if self.experimental:
            object.__setattr__(
                self,
                "experimental_reason",
                _required(self.experimental_reason, name="experimental_reason"),
            )
        if not isinstance(self.advisory, AdvisoryTone):
            raise ValueError("advisory must be an AdvisoryTone")
        if self.advisory is not AdvisoryTone.NONE:
            object.__setattr__(
                self,
                "advisory_reason",
                _required(self.advisory_reason, name="advisory_reason"),
            )
        if not isinstance(self.verification, VerificationStatus):
            raise ValueError("verification must be a VerificationStatus")
        if self.verification is not VerificationStatus.VERIFIED:
            object.__setattr__(
                self,
                "verification_reason",
                _required(self.verification_reason, name="verification_reason"),
            )
        if not isinstance(self.cost, TransformCost):
            raise ValueError("cost must be a TransformCost")
        if self.cost in {
            TransformCost.RUNTIME_LOW,
            TransformCost.RUNTIME_MODERATE,
            TransformCost.RUNTIME_HIGH,
        }:
            object.__setattr__(
                self,
                "cost_detail",
                _required(self.cost_detail, name="cost_detail"),
            )


@dataclasses.dataclass(frozen=True, slots=True)
class TransformEditorSpec:
    """Explicit catalog metadata for one individually selectable transform."""

    transform_id: str
    label: str
    family_id: str
    family_label: str
    subfamily_id: str | None
    subfamily_label: str | None
    description: str
    reference: str
    maturities: tuple[str, ...]
    default_selected: bool
    verification: VerificationStatus
    verification_reason: str
    advisory: AdvisoryTone
    advisory_reason: str
    cost: TransformCost
    cost_detail: str = ""

    def __post_init__(self) -> None:
        for name in (
            "transform_id",
            "label",
            "family_id",
            "family_label",
            "description",
            "reference",
            "verification_reason",
        ):
            object.__setattr__(
                self,
                name,
                _required(getattr(self, name), name=name),
            )
        if (self.subfamily_id is None) != (self.subfamily_label is None):
            raise ValueError("subfamily_id and subfamily_label must be provided together")
        if self.subfamily_id is not None:
            object.__setattr__(
                self,
                "subfamily_id",
                _required(self.subfamily_id, name="subfamily_id"),
            )
            object.__setattr__(
                self,
                "subfamily_label",
                _required(self.subfamily_label, name="subfamily_label"),
            )
        normalized_maturities = tuple(
            _required(item, name="maturity") for item in self.maturities
        )
        if not normalized_maturities:
            raise ValueError("maturities must be non-empty")
        object.__setattr__(self, "maturities", normalized_maturities)
        if not isinstance(self.default_selected, bool):
            raise ValueError("default_selected must be a bool")
        if not isinstance(self.verification, VerificationStatus):
            raise ValueError("verification must be a VerificationStatus")
        if not isinstance(self.advisory, AdvisoryTone):
            raise ValueError("advisory must be an AdvisoryTone")
        if not isinstance(self.cost, TransformCost):
            raise ValueError("cost must be a TransformCost")
        if self.advisory is not AdvisoryTone.NONE:
            object.__setattr__(
                self,
                "advisory_reason",
                _required(self.advisory_reason, name="advisory_reason"),
            )
        if self.cost in {
            TransformCost.RUNTIME_LOW,
            TransformCost.RUNTIME_MODERATE,
            TransformCost.RUNTIME_HIGH,
        }:
            object.__setattr__(
                self,
                "cost_detail",
                _required(self.cost_detail, name="cost_detail"),
            )


@dataclasses.dataclass(frozen=True, slots=True)
class PassEditorSpec:
    """A pass-owned contract for one fixed config-v2 editor renderer."""

    kind: PassEditorKind
    fields: tuple[FieldEditorSpec, ...] = ()
    transforms: tuple[TransformEditorSpec, ...] = ()
    rules: tuple[RuleEditorSpec, ...] = ()
    rule_option_path: tuple[str, ...] = ("enabled_rules",)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PassEditorKind):
            raise ValueError("kind must be a PassEditorKind")
        fields = tuple(self.fields)
        transforms = tuple(self.transforms)
        rules = tuple(self.rules)
        rule_option_path = tuple(
            _required(item, name="rule option path") for item in self.rule_option_path
        )
        if not rule_option_path:
            raise ValueError("rule option path must be non-empty")
        field_ids = tuple(item.field_id for item in fields)
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("editor has duplicate field_id")
        field_paths = tuple(item.path for item in fields)
        if len(field_paths) != len(set(field_paths)):
            raise ValueError("editor has duplicate field path")
        if self.kind is PassEditorKind.SUMMARY:
            if fields or transforms or rules:
                raise ValueError("summary editor must not declare fields, transforms, or rules")
        elif self.kind is PassEditorKind.FIELDS:
            if not fields or transforms or rules:
                raise ValueError("fields editor requires fields and no transforms or rules")
        elif self.kind is PassEditorKind.TRANSFORM_CATALOG:
            if fields or rules or not transforms:
                raise ValueError(
                    "transform catalog requires transforms and no fields or rules"
                )
            transform_ids = tuple(item.transform_id for item in transforms)
            if len(transform_ids) != len(set(transform_ids)):
                raise ValueError("transform catalog has duplicate transform_id")
        elif self.kind is PassEditorKind.RULE_CATALOG:
            if transforms or not rules:
                raise ValueError("rule catalog requires rules and no transforms")
            rule_ids = tuple(item.rule_id for item in rules)
            if len(rule_ids) != len(set(rule_ids)):
                raise ValueError("rule catalog has duplicate rule_id")
            if rule_option_path in field_paths:
                raise ValueError("rule option path must not duplicate a field path")
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "transforms", transforms)
        object.__setattr__(self, "rules", rules)
        object.__setattr__(self, "rule_option_path", rule_option_path)

    @classmethod
    def summary(cls) -> PassEditorSpec:
        return cls(PassEditorKind.SUMMARY)

    @classmethod
    def fields_editor(
        cls,
        fields: tuple[FieldEditorSpec, ...],
    ) -> PassEditorSpec:
        return cls(PassEditorKind.FIELDS, fields=fields)

    @classmethod
    def transform_catalog(
        cls,
        transforms: tuple[TransformEditorSpec, ...],
    ) -> PassEditorSpec:
        return cls(PassEditorKind.TRANSFORM_CATALOG, transforms=transforms)

    @classmethod
    def rule_catalog(
        cls,
        rules: tuple[RuleEditorSpec, ...],
        *,
        fields: tuple[FieldEditorSpec, ...] = (),
        option_path: tuple[str, ...] = ("enabled_rules",),
    ) -> PassEditorSpec:
        return cls(
            PassEditorKind.RULE_CATALOG,
            fields=fields,
            rules=rules,
            rule_option_path=option_path,
        )

    def option_paths(self) -> tuple[tuple[str, ...], ...]:
        """Return every public config option path this fixed editor can render."""
        field_paths = tuple(field.path for field in self.fields)
        if self.kind is PassEditorKind.SUMMARY:
            return ()
        if self.kind is PassEditorKind.FIELDS:
            return field_paths
        if self.kind is PassEditorKind.TRANSFORM_CATALOG:
            return (("transforms",), ("transform_options",))
        return (*field_paths, self.rule_option_path)

    def default_options(self) -> dict[str, object]:
        """Return the complete public default configuration rendered by this editor."""
        if self.kind is PassEditorKind.SUMMARY:
            return {}
        if self.kind is PassEditorKind.TRANSFORM_CATALOG:
            return {
                "transforms": [
                    item.transform_id for item in self.transforms if item.default_selected
                ],
                "transform_options": {},
            }
        options = _field_defaults(self.fields)
        if self.kind is PassEditorKind.RULE_CATALOG:
            _set_path(
                options,
                self.rule_option_path,
                [item.rule_id for item in self.rules if item.default_selected],
            )
        return options


def _set_path(options: dict[str, object], path: tuple[str, ...], value: object) -> None:
    cursor: dict[str, object] = options
    for segment in path[:-1]:
        nested = cursor.setdefault(segment, {})
        if not isinstance(nested, dict):
            raise ValueError(f"editor field path collides at {segment!r}")
        cursor = nested
    cursor[path[-1]] = deepcopy(value)


def _field_defaults(fields: tuple[FieldEditorSpec, ...]) -> dict[str, object]:
    options: dict[str, object] = {}
    for field in fields:
        if not field.has_default:
            raise ValueError(
                f"field {field.field_id!r} must declare a runtime-effective default"
            )
        _set_path(options, field.path, field.default)
    return options


__all__ = [
    "AdvisoryTone",
    "FieldControlKind",
    "FieldEditorSpec",
    "PassEditorKind",
    "PassEditorSpec",
    "RuleEditorSpec",
    "TransformCost",
    "TransformEditorSpec",
    "VerificationStatus",
]
