"""Portable contracts and compiler for the constant-simplification bundle.

This module deliberately contains no IDA imports.  The registration descriptors
are the authority for the maturities a live implementation supports; this
module only validates project data and compiles it into an immutable schedule.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from d810.core.execution_scope import ExecutionPipeline
from d810.core.pass_ids import PassId
from d810.core.typing import TYPE_CHECKING
from d810.ir.maturity import IRMaturity, IR_MATURITY_ORDER
from d810.passes.execution_stages import StageLifecycleDomain
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError

if TYPE_CHECKING:
    from d810.passes.execution_stages import ExecutionStageDescriptor


CONSTANT_SIMPLIFICATION_PASS_ID = PassId.CONSTANT_SIMPLIFICATION
CONSTANT_STAGE_IDS = (
    "fold-readonly-data",
    "fold-constant-subtree",
    "forward-constants",
)

STRICT_MEMORY_POLICY = "strict"
AGGRESSIVE_MEMORY_POLICY = "aggressive_no_direct_writes"
_MEMORY_POLICIES = frozenset({STRICT_MEMORY_POLICY, AGGRESSIVE_MEMORY_POLICY})
_LEGACY_OPTION_NAMES = frozenset(
    {
        "memory_policy",
        "rva_guard",
        "allow_executable_readonly",
        "persist_global_const_annotations",
    }
)
_CANONICAL_TOP_LEVEL_NAMES = frozenset({"preparation", "stages"})
_MISSING = object()

# The provider vocabulary is kept here as a portable spelling table.  The
# values are the same vocabulary used by the Hex-Rays adapter, but no adapter
# is imported by the compiler.
_PROVIDER_PREFIX = "MMAT" + "_"
_PROVIDER_BY_IR = MappingProxyType(
    {
        IRMaturity.LIFTED: f"{_PROVIDER_PREFIX}GENERATED",
        IRMaturity.CANONICAL: f"{_PROVIDER_PREFIX}PREOPTIMIZED",
        IRMaturity.LOCAL_OPTIMIZED: f"{_PROVIDER_PREFIX}LOCOPT",
        IRMaturity.CALL_MODELED: f"{_PROVIDER_PREFIX}CALLS",
        IRMaturity.GLOBAL_ANALYZED: f"{_PROVIDER_PREFIX}GLBOPT1",
        IRMaturity.GLOBAL_OPTIMIZED: f"{_PROVIDER_PREFIX}GLBOPT2",
        IRMaturity.STRUCTURED: f"{_PROVIDER_PREFIX}GLBOPT3",
        IRMaturity.VARIABLE_RECOVERED: f"{_PROVIDER_PREFIX}LVARS",
    }
)
_IR_BY_PROVIDER = {provider: maturity for maturity, provider in _PROVIDER_BY_IR.items()}
_IR_BY_NAME = {maturity.name: maturity for maturity in IRMaturity}


def _freeze_value(value: object) -> object:
    """Recursively freeze JSON-like option metadata."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    return value


def _ordered_maturities(values: Sequence[IRMaturity]) -> tuple[IRMaturity, ...]:
    return tuple(
        maturity
        for maturity in IR_MATURITY_ORDER
        if maturity in values
    )


def _validate_maturity_tuple(
    values: object,
    field_name: str,
) -> tuple[IRMaturity, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"{field_name} must be a tuple of IRMaturity values")
    if any(not isinstance(value, IRMaturity) for value in values):
        raise TypeError(f"{field_name} must contain only IRMaturity values")
    if len(set(values)) != len(values):
        raise ValueError(f"{field_name} must not contain duplicates")
    if values != _ordered_maturities(values):
        raise ValueError(f"{field_name} must follow IR_MATURITY_ORDER")
    return values


@dataclass(frozen=True, slots=True)
class ConstantPreparationOptions:
    """Pure options for reversible pre-Hex-Rays const preparation."""

    enabled: bool = False
    discover_bounded_tables: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("preparation.enabled must be a boolean")
        if not isinstance(self.discover_bounded_tables, bool):
            raise TypeError("preparation.discover_bounded_tables must be a boolean")


@dataclass(frozen=True, slots=True)
class ConstantMutationStageOptions:
    """Parsed options for one mutation stage before gate intersection."""

    enabled: bool
    requested_maturities: tuple[IRMaturity, ...]
    stage_options: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("stage.enabled must be a boolean")
        object.__setattr__(
            self,
            "requested_maturities",
            _validate_maturity_tuple(
                self.requested_maturities,
                "stage.requested_maturities",
            ),
        )
        if not isinstance(self.stage_options, Mapping):
            raise TypeError("stage.stage_options must be a mapping")
        object.__setattr__(self, "stage_options", _freeze_value(self.stage_options))


@dataclass(frozen=True, slots=True)
class CompiledConstantStage:
    """One immutable, validated stage in the effective schedule."""

    pass_id: str
    stage_id: str
    lifecycle_domain: StageLifecycleDomain
    pipeline: ExecutionPipeline | None
    implementation_name: str | None
    enabled: bool
    supported_maturities: tuple[IRMaturity, ...]
    requested_maturities: tuple[IRMaturity, ...]
    pass_maturity_gates: tuple[IRMaturity, ...]
    effective_maturities: tuple[IRMaturity, ...]
    runtime_order: int | None
    inactive_reason: str | None
    options: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.pass_id, str) or not self.pass_id:
            raise TypeError("compiled stage pass_id must be a non-empty string")
        if not isinstance(self.stage_id, str) or not self.stage_id:
            raise TypeError("compiled stage stage_id must be a non-empty string")
        if not isinstance(self.lifecycle_domain, StageLifecycleDomain):
            raise TypeError("compiled stage lifecycle_domain must be typed")
        if self.pipeline is not None and not isinstance(self.pipeline, ExecutionPipeline):
            raise TypeError("compiled stage pipeline must be typed or None")
        if self.implementation_name is not None and not isinstance(
            self.implementation_name, str
        ):
            raise TypeError("compiled stage implementation_name must be a string or None")
        if not isinstance(self.enabled, bool):
            raise TypeError("compiled stage enabled must be a boolean")
        for field_name in (
            "supported_maturities",
            "requested_maturities",
            "pass_maturity_gates",
            "effective_maturities",
        ):
            object.__setattr__(
                self,
                field_name,
                _validate_maturity_tuple(getattr(self, field_name), field_name),
            )
        if self.runtime_order is not None and (
            isinstance(self.runtime_order, bool)
            or not isinstance(self.runtime_order, int)
            or self.runtime_order < 0
        ):
            raise TypeError("compiled stage runtime_order must be a non-negative integer or None")
        if self.inactive_reason is not None and not isinstance(self.inactive_reason, str):
            raise TypeError("compiled stage inactive_reason must be a string or None")
        if not isinstance(self.options, Mapping):
            raise TypeError("compiled stage options must be a mapping")
        object.__setattr__(self, "options", _freeze_value(self.options))


@dataclass(frozen=True, slots=True)
class CompiledConstantSimplificationSchedule:
    """Immutable canonical schedule shared by runtime and Workbench."""

    preparation: ConstantPreparationOptions
    stages: tuple[CompiledConstantStage, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.preparation, ConstantPreparationOptions):
            raise TypeError("schedule.preparation must be ConstantPreparationOptions")
        if not isinstance(self.stages, tuple) or not all(
            isinstance(stage, CompiledConstantStage) for stage in self.stages
        ):
            raise TypeError("schedule.stages must be a tuple of compiled stages")

    def stage(self, stage_id: str) -> CompiledConstantStage:
        """Return one stage by its stable public identity."""

        for stage in self.stages:
            if stage.stage_id == stage_id:
                return stage
        raise KeyError(stage_id)

    # These projections keep older callers source-compatible while the live
    # bridge migrates to the schedule object.  They are deliberately read-only.
    @property
    def memory_policy(self) -> str:
        return str(self.stage("fold-readonly-data").options["memory_policy"])

    @property
    def rva_guard(self) -> bool:
        return bool(self.stage("fold-readonly-data").options["rva_guard"])

    @property
    def allow_executable_readonly(self) -> bool:
        return bool(self.stage("fold-readonly-data").options["allow_executable_readonly"])

    @property
    def persist_global_const_annotations(self) -> bool:
        return self.preparation.enabled


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PipelineConfigError(f"{field_name} must be a mapping")
    return value


def _parse_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PipelineConfigError(f"{field_name} must be boolean")
    return value


def _normalize_maturity(value: object, field_name: str) -> IRMaturity:
    if isinstance(value, bool) or not isinstance(value, (str, IRMaturity)):
        raise PipelineConfigError(
            f"{field_name} contains invalid maturity {value!r}; expected a name"
        )
    if isinstance(value, IRMaturity):
        return value
    raw = value.strip()
    if not raw:
        raise PipelineConfigError(f"{field_name} contains an empty maturity")
    upper = raw.upper()
    if upper in _IR_BY_PROVIDER:
        return _IR_BY_PROVIDER[upper]
    if upper in _IR_BY_NAME:
        return _IR_BY_NAME[upper]
    try:
        return IRMaturity(raw)
    except ValueError as exc:
        raise PipelineConfigError(
            f"{field_name} contains unknown maturity {value!r}"
        ) from exc


def _parse_maturities(
    value: object,
    field_name: str,
    default: tuple[IRMaturity, ...],
) -> tuple[IRMaturity, ...]:
    if value is _MISSING:
        return default
    if not isinstance(value, list):
        raise PipelineConfigError(f"{field_name} must be a list of maturities")
    values = {
        _normalize_maturity(item, field_name)
        for item in value
    }
    return _ordered_maturities(tuple(values))


def _supported_names(values: Sequence[IRMaturity]) -> str:
    return ", ".join(value.name for value in values) or "<none>"


def _validate_descriptors(
    descriptors: Sequence["ExecutionStageDescriptor"],
) -> tuple["ExecutionStageDescriptor", ...]:
    ordered = tuple(descriptors)
    by_id = {descriptor.stage_id: descriptor for descriptor in ordered}
    if len(by_id) != len(ordered):
        raise PipelineConfigError(
            "constant-simplification registration contains duplicate stage IDs"
        )
    missing = tuple(stage_id for stage_id in CONSTANT_STAGE_IDS if stage_id not in by_id)
    extra = tuple(stage_id for stage_id in by_id if stage_id not in CONSTANT_STAGE_IDS)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {list(missing)}")
        if extra:
            details.append(f"unknown {list(extra)}")
        raise PipelineConfigError(
            "constant-simplification registration must declare exactly the three "
            f"public stages ({'; '.join(details)})"
        )
    for descriptor in ordered:
        if str(descriptor.pass_id) != str(CONSTANT_SIMPLIFICATION_PASS_ID):
            raise PipelineConfigError(
                "constant-simplification stage registration has the wrong pass id: "
                f"{descriptor.pass_id!r}"
            )
        if descriptor.lifecycle_domain is not StageLifecycleDomain.MICROCODE:
            raise PipelineConfigError(
                "constant-simplification mutation stages must use the microcode domain"
            )
        if not descriptor.supported_maturities:
            raise PipelineConfigError(
                f"constant-simplification stage {descriptor.stage_id} has no supported maturities"
            )
    # Preserve the declaration order supplied by the registration.  The
    # constant bundle declares instruction stages before flow stages, and the
    # runtime order field is defined in terms of that declaration order.
    return ordered


def _parse_preparation(options: Mapping[str, object]) -> ConstantPreparationOptions:
    preparation = _mapping(options.get("preparation", {}), "preparation")
    unknown = sorted(set(preparation) - {"global_const_types"})
    if unknown:
        raise PipelineConfigError(
            f"constant-simplification preparation has unknown option(s): {unknown}"
        )
    global_types = _mapping(
        preparation.get("global_const_types", {}),
        "preparation.global_const_types",
    )
    unknown = sorted(set(global_types) - {"enabled", "discover_bounded_tables"})
    if unknown:
        raise PipelineConfigError(
            "constant-simplification preparation.global_const_types has unknown "
            f"option(s): {unknown}"
        )
    return ConstantPreparationOptions(
        enabled=_parse_bool(
            global_types.get("enabled", False),
            "preparation.global_const_types.enabled",
        ),
        discover_bounded_tables=_parse_bool(
            global_types.get("discover_bounded_tables", True),
            "preparation.global_const_types.discover_bounded_tables",
        ),
    )


def _parse_stage_options(
    stage_id: str,
    payload: object,
    supported: tuple[IRMaturity, ...],
) -> ConstantMutationStageOptions:
    data = _mapping(payload, f"stages.{stage_id}")
    allowed = {"enabled", "maturities"}
    if stage_id == "fold-readonly-data":
        allowed.update({"memory_policy", "rva_guard", "allow_executable_readonly"})
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PipelineConfigError(
            f"constant-simplification stage {stage_id} has unknown option(s): {unknown}"
        )

    enabled = _parse_bool(data.get("enabled", True), f"stages.{stage_id}.enabled")
    requested = _parse_maturities(
        data.get("maturities", _MISSING),
        f"stages.{stage_id}.maturities",
        supported,
    )
    stage_options: dict[str, object] = {}
    if stage_id == "fold-readonly-data":
        memory_policy = data.get("memory_policy", STRICT_MEMORY_POLICY)
        if not isinstance(memory_policy, str) or memory_policy not in _MEMORY_POLICIES:
            raise PipelineConfigError(
                "constant-simplification stage fold-readonly-data "
                "memory_policy must be one of: "
                f"{', '.join(sorted(_MEMORY_POLICIES))}"
            )
        stage_options = {
            "memory_policy": memory_policy,
            "rva_guard": _parse_bool(
                data.get("rva_guard", True),
                "stages.fold-readonly-data.rva_guard",
            ),
            "allow_executable_readonly": _parse_bool(
                data.get("allow_executable_readonly", False),
                "stages.fold-readonly-data.allow_executable_readonly",
            ),
        }
    return ConstantMutationStageOptions(
        enabled=enabled,
        requested_maturities=requested,
        stage_options=stage_options,
    )


def compile_constant_simplification_schedule(
    config: PipelineConfig,
    stage_descriptors: Sequence["ExecutionStageDescriptor"] | None = None,
) -> CompiledConstantSimplificationSchedule:
    """Validate and compile canonical or legacy constant-stage options."""

    if config.pass_id != CONSTANT_SIMPLIFICATION_PASS_ID:
        raise PipelineConfigError(
            f"expected {CONSTANT_SIMPLIFICATION_PASS_ID!r}, got {config.pass_id!r}"
        )
    if stage_descriptors is None:
        # Lazy import keeps this portable module independent of the pass module
        # at import time while retaining one registration-owned support table.
        from d810.passes.constant_simplification import (
            constant_simplification_stage_descriptors,
        )

        stage_descriptors = constant_simplification_stage_descriptors()
    descriptors = _validate_descriptors(stage_descriptors)

    options = _mapping(config.options, "constant-simplification options")
    keys = set(options)
    canonical_keys = keys.intersection(_CANONICAL_TOP_LEVEL_NAMES)
    legacy_keys = keys.intersection(_LEGACY_OPTION_NAMES)
    if canonical_keys and legacy_keys:
        raise PipelineConfigError(
            "constant-simplification cannot mix legacy options with canonical "
            "preparation/stages"
        )

    if canonical_keys:
        unknown = sorted(keys - _CANONICAL_TOP_LEVEL_NAMES)
        if unknown:
            raise PipelineConfigError(
                "constant-simplification canonical options have unknown "
                f"key(s): {unknown}"
            )
        preparation = _parse_preparation(options)
        stages_payload = _mapping(options.get("stages", {}), "stages")
        unknown_stages = sorted(set(stages_payload) - set(CONSTANT_STAGE_IDS))
        if unknown_stages:
            raise PipelineConfigError(
                "constant-simplification stages has unknown stage(s): "
                f"{unknown_stages}"
            )
        parsed = {
            descriptor.stage_id: _parse_stage_options(
                descriptor.stage_id,
                stages_payload.get(descriptor.stage_id, {}),
                tuple(descriptor.supported_maturities),
            )
            for descriptor in descriptors
        }
    else:
        unknown = sorted(keys - _LEGACY_OPTION_NAMES)
        if unknown:
            raise PipelineConfigError(
                "constant-simplification has unknown options: " f"{unknown}"
            )
        memory_policy = options.get("memory_policy", STRICT_MEMORY_POLICY)
        rva_guard = options.get("rva_guard", True)
        allow_executable_readonly = options.get("allow_executable_readonly", False)
        persist = options.get("persist_global_const_annotations", False)
        preparation = ConstantPreparationOptions(
            enabled=_parse_bool(
                persist,
                "persist_global_const_annotations",
            ),
            discover_bounded_tables=True,
        )
        readonly_data = {
            "enabled": True,
            "memory_policy": memory_policy,
            "rva_guard": rva_guard,
            "allow_executable_readonly": allow_executable_readonly,
        }
        parsed = {
            descriptor.stage_id: _parse_stage_options(
                descriptor.stage_id,
                readonly_data if descriptor.stage_id == "fold-readonly-data" else {},
                tuple(descriptor.supported_maturities),
            )
            for descriptor in descriptors
        }

    raw_gates = getattr(config, "maturity_gates", frozenset())
    if not isinstance(raw_gates, (set, frozenset, tuple, list)):
        raise PipelineConfigError("constant-simplification maturity_gates must be a set")
    if any(not isinstance(value, IRMaturity) for value in raw_gates):
        raise PipelineConfigError(
            "constant-simplification maturity_gates contains invalid values"
        )
    try:
        pass_gates = _ordered_maturities(tuple(set(raw_gates)))
    except (TypeError, ValueError) as exc:
        raise PipelineConfigError(
            "constant-simplification maturity_gates contains invalid values"
        ) from exc
    pass_gate_set = set(pass_gates)

    pipeline_orders: dict[ExecutionPipeline, int] = {}
    compiled: list[CompiledConstantStage] = []
    for descriptor in descriptors:
        stage_options = parsed[descriptor.stage_id]
        supported = tuple(descriptor.supported_maturities)
        unsupported = tuple(
            maturity
            for maturity in stage_options.requested_maturities
            if maturity not in supported
        )
        if unsupported:
            offending = unsupported[0]
            raise PipelineConfigError(
                f"constant-simplification stage {descriptor.stage_id} does not support "
                f"{offending.name}; supported: {_supported_names(supported)}"
            )
        effective = (
            tuple(
                maturity
                for maturity in supported
                if maturity in stage_options.requested_maturities
                and (not pass_gates or maturity in pass_gate_set)
            )
            if stage_options.enabled
            else ()
        )
        if stage_options.enabled and not effective:
            requested = _supported_names(stage_options.requested_maturities)
            gates = _supported_names(pass_gates)
            raise PipelineConfigError(
                f"constant-simplification stage {descriptor.stage_id} is enabled but "
                "its requested maturities have an empty intersection with pass "
                f"maturity_gates; requested: {requested}; pass maturity_gates: {gates}"
            )
        runtime_order: int | None = None
        if stage_options.enabled:
            runtime_order = pipeline_orders.get(descriptor.pipeline, 0)
            pipeline_orders[descriptor.pipeline] = runtime_order + 1
        compiled.append(
            CompiledConstantStage(
                pass_id=str(descriptor.pass_id),
                stage_id=descriptor.stage_id,
                lifecycle_domain=descriptor.lifecycle_domain,
                pipeline=descriptor.pipeline,
                implementation_name=descriptor.implementation_name,
                enabled=stage_options.enabled,
                supported_maturities=supported,
                requested_maturities=stage_options.requested_maturities,
                pass_maturity_gates=pass_gates,
                effective_maturities=effective,
                runtime_order=runtime_order,
                inactive_reason=(
                    "disabled by configuration" if not stage_options.enabled else None
                ),
                options=stage_options.stage_options,
            )
        )
    return CompiledConstantSimplificationSchedule(
        preparation=preparation,
        stages=tuple(compiled),
    )


def canonical_constant_simplification_options(
    config: PipelineConfig,
    stage_descriptors: Sequence["ExecutionStageDescriptor"] | None = None,
) -> dict[str, object]:
    """Return the complete canonical option document for ``config``.

    Compilation remains the sole validator and legacy compatibility boundary.
    This projection deliberately serializes requested maturities rather than
    effective maturities so pass-level ``maturity_gates`` retain their original
    meaning when a project is loaded and saved again.
    """

    schedule = compile_constant_simplification_schedule(
        config,
        stage_descriptors,
    )
    stages: dict[str, object] = {}
    for stage in schedule.stages:
        options: dict[str, object] = {
            "enabled": stage.enabled,
            "maturities": [maturity.name for maturity in stage.requested_maturities],
        }
        options.update(dict(stage.options))
        stages[stage.stage_id] = options
    return {
        "preparation": {
            "global_const_types": {
                "enabled": schedule.preparation.enabled,
                "discover_bounded_tables": schedule.preparation.discover_bounded_tables,
            }
        },
        "stages": stages,
    }


def canonicalize_constant_simplification_entry(
    entry: Mapping[str, object],
) -> dict[str, object]:
    """Canonicalize one serialized public pipeline entry.

    The surrounding entry is copied without reinterpretation.  Only the
    pass-owned ``options`` object is projected through the portable compiler;
    pass metadata, including ``maturity_gates``, is preserved by the normal
    ``PipelineConfig`` serializer.
    """

    config = PipelineConfig.from_dict(entry)
    if config.pass_id != CONSTANT_SIMPLIFICATION_PASS_ID:
        raise PipelineConfigError(
            "constant option canonicalization received pass "
            f"{config.pass_id!r}"
        )
    canonical = config.to_dict()
    canonical["options"] = canonical_constant_simplification_options(config)
    return canonical


# Explicit aliases make the parser/compiler boundary discoverable to callers
# using either vocabulary without introducing another implementation.
parse_constant_simplification_options = compile_constant_simplification_schedule
compile_constant_simplification_options = compile_constant_simplification_schedule


__all__ = [
    "AGGRESSIVE_MEMORY_POLICY",
    "CONSTANT_SIMPLIFICATION_PASS_ID",
    "CONSTANT_STAGE_IDS",
    "CompiledConstantSimplificationSchedule",
    "CompiledConstantStage",
    "ConstantMutationStageOptions",
    "ConstantPreparationOptions",
    "IRMaturity",
    "StageLifecycleDomain",
    "STRICT_MEMORY_POLICY",
    "compile_constant_simplification_options",
    "compile_constant_simplification_schedule",
    "canonical_constant_simplification_options",
    "canonicalize_constant_simplification_entry",
    "parse_constant_simplification_options",
]
