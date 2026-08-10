"""Typed public transform selection for the ``mba-simplify`` pass."""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.pass_ids import PassId
from d810.core.pass_editor_spec import FieldControlKind, FieldEditorSpec
from d810.core.typing import Mapping
from d810.mba.rules import VerifiableRule
from d810.passes.execution_stages import (
    ExecutionPipeline,
    ExecutionStageDescriptor,
    canonical_transform_id,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry

#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
#: This module and ``mba_simplify`` each spelled the literal out independently,
#: which is two sources of truth for one identity.
MBA_SIMPLIFY_PASS_ID = PassId.MBA_SIMPLIFY

# These implementations still live in the Hex-Rays instruction backend and
# therefore cannot be imported into the portable pass layer. Their bindings
# are explicit strings; the public registry exposes only the derived IDs.
_LIVE_IMPLEMENTATION_NAMES = (
    "AndChain",
    "ArithmeticChain",
    "ConstantCallResultFoldRule",
    "ExampleGuessingRule",
    "OrChain",
    "ReplaceMovHighContext",
    "ReplaceReadonlyAddressOfWithImmediate",
    "RotateHelperInlineRule",
    "SetGlobalVariablesToZeroIfDetectedReadOnly",
    "XorChain",
    "Z3ConstantOptimization",
    "Z3SmodRuleGeneric",
    "Z3lnotRuleGeneric",
    "Z3setnzRuleGeneric",
    "Z3setzRuleGeneric",
)

# Two historically distinct XNOR rewrites normalize to the same mechanical
# spelling. Stable semantic IDs make the distinction explicit.
_TRANSFORM_ID_OVERRIDES = {
    "BnotXor_Rule_1": "bnot-xor-paired-not-1",
    "Bnot_XorRule_1": "bnot-xor-demorgan-1",
}

# The existing hook adapter and bundled projects use these implementation
# identities. Keep that private binding exact while the pure MBA class names
# remain an internal refactor detail.
_PRIVATE_BINDING_OVERRIDES = {
    "Mul_MBA_1": "Mul_MbaRule_1",
    "Mul_MBA_2": "Mul_MbaRule_2",
    "Mul_MBA_3": "Mul_MbaRule_3",
    "Mul_MBA_4": "Mul_MbaRule_4",
}


# Runtime-owned schema for the small number of MBA transforms that accept
# parameters. The pass catalog renders these fixed controls; raw JSON cannot
# introduce another transform option.
MBA_TRANSFORM_OPTION_FIELDS: Mapping[str, tuple[FieldEditorSpec, ...]] = {
    "z-3-constant-optimization": (
        FieldEditorSpec(
            field_id="min_nb_opcode",
            label="Minimum distinct opcodes",
            path=("min_nb_opcode",),
            control=FieldControlKind.INTEGER,
            description="Require this many distinct opcodes before invoking Z3.",
            minimum=1,
            maximum=64,
            default=4,
        ),
        FieldEditorSpec(
            field_id="min_nb_constant",
            label="Minimum constants",
            path=("min_nb_constant",),
            control=FieldControlKind.INTEGER,
            description="Require this many constants before invoking Z3.",
            minimum=1,
            maximum=64,
            default=3,
        ),
    ),
    "example-guessing": (
        FieldEditorSpec(
            field_id="min_nb_var",
            label="Minimum variables",
            path=("min_nb_var",),
            control=FieldControlKind.INTEGER,
            description="Minimum symbolic variables in a guessed pattern.",
            minimum=1,
            maximum=255,
            default=1,
        ),
        FieldEditorSpec(
            field_id="max_nb_var",
            label="Maximum variables",
            path=("max_nb_var",),
            control=FieldControlKind.INTEGER,
            description="Maximum symbolic variables in a guessed pattern.",
            minimum=-1,
            maximum=255,
            default=3,
        ),
        FieldEditorSpec(
            field_id="min_nb_diff_opcodes",
            label="Minimum distinct opcodes",
            path=("min_nb_diff_opcodes",),
            control=FieldControlKind.INTEGER,
            description="Minimum operation diversity required for pattern guessing.",
            minimum=1,
            maximum=255,
            default=3,
        ),
        FieldEditorSpec(
            field_id="max_nb_diff_opcodes",
            label="Maximum distinct opcodes",
            path=("max_nb_diff_opcodes",),
            control=FieldControlKind.INTEGER,
            description="Maximum operation diversity considered by pattern guessing.",
            minimum=-1,
            maximum=255,
            default=6,
        ),
    ),
}


@dataclass(frozen=True, slots=True)
class MbaSimplifyOptions:
    transform_ids: tuple[str, ...]
    transform_options: Mapping[str, Mapping[str, object]]

    def __post_init__(self) -> None:
        copied = {
            transform_id: MappingProxyType(dict(options))
            for transform_id, options in self.transform_options.items()
        }
        object.__setattr__(self, "transform_options", MappingProxyType(copied))


def mba_transform_id(implementation_name: str) -> str:
    """Return the stable public transform ID for a private implementation."""

    return _TRANSFORM_ID_OVERRIDES.get(
        implementation_name,
        canonical_transform_id(implementation_name),
    )


def mba_transform_stages() -> tuple[ExecutionStageDescriptor, ...]:
    """Return deterministic registered bindings without importing live IDA code."""

    portable_names = {
        _PRIVATE_BINDING_OVERRIDES.get(rule_type.__name__, rule_type.__name__)
        for rule_type in VerifiableRule.registry.values()
        if rule_type.__module__.startswith("d810.mba.rules.")
    }
    implementation_names = tuple(
        sorted(portable_names | set(_LIVE_IMPLEMENTATION_NAMES))
    )
    return tuple(
        ExecutionStageDescriptor(
            pass_id=MBA_SIMPLIFY_PASS_ID,
            stage_id=mba_transform_id(implementation_name),
            pipeline=ExecutionPipeline.INSTRUCTION,
            implementation_name=implementation_name,
        )
        for implementation_name in implementation_names
    )


def parse_mba_simplify_options(
    config: PipelineConfig,
    registry: PassRegistry,
) -> MbaSimplifyOptions:
    """Validate ordered public transform selection against registered bindings."""

    if config.pass_id != MBA_SIMPLIFY_PASS_ID:
        raise PipelineConfigError(
            f"expected {MBA_SIMPLIFY_PASS_ID!r}, got {config.pass_id!r}"
        )
    unknown_option_names = tuple(
        sorted(set(config.options) - {"transforms", "transform_options"})
    )
    if unknown_option_names:
        raise PipelineConfigError(
            f"mba-simplify has unknown options: {list(unknown_option_names)}"
        )
    raw_transform_ids = config.options.get("transforms", [])
    if isinstance(raw_transform_ids, str) or not isinstance(
        raw_transform_ids, (list, tuple)
    ):
        raise PipelineConfigError("mba-simplify options.transforms must be a list")
    transform_ids: list[str] = []
    seen: set[str] = set()
    for transform_id in raw_transform_ids:
        if not isinstance(transform_id, str) or not transform_id:
            raise PipelineConfigError(
                "mba-simplify options.transforms must contain non-empty strings"
            )
        if transform_id in seen:
            raise PipelineConfigError(
                f"mba-simplify options.transforms contains duplicate {transform_id!r}"
            )
        seen.add(transform_id)
        transform_ids.append(transform_id)

    known_ids = frozenset(registry.transform_ids_for(MBA_SIMPLIFY_PASS_ID))
    unknown_ids = tuple(
        transform_id for transform_id in transform_ids if transform_id not in known_ids
    )
    if unknown_ids:
        raise PipelineConfigError(
            f"mba-simplify references unknown transform IDs: {list(unknown_ids)}"
        )

    raw_options = config.options.get("transform_options", {})
    if not isinstance(raw_options, ABCMapping):
        raise PipelineConfigError(
            "mba-simplify options.transform_options must be a mapping"
        )
    transform_options: dict[str, Mapping[str, object]] = {}
    for transform_id, options in raw_options.items():
        if not isinstance(transform_id, str) or not transform_id:
            raise PipelineConfigError(
                "mba-simplify options.transform_options keys must be non-empty strings"
            )
        if transform_id not in seen:
            raise PipelineConfigError(
                "mba-simplify options.transform_options targets unselected transform "
                f"{transform_id!r}"
            )
        if not isinstance(options, ABCMapping):
            raise PipelineConfigError(
                f"mba-simplify transform options for {transform_id!r} must be a mapping"
            )
        declared_fields = MBA_TRANSFORM_OPTION_FIELDS.get(transform_id, ())
        allowed_names = {field.path[0] for field in declared_fields}
        unknown_names = tuple(sorted(set(options).difference(allowed_names)))
        if unknown_names:
            raise PipelineConfigError(
                "mba-simplify transform options for "
                f"{transform_id!r} have option(s) that are not editor-visible: "
                f"{list(unknown_names)}"
            )
        transform_options[transform_id] = dict(options)
    return MbaSimplifyOptions(tuple(transform_ids), transform_options)


__all__ = [
    "MBA_TRANSFORM_OPTION_FIELDS",
    "MbaSimplifyOptions",
    "mba_transform_id",
    "mba_transform_stages",
    "parse_mba_simplify_options",
]
