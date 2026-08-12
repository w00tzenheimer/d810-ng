"""Pure pass/stage execution scoping and diagnostics.

Private optimizer objects are carried only as opaque stage implementations. All
selection, suppression, persistence, and reporting identities are stable pass or
stage IDs.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from d810.core.typing import Any, Callable, Iterable, Mapping, Protocol

from d810.core.registry import EventEmitter


class ExecutionPipeline(str, enum.Enum):
    """Portable execution backend selected by a public pass stage."""

    INSTRUCTION = "instruction"
    FLOW = "flow"
    CTREE = "ctree"


class ExecutionTargetKind(str, enum.Enum):
    """Public identity namespace targeted by an execution adjustment."""

    PASS = "pass"
    STAGE = "stage"


class ExecutionAdjustmentAction(str, enum.Enum):
    """Strict operation applied to a public pass or stage identity."""

    SUPPRESS = "suppress"
    OVERRIDE = "override"


class ExecutionScopeEvent(enum.Enum):
    PROJECT_PIPELINE_RELOADED = "project_pipeline_reloaded"
    IDB_METADATA_RELOADED = "idb_metadata_reloaded"
    FUNCTION_RECIPE_UPDATED = "function_recipe_updated"
    FUNCTION_TAGS_UPDATED = "function_tags_updated"
    HINTS_APPLIED = "hints_applied"


@dataclass(frozen=True, slots=True)
class ExecutionScopeInvalidation:
    reason: ExecutionScopeEvent
    project_name: str | None = None
    func_eas: frozenset[int] | None = None
    changed_targets: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class FunctionExecutionMetadata:
    function_tags: frozenset[str] = frozenset()


class FunctionExecutionMetadataProvider(Protocol):
    def __call__(self, function_ea: int) -> FunctionExecutionMetadata | None: ...


@dataclass(frozen=True, slots=True)
class ExpandedExecutionStage:
    descriptor: Any
    implementation: object
    target: Any
    maturities: frozenset[int]

    @property
    def pass_id(self) -> str:
        return str(self.descriptor.pass_id)

    @property
    def stage_id(self) -> str:
        return str(self.descriptor.stage_id)

    @property
    def pipeline(self) -> object:
        return self.descriptor.pipeline


@dataclass(frozen=True, slots=True)
class ExecutionStageIdentity:
    """Stable identity carried across deferred execution boundaries."""

    pass_id: str
    stage_id: str

    def __post_init__(self) -> None:
        if not self.pass_id or not self.stage_id:
            raise ValueError("execution stage identity fields must be non-empty")


@dataclass(frozen=True, slots=True)
class ExecutionAdjustment:
    target_kind: ExecutionTargetKind
    target_id: str
    action: ExecutionAdjustmentAction
    overrides: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.target_kind, ExecutionTargetKind):
            raise TypeError("execution adjustment target_kind must be typed")
        if not isinstance(self.action, ExecutionAdjustmentAction):
            raise TypeError("execution adjustment action must be typed")
        if not self.target_id:
            raise ValueError("execution adjustment target_id must be non-empty")
        if self.action is ExecutionAdjustmentAction.SUPPRESS and self.overrides:
            raise ValueError("suppress adjustments cannot carry overrides")


@dataclass(frozen=True, slots=True)
class ExecutionInference:
    name: str
    adjustments: tuple[ExecutionAdjustment, ...]
    target_func_eas: frozenset[int] = frozenset()
    target_tags_any: frozenset[str] = frozenset()
    target_tags_all: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class EffectiveExecutionDecision:
    pass_id: str
    stage_id: str
    pipeline: object
    maturities: tuple[int, ...]
    active: bool
    reason: str
    detail: str


@dataclass(frozen=True, slots=True)
class EffectiveExecutionReport:
    project_name: str
    idb_key: str
    function_ea: int
    function_tags: tuple[str, ...]
    inference_names: tuple[str, ...]
    decisions: tuple[EffectiveExecutionDecision, ...]
    unknown_targets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApplyExecutionHintsResult:
    func_ea: int
    inferences_applied: tuple[str, ...]
    inferences_not_found: tuple[str, ...]
    stages_suppressed: tuple[str, ...]
    cache_invalidated: bool
    generation_before: int
    generation_after: int


InferenceFactory = Callable[[Any], list[ExecutionAdjustment]]


@dataclass(frozen=True, slots=True)
class _Evaluation:
    active: bool
    reason: str
    detail: str


class ExecutionScopeService:
    """Evaluate configured stages once for both execution and diagnostics."""

    def __init__(self) -> None:
        self._generation = 0
        self._stages: tuple[ExpandedExecutionStage, ...] = ()
        self._metadata_provider: FunctionExecutionMetadataProvider | None = None
        self._metadata_cache: dict[int, FunctionExecutionMetadata | None] = {}
        self._inference_registry: dict[str, InferenceFactory] = {}
        self._hint_inferences: dict[int, tuple[ExecutionInference, ...]] = {}
        self._hint_suppressions: dict[int, frozenset[str]] = {}
        self._active_cache: dict[
            tuple[str, str, int, str, int], tuple[ExpandedExecutionStage, ...]
        ] = {}
        self._attached = False

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def active_cache_size(self) -> int:
        return len(self._active_cache)

    def attach(self, emitter: EventEmitter) -> None:
        if self._attached:
            return
        for event in ExecutionScopeEvent:
            emitter.on(event, self._on_event)
        self._attached = True

    def _on_event(self, payload: ExecutionScopeInvalidation | None = None) -> None:
        if payload is not None:
            self.invalidate(payload)

    def invalidate(self, payload: ExecutionScopeInvalidation) -> None:
        self._generation += 1
        if payload.func_eas:
            targets = payload.func_eas
            self._active_cache = {
                key: value
                for key, value in self._active_cache.items()
                if key[2] not in targets
            }
            for func_ea in targets:
                self._metadata_cache.pop(func_ea, None)
            return
        self._active_cache.clear()
        self._metadata_cache.clear()

    def set_metadata_provider(
        self, provider: FunctionExecutionMetadataProvider | None
    ) -> None:
        self._metadata_provider = provider
        self._metadata_cache.clear()
        self._active_cache.clear()

    def configure(self, stages: Iterable[ExpandedExecutionStage]) -> None:
        configured = tuple(stages)
        identities: set[tuple[str, str]] = set()
        for stage in configured:
            identity = (stage.pass_id, stage.stage_id)
            if identity in identities:
                raise ValueError(
                    f"duplicate expanded execution stage: {stage.pass_id}/{stage.stage_id}"
                )
            identities.add(identity)
        self._stages = configured
        self._generation += 1
        self._active_cache.clear()

    def register_inference(self, name: str, factory: InferenceFactory) -> None:
        self._inference_registry[name] = factory

    def clear_hint_state(self, func_ea: int) -> None:
        changed = self._hint_inferences.pop(func_ea, None) is not None
        changed = self._hint_suppressions.pop(func_ea, None) is not None or changed
        if changed:
            self.invalidate(
                ExecutionScopeInvalidation(
                    ExecutionScopeEvent.HINTS_APPLIED,
                    func_eas=frozenset({func_ea}),
                )
            )

    def apply_hints(self, hints: Any) -> ApplyExecutionHintsResult:
        func_ea = int(hints.func_ea)
        generation_before = self._generation
        had_state = (
            func_ea in self._hint_inferences or func_ea in self._hint_suppressions
        )
        self._hint_inferences.pop(func_ea, None)
        self._hint_suppressions.pop(func_ea, None)
        applied: list[str] = []
        missing: list[str] = []
        inferred: list[ExecutionInference] = []
        for name in tuple(getattr(hints, "recommended_inferences", ())):
            factory = self._inference_registry.get(name)
            if factory is None:
                missing.append(name)
                continue
            inferred.append(
                ExecutionInference(
                    name=name,
                    adjustments=tuple(factory(hints)),
                    target_func_eas=frozenset({func_ea}),
                )
            )
            applied.append(name)
        if inferred:
            self._hint_inferences[func_ea] = tuple(inferred)
        raw_suppressed = tuple(
            str(value) for value in getattr(hints, "suppress_stages", ())
        )
        # Older D810 databases persisted an OLLVM flattening hint as a flat
        # suppression of forward-constants.  It predates config-v2's delayed
        # FCP scheduling and the rule's own MMAT_CALLS safety gate, so retaining
        # it would incorrectly block the GLBOPT2 recovery pass.  Consume only
        # that precise stale encoding; every other explicit suppression keeps
        # its unconditional meaning.
        legacy_flattening_forward_suppression = (
            getattr(hints, "obfuscation_type", None) == "ollvm_flat"
            and "unflattening"
            in tuple(getattr(hints, "recommended_inferences", ()))
        )
        suppressed = tuple(
            stage_id
            for stage_id in raw_suppressed
            if not (
                legacy_flattening_forward_suppression
                and stage_id == "forward-constants"
            )
        )
        if suppressed:
            self._hint_suppressions[func_ea] = frozenset(suppressed)
        changed = had_state or bool(applied) or bool(suppressed)
        if changed:
            self.invalidate(
                ExecutionScopeInvalidation(
                    ExecutionScopeEvent.HINTS_APPLIED,
                    func_eas=frozenset({func_ea}),
                    changed_targets=frozenset(suppressed) or None,
                )
            )
        return ApplyExecutionHintsResult(
            func_ea=func_ea,
            inferences_applied=tuple(applied),
            inferences_not_found=tuple(missing),
            stages_suppressed=suppressed,
            cache_invalidated=changed,
            generation_before=generation_before,
            generation_after=self._generation,
        )

    def active_stages(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: object,
        maturity: int,
        function_tags: frozenset[str] | None = None,
    ) -> tuple[ExpandedExecutionStage, ...]:
        pipeline_value = str(getattr(pipeline, "value", pipeline))
        key = (project_name, idb_key, int(func_ea), pipeline_value, int(maturity))
        cached = self._active_cache.get(key)
        if cached is not None:
            return cached
        tags = self._tags(int(func_ea), function_tags)
        result = tuple(
            stage
            for stage in self._stages
            if str(getattr(stage.pipeline, "value", stage.pipeline)) == pipeline_value
            and stage.implementation is not None
            and self._evaluate(stage, int(func_ea), int(maturity), tags).active
        )
        self._active_cache[key] = result
        return result

    def identity_for_implementation(
        self,
        implementation: object,
        *,
        pipeline: object,
    ) -> ExecutionStageIdentity | None:
        """Resolve one private object to its configured public stage identity."""
        pipeline_value = str(getattr(pipeline, "value", pipeline))
        matches = tuple(
            stage
            for stage in self._stages
            if stage.implementation is implementation
            and str(getattr(stage.pipeline, "value", stage.pipeline))
            == pipeline_value
        )
        if not matches:
            return None
        if len(matches) != 1:
            identities = ", ".join(
                f"{stage.pass_id}/{stage.stage_id}" for stage in matches
            )
            raise ValueError(
                "implementation is bound to multiple configured stages: "
                f"{identities}"
            )
        return ExecutionStageIdentity(matches[0].pass_id, matches[0].stage_id)

    def identity_for_target(
        self,
        target_id: str,
        *,
        pipeline: object,
    ) -> ExecutionStageIdentity | None:
        """Resolve an explicit stable pass or stage target without aliases."""
        pipeline_value = str(getattr(pipeline, "value", pipeline))
        matches = tuple(
            stage
            for stage in self._stages
            if stage.implementation is not None
            and str(getattr(stage.pipeline, "value", stage.pipeline))
            == pipeline_value
            and target_id in {stage.pass_id, stage.stage_id}
        )
        if not matches:
            return None
        if len(matches) != 1:
            identities = ", ".join(
                f"{stage.pass_id}/{stage.stage_id}" for stage in matches
            )
            raise ValueError(
                f"execution target {target_id!r} is ambiguous: {identities}"
            )
        return ExecutionStageIdentity(matches[0].pass_id, matches[0].stage_id)

    def scheduled_stages(
        self,
        *,
        identities: Iterable[ExecutionStageIdentity],
        func_ea: int,
        pipeline: object,
        function_tags: frozenset[str] | None = None,
    ) -> tuple[ExpandedExecutionStage, ...]:
        """Resolve deferred stages while intentionally bypassing maturity gates."""
        requested = frozenset(identities)
        if not requested:
            return ()
        pipeline_value = str(getattr(pipeline, "value", pipeline))
        tags = self._tags(int(func_ea), function_tags)
        return tuple(
            stage
            for stage in self._stages
            if ExecutionStageIdentity(stage.pass_id, stage.stage_id) in requested
            and str(getattr(stage.pipeline, "value", stage.pipeline))
            == pipeline_value
            and stage.implementation is not None
            and self._evaluate(stage, int(func_ea), None, tags).active
        )

    def explain(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        maturity: int | None = None,
        function_tags: frozenset[str] | None = None,
    ) -> EffectiveExecutionReport:
        tags = self._tags(int(func_ea), function_tags)
        decisions: list[EffectiveExecutionDecision] = []
        for stage in self._stages:
            evaluation = self._evaluate(stage, int(func_ea), maturity, tags)
            decisions.append(
                EffectiveExecutionDecision(
                    pass_id=stage.pass_id,
                    stage_id=stage.stage_id,
                    pipeline=stage.pipeline,
                    maturities=tuple(sorted(stage.maturities)),
                    active=evaluation.active,
                    reason=evaluation.reason,
                    detail=evaluation.detail,
                )
            )
        known_passes = {stage.pass_id for stage in self._stages}
        known_stages = {stage.stage_id for stage in self._stages}
        referenced = set(self._hint_suppressions.get(int(func_ea), ()))
        inference_names: list[str] = []
        for inference in self._hint_inferences.get(int(func_ea), ()):
            if not self._inference_targets(inference, int(func_ea), tags):
                continue
            inference_names.append(inference.name)
            referenced.update(item.target_id for item in inference.adjustments)
        return EffectiveExecutionReport(
            project_name=project_name,
            idb_key=idb_key,
            function_ea=int(func_ea),
            function_tags=tuple(sorted(tags)),
            inference_names=tuple(inference_names),
            decisions=tuple(decisions),
            unknown_targets=tuple(sorted(referenced - known_passes - known_stages)),
        )

    def _tags(self, func_ea: int, explicit: frozenset[str] | None) -> frozenset[str]:
        tags = set(explicit or ())
        if self._metadata_provider is not None:
            if func_ea not in self._metadata_cache:
                self._metadata_cache[func_ea] = self._metadata_provider(func_ea)
            metadata = self._metadata_cache[func_ea]
            if metadata is not None:
                tags.update(metadata.function_tags)
        return frozenset(tags)

    def _evaluate(
        self,
        stage: ExpandedExecutionStage,
        func_ea: int,
        maturity: int | None,
        tags: frozenset[str],
    ) -> _Evaluation:
        target = stage.target
        include_eas = frozenset(getattr(target, "include_eas", ()))
        exclude_eas = frozenset(getattr(target, "exclude_eas", ()))
        tags_any = frozenset(getattr(target, "tags_any", ()))
        tags_all = frozenset(getattr(target, "tags_all", ()))
        if include_eas and func_ea not in include_eas:
            return _Evaluation(False, "pass-not-targeted", "function is not included")
        if func_ea in exclude_eas:
            return _Evaluation(False, "ea-excluded", "function is explicitly excluded")
        if tags_any and tags_any.isdisjoint(tags):
            return _Evaluation(
                False, "missing-tag-any", "no required any-tag is present"
            )
        if tags_all and not tags_all.issubset(tags):
            return _Evaluation(
                False, "missing-tag-all", "not all required tags are present"
            )
        if (
            maturity is not None
            and stage.maturities
            and maturity not in stage.maturities
        ):
            return _Evaluation(
                False, "wrong-maturity", "stage is inactive at this maturity"
            )
        for inference in self._hint_inferences.get(func_ea, ()):
            if not self._inference_targets(inference, func_ea, tags):
                continue
            for adjustment in inference.adjustments:
                matches = (
                    adjustment.target_kind is ExecutionTargetKind.PASS
                    and adjustment.target_id == stage.pass_id
                ) or (
                    adjustment.target_kind is ExecutionTargetKind.STAGE
                    and adjustment.target_id == stage.stage_id
                )
                if matches and adjustment.action is ExecutionAdjustmentAction.SUPPRESS:
                    return _Evaluation(
                        False,
                        "inference-suppressed",
                        f"inference {inference.name} suppressed this stage",
                    )
        if stage.stage_id in self._hint_suppressions.get(func_ea, ()):
            return _Evaluation(
                False, "hint-suppressed", "preanalysis suppressed this stage"
            )
        return _Evaluation(True, "active", "passed all execution gates")

    @staticmethod
    def _inference_targets(
        inference: ExecutionInference, func_ea: int, tags: frozenset[str]
    ) -> bool:
        if inference.target_func_eas and func_ea not in inference.target_func_eas:
            return False
        if inference.target_tags_any and inference.target_tags_any.isdisjoint(tags):
            return False
        if inference.target_tags_all and not inference.target_tags_all.issubset(tags):
            return False
        return True


__all__ = [
    "ApplyExecutionHintsResult",
    "EffectiveExecutionDecision",
    "EffectiveExecutionReport",
    "ExecutionAdjustment",
    "ExecutionAdjustmentAction",
    "ExecutionInference",
    "ExecutionPipeline",
    "ExecutionScopeEvent",
    "ExecutionScopeInvalidation",
    "ExecutionScopeService",
    "ExecutionStageIdentity",
    "ExecutionTargetKind",
    "ExpandedExecutionStage",
    "FunctionExecutionMetadata",
    "FunctionExecutionMetadataProvider",
]
