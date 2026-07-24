"""Read-only, IDA-independent collection for the deobfuscation workbench."""

from __future__ import annotations

import json
import pathlib
from collections.abc import Callable, Mapping

from d810.core.deobfuscation_case import DeobfuscationCaseSnapshot
from d810.manager.deobfuscation_case_service import DeobfuscationCaseCollectionError
from d810.manager.project_runtime import ProjectRuntimeSnapshot
from d810.manager.workbench_models import (
    ArtifactRef,
    AttackSummary,
    BaselineRef,
    ConsumerOutcomeSnapshot,
    CountEntry,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    FunctionRef,
    OutcomeStatus,
    PatchCountEntry,
    PipelineStageSnapshot,
    RuleScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
    WorkbenchDiagnostic,
)
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    RecipeCommandRequest,
)
from d810.passes.contract_manifest import (
    pipeline_contract_manifest,
    pipeline_contract_preflight_manifest,
)
from d810.passes.contract_preflight import preflight_pipeline_contract
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pass_specs_from_project_config


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _path_ref(*, kind: str, label: str, value: object) -> ArtifactRef:
    if value is None:
        return ArtifactRef(kind=kind, label=label, path=None, available=False)
    try:
        path = pathlib.Path(value)
    except TypeError:
        return ArtifactRef(kind=kind, label=label, path=None, available=False)
    return ArtifactRef(
        kind=kind,
        label=label,
        path=str(path),
        available=path.exists(),
    )


def _empty_attack() -> AttackSummary:
    return AttackSummary(
        observed_shape="unknown",
        mechanism="unavailable",
        selected_profile=None,
        selection_mode="not-analyzed",
        confidence=None,
        recommended_inferences=(),
        suppressed_rules=(),
        candidate_kinds=(),
    )


def _maturity_label(manifest: Mapping[str, object]) -> str:
    maturity = manifest.get("maturity")
    if not isinstance(maturity, Mapping):
        return "any"
    preferred = maturity.get("preferred")
    if preferred:
        return str(preferred)
    minimum = maturity.get("min")
    maximum = maturity.get("max")
    if minimum and maximum:
        return f"{minimum}..{maximum}"
    if minimum:
        return f">={minimum}"
    if maximum:
        return f"<={maximum}"
    return "any"


def _diagnostic_snapshot(diagnostic: object) -> WorkbenchDiagnostic:
    namespace = str(getattr(diagnostic, "namespace", "") or "")
    pass_id = str(getattr(diagnostic, "pass_id", "") or "")
    missing = tuple(sorted(str(value) for value in getattr(diagnostic, "missing", ())))
    available = tuple(
        sorted(str(value) for value in getattr(diagnostic, "available", ()))
    )
    detail = str(getattr(diagnostic, "detail", "") or "")
    message_parts: list[str] = []
    if namespace:
        message_parts.append(namespace)
    if missing:
        message_parts.append("missing " + ", ".join(missing))
    if detail:
        message_parts.append(detail)
    return WorkbenchDiagnostic(
        code="missing-contract-input",
        message=": ".join(message_parts) or "Contract preflight blocked",
        pass_id=pass_id or None,
        namespace=namespace or None,
        missing=missing,
        available=available,
    )


def _explicit_outcome_status(provenance: object) -> OutcomeStatus | None:
    if not isinstance(provenance, Mapping):
        return None
    raw = provenance.get("status")
    if raw is None:
        return None
    text = str(raw)
    for status in OutcomeStatus:
        if text in {status.value, status.name}:
            return status
    return None


def _consumer_status(report: object) -> OutcomeStatus:
    explicit = _explicit_outcome_status(getattr(report, "provenance_dict", None))
    if explicit is not None:
        return explicit
    if not bool(getattr(report, "source_artifacts_available", False)):
        return OutcomeStatus.NOT_ELIGIBLE
    if not bool(getattr(report, "summary_available", False)):
        return OutcomeStatus.NO_MATCH
    if bool(getattr(report, "consumer_verdict_applied", False)):
        return OutcomeStatus.CHANGED
    return OutcomeStatus.ABSTAINED


def _inference_applies(
    inference: object | None,
    *,
    function_ea: int,
    tags: frozenset[str],
) -> bool:
    if inference is None:
        return False
    target_eas = frozenset(
        int(value) for value in getattr(inference, "target_func_eas", ())
    )
    if target_eas and int(function_ea) not in target_eas:
        return False
    target_any = frozenset(
        str(value) for value in getattr(inference, "target_tags_any", ())
    )
    if target_any and target_any.isdisjoint(tags):
        return False
    target_all = frozenset(
        str(value) for value in getattr(inference, "target_tags_all", ())
    )
    if target_all and not target_all.issubset(tags):
        return False
    return True


class WorkbenchService:
    """Collect immutable workbench truth from an existing manager runtime."""

    def __init__(self, manager: object, *, registry: object | None = None) -> None:
        self._manager = manager
        self._registry = registry or operational_config_v2_pass_registry()
        self._generation = 0
        self._latest_function_ea: int | None = None
        self._latest_function_fingerprint: str | None = None

    def collect(
        self,
        *,
        function_ea: int,
        function_name: str,
        function_fingerprint: str | None,
        project_snapshot: ProjectRuntimeSnapshot,
        runtime_project: object,
        facts: object | None = None,
        baseline: BaselineRef | None = None,
        latest_output: D810OutputRef | None = None,
        runtime_scope: str = "project",
        saved_recipe: FunctionPipelineOverride | None = None,
        initial_errors: tuple[str, ...] = (),
    ) -> DeobfuscationWorkbenchSnapshot:
        """Collect one generation without executing passes or mutating state."""
        self._generation += 1
        generation = self._generation
        self._latest_function_ea = int(function_ea)
        self._latest_function_fingerprint = function_fingerprint
        errors = list(initial_errors)

        runtime = RuntimeConfigRef(
            source_name=project_snapshot.source.basename,
            source_path=str(project_snapshot.source.path),
            runtime_name=project_snapshot.runtime.basename,
            runtime_path=str(project_snapshot.runtime.path),
            mode=project_snapshot.mode.value,
            routed=project_snapshot.routed,
            hook_mode=project_snapshot.hook_mode,
            pass_ids=tuple(project_snapshot.effective_pass_ids),
            recipe_scope=str(runtime_scope),
        )
        function = FunctionRef(
            ea=int(function_ea),
            name=str(function_name),
            fingerprint=function_fingerprint,
            generation=generation,
        )

        try:
            pipeline = self._pipeline(runtime_project, facts=facts)
            actual_ids = tuple(stage.pass_id for stage in pipeline)
            if actual_ids != runtime.pass_ids:
                errors.append(
                    "pipeline: runtime pass IDs do not match parsed pass specs "
                    f"({runtime.pass_ids!r} != {actual_ids!r})"
                )
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            pipeline = ()
            errors.append(f"pipeline: {exc}")

        try:
            attack = self._attack(function_ea)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            attack = _empty_attack()
            errors.append(f"attack: {exc}")

        try:
            consumers = self._consumers(function_ea)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            consumers = ()
            errors.append(f"consumers: {exc}")

        try:
            rule_scope = self._rule_scope(
                function_ea=function_ea,
                project_snapshot=project_snapshot,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            rule_scope = RuleScopeSummary(
                project_instruction_rules=tuple(
                    project_snapshot.effective_instruction_rule_names
                ),
                project_block_rules=tuple(project_snapshot.effective_block_rule_names),
                function_enabled_rules=(),
                function_disabled_rules=(),
                function_tags=(),
                function_notes="",
                inference_name=None,
                inference_enabled_rules=(),
                inference_disabled_rules=(),
                inference_applies=False,
            )
            errors.append(f"rule-scope: {exc}")

        try:
            statistics = self._statistics()
        except (RuntimeError, TypeError, ValueError) as exc:
            statistics = StatisticsSummary((), (), (), 0, (), 0)
            errors.append(f"statistics: {exc}")

        if baseline is None or latest_output is None:
            comparison_service = getattr(self._manager, "comparison_service", None)
            if comparison_service is not None:
                stored_baseline, stored_output = comparison_service.refs(function_ea)
                if baseline is None:
                    baseline = stored_baseline
                if latest_output is None:
                    latest_output = stored_output

        case = self._case_snapshot(
            function=function,
            runtime=runtime,
            saved_recipe=saved_recipe,
            errors=errors,
        )

        return DeobfuscationWorkbenchSnapshot(
            generation=generation,
            function=function,
            runtime=runtime,
            attack=attack,
            pipeline=pipeline,
            consumers=consumers,
            rule_scope=rule_scope,
            statistics=statistics,
            baseline=baseline or BaselineRef(False, None, None, None),
            latest_output=latest_output or D810OutputRef(False, None, None, None),
            artifacts=self._artifacts(project_snapshot),
            freshness=SnapshotFreshness.CURRENT,
            engine_started=bool(getattr(self._manager, "started", False)),
            collection_errors=tuple(errors),
            case=case,
        )

    def execute_analyze(
        self,
        request: WorkbenchCommandRequest,
        *,
        target: object,
        provider_phase: object,
    ) -> WorkbenchCommandResult:
        """Run recon collection/classification without invoking mutation."""
        invalid = self._validate_request(request, expected_command="analyze")
        if invalid is not None:
            return invalid
        try:
            self._manager.analyze_workbench_function(
                function_ea=request.function_ea,
                target=target,
                provider_phase=provider_phase,
            )
        except Exception as exc:
            return self._failure(request, f"Analyze failed: {exc}")
        if not self._request_is_current(request):
            return self._stale_result(
                request,
                succeeded=True,
                message="Analyze completed for an older workbench generation",
            )
        return self._result(
            request,
            status=OutcomeStatus.READY,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message="Analysis completed",
        )

    def execute_deobfuscate(
        self,
        request: WorkbenchCommandRequest,
        *,
        lifecycle: Callable[[], bool],
    ) -> WorkbenchCommandResult:
        """Invoke the established deobfuscation lifecycle exactly once."""
        return self._execute_lifecycle(
            request,
            expected_command="deobfuscate",
            label="Deobfuscation",
            lifecycle=lifecycle,
        )

    def execute_build_deobfuscator(
        self,
        request: WorkbenchCommandRequest,
        *,
        target: object,
        provider_phase: object,
    ) -> WorkbenchCommandResult:
        """Refresh the case dossier without invoking a deobfuscation rewrite."""

        def lifecycle() -> bool:
            self._manager.analyze_workbench_function(
                function_ea=request.function_ea,
                target=target,
                provider_phase=provider_phase,
            )
            return True

        return self._execute_lifecycle(
            request,
            expected_command="build_deobfuscator",
            label="Build Deobfuscator",
            lifecycle=lifecycle,
        )

    def execute_function_override(
        self,
        request: WorkbenchCommandRequest,
        *,
        lifecycle: Callable[[], bool],
    ) -> WorkbenchCommandResult:
        """Invoke the established function-rule dialog lifecycle exactly once."""
        return self._execute_lifecycle(
            request,
            expected_command="function_override",
            label="Function override",
            lifecycle=lifecycle,
        )

    def _execute_lifecycle(
        self,
        request: WorkbenchCommandRequest,
        *,
        expected_command: str,
        label: str,
        lifecycle: Callable[[], bool],
    ) -> WorkbenchCommandResult:
        invalid = self._validate_request(
            request,
            expected_command=expected_command,
        )
        if invalid is not None:
            return invalid
        try:
            succeeded = bool(lifecycle())
        except Exception as exc:
            return self._failure(request, f"{label} failed: {exc}")
        if not self._request_is_current(request):
            return self._stale_result(
                request,
                succeeded=succeeded,
                message=f"{label} completed for an older workbench generation",
            )
        if not succeeded:
            return self._failure(request, f"{label} did not complete")
        return self._result(
            request,
            status=OutcomeStatus.READY,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message=f"{label} completed",
        )

    def _case_snapshot(
        self,
        *,
        function: FunctionRef,
        runtime: RuntimeConfigRef,
        saved_recipe: FunctionPipelineOverride | None,
        errors: list[str],
    ) -> DeobfuscationCaseSnapshot:
        collector = getattr(self._manager, "get_deobfuscation_case_snapshot", None)
        if not callable(collector):
            return DeobfuscationCaseSnapshot(
                evidence=None,
                strategy=None,
                direct_run_permitted=False,
                direct_run_reason="Build a strategy before running it.",
            )
        try:
            return collector(
                function=function,
                runtime=runtime,
                saved_recipe=saved_recipe,
            )
        except DeobfuscationCaseCollectionError as exc:
            errors.append(f"case: {exc}")
            return DeobfuscationCaseSnapshot(
                evidence=None,
                strategy=None,
                direct_run_permitted=False,
                direct_run_reason="Case evidence is unavailable; Build a strategy before running it.",
            )

    def _validate_request(
        self,
        request: WorkbenchCommandRequest,
        *,
        expected_command: str,
    ) -> WorkbenchCommandResult | None:
        if request.command != expected_command:
            return self._failure(
                request,
                f"Expected {expected_command!r} command, got {request.command!r}",
            )
        if not self._request_is_current(request):
            return self._stale_result(
                request,
                succeeded=False,
                message="Command belongs to an older workbench generation",
            )
        return None

    def _request_is_current(self, request: WorkbenchCommandRequest) -> bool:
        return (
            request.expected_generation == self._generation
            and request.function_ea == self._latest_function_ea
            and request.function_fingerprint == self._latest_function_fingerprint
        )

    def recipe_request_is_current(self, request: RecipeCommandRequest) -> bool:
        return (
            request.expected_workbench_generation == self._generation
            and request.function_ea == self._latest_function_ea
            and request.function_fingerprint == self._latest_function_fingerprint
        )

    @staticmethod
    def _result(
        request: WorkbenchCommandRequest,
        *,
        status: OutcomeStatus,
        succeeded: bool,
        accepted: bool,
        refresh_requested: bool,
        message: str,
    ) -> WorkbenchCommandResult:
        return WorkbenchCommandResult(
            command=request.command,
            function_ea=request.function_ea,
            requested_generation=request.expected_generation,
            function_fingerprint=request.function_fingerprint,
            status=status,
            succeeded=succeeded,
            accepted=accepted,
            refresh_requested=refresh_requested,
            message=message,
        )

    def _failure(
        self,
        request: WorkbenchCommandRequest,
        message: str,
    ) -> WorkbenchCommandResult:
        return self._result(
            request,
            status=OutcomeStatus.FAILED,
            succeeded=False,
            accepted=self._request_is_current(request),
            refresh_requested=False,
            message=message,
        )

    def _stale_result(
        self,
        request: WorkbenchCommandRequest,
        *,
        succeeded: bool,
        message: str,
    ) -> WorkbenchCommandResult:
        return self._result(
            request,
            status=OutcomeStatus.STALE,
            succeeded=succeeded,
            accepted=False,
            refresh_requested=False,
            message=message,
        )

    def _pipeline(
        self,
        runtime_project: object,
        *,
        facts: object | None,
    ) -> tuple[PipelineStageSnapshot, ...]:
        specs = pass_specs_from_project_config(runtime_project, self._registry)
        if facts is None:
            manifests = pipeline_contract_manifest(specs)
            results: tuple[object | None, ...] = (None,) * len(specs)
        else:
            preflight = preflight_pipeline_contract(specs, facts)
            manifests = pipeline_contract_preflight_manifest(specs, preflight)
            results = tuple(preflight.results)

        stages: list[PipelineStageSnapshot] = []
        for ordinal, (spec, manifest, result) in enumerate(
            zip(specs, manifests, results)
        ):
            diagnostics = (
                ()
                if result is None
                else tuple(
                    _diagnostic_snapshot(diagnostic)
                    for diagnostic in getattr(result, "diagnostics", ())
                )
            )
            if result is None:
                status = OutcomeStatus.NOT_RUN
                summary = "No facts view is available for static preflight"
            elif bool(getattr(result, "satisfied", False)):
                status = OutcomeStatus.READY
                summary = "Contract requirements are satisfied"
            else:
                status = OutcomeStatus.BLOCKED
                summary = "; ".join(item.message for item in diagnostics)
            stages.append(
                PipelineStageSnapshot(
                    ordinal=ordinal,
                    pass_id=spec.pass_id,
                    phase=spec.granularity.value,
                    scope=str(manifest.get("scope", "")),
                    maturity=_maturity_label(manifest),
                    status=status,
                    summary=summary,
                    contract_json=_canonical_json(manifest),
                    diagnostics=diagnostics,
                )
            )
        return tuple(stages)

    def _attack(self, function_ea: int) -> AttackSummary:
        loader = getattr(self._manager, "load_recon_hints", None)
        hints = loader(int(function_ea)) if callable(loader) else None
        if hints is None:
            return _empty_attack()
        candidate_kinds = tuple(
            dict.fromkeys(
                str(candidate.kind)
                for candidate in getattr(hints, "candidates", ())
                if str(getattr(candidate, "kind", ""))
            )
        )
        return AttackSummary(
            observed_shape=str(getattr(hints, "obfuscation_type", None) or "unknown"),
            mechanism="unavailable",
            selected_profile=None,
            selection_mode="recon-hints",
            confidence=float(getattr(hints, "confidence", 0.0)),
            recommended_inferences=tuple(
                str(value) for value in getattr(hints, "recommended_inferences", ())
            ),
            suppressed_rules=tuple(
                str(value) for value in getattr(hints, "suppress_rules", ())
            ),
            candidate_kinds=candidate_kinds,
        )

    def _consumers(self, function_ea: int) -> tuple[ConsumerOutcomeSnapshot, ...]:
        loader = getattr(self._manager, "get_recon_outcome_reports", None)
        reports = loader(int(function_ea)) if callable(loader) else ()
        outcomes: list[ConsumerOutcomeSnapshot] = []
        for report in reports or ():
            provenance = getattr(report, "provenance_dict", None)
            outcomes.append(
                ConsumerOutcomeSnapshot(
                    phase="supporting",
                    consumer_name=str(getattr(report, "consumer_name", "unknown")),
                    status=_consumer_status(report),
                    detail=str(getattr(report, "detail", "") or ""),
                    provenance_json=(
                        _canonical_json(provenance) if provenance is not None else None
                    ),
                )
            )
        return tuple(outcomes)

    def _rule_scope(
        self,
        *,
        function_ea: int,
        project_snapshot: ProjectRuntimeSnapshot,
    ) -> RuleScopeSummary:
        override_loader = getattr(self._manager, "get_function_rule_override", None)
        override = (
            override_loader(int(function_ea)) if callable(override_loader) else None
        )
        tag_loader = getattr(self._manager, "get_function_tags", None)
        tags = set(tag_loader(int(function_ea)) if callable(tag_loader) else ())
        if override is not None:
            tags.update(getattr(override, "tags", ()))
        normalized_tags = frozenset(
            str(value).strip() for value in tags if str(value).strip()
        )
        inference_loader = getattr(self._manager, "get_active_rule_inference", None)
        inference = inference_loader() if callable(inference_loader) else None
        return RuleScopeSummary(
            project_instruction_rules=tuple(
                project_snapshot.effective_instruction_rule_names
            ),
            project_block_rules=tuple(project_snapshot.effective_block_rule_names),
            function_enabled_rules=tuple(
                sorted(str(value) for value in getattr(override, "enabled_rules", ()))
            ),
            function_disabled_rules=tuple(
                sorted(str(value) for value in getattr(override, "disabled_rules", ()))
            ),
            function_tags=tuple(sorted(normalized_tags)),
            function_notes=str(getattr(override, "notes", "") or ""),
            inference_name=(
                str(getattr(inference, "name", "")) or None
                if inference is not None
                else None
            ),
            inference_enabled_rules=tuple(
                sorted(str(value) for value in getattr(inference, "enabled_rules", ()))
            ),
            inference_disabled_rules=tuple(
                sorted(str(value) for value in getattr(inference, "disabled_rules", ()))
            ),
            inference_applies=_inference_applies(
                inference,
                function_ea=int(function_ea),
                tags=normalized_tags,
            ),
        )

    def _statistics(self) -> StatisticsSummary:
        stats = getattr(self._manager, "stats", None)
        report = stats.last_report() if stats is not None else {}
        report = report or {}
        optimizer_matches = report.get("optimizer_matches", {})
        rule_matches = report.get("rule_matches", {})
        cfg_patches = report.get("cfg_patches", {})
        cycles = report.get("cycles_detected", {})
        return StatisticsSummary(
            optimizer_matches=tuple(
                CountEntry(str(name), int(count))
                for name, count in sorted(optimizer_matches.items())
            ),
            rule_matches=tuple(
                CountEntry(str(name), int(count))
                for name, count in sorted(rule_matches.items())
            ),
            cfg_patches=tuple(
                PatchCountEntry(
                    str(name),
                    int(values.get("uses", 0)),
                    int(values.get("total_patches", 0)),
                )
                for name, values in sorted(cfg_patches.items())
            ),
            total_rule_firings=int(report.get("total_rule_firings", 0)),
            cycles_detected=tuple(
                CountEntry(str(name), int(count))
                for name, count in sorted(cycles.items())
            ),
            total_cycles_detected=int(report.get("total_cycles_detected", 0)),
        )

    def _artifacts(
        self,
        project_snapshot: ProjectRuntimeSnapshot,
    ) -> tuple[ArtifactRef, ...]:
        storage = getattr(self._manager, "storage", None)
        storage_path = None
        if storage is not None:
            storage_path = getattr(storage, "db_path", None) or getattr(
                storage, "path", None
            )
        return (
            _path_ref(
                kind="source-config",
                label="Source project configuration",
                value=project_snapshot.source.path,
            ),
            _path_ref(
                kind="runtime-config",
                label="Effective runtime configuration",
                value=project_snapshot.runtime.path,
            ),
            _path_ref(
                kind="recon-db",
                label="Recon database",
                value=getattr(self._manager, "recon_db", None),
            ),
            _path_ref(
                kind="log-directory",
                label="D810 log directory",
                value=getattr(self._manager, "log_dir", None),
            ),
            _path_ref(
                kind="function-rules-db",
                label="Function rule storage",
                value=storage_path,
            ),
        )


__all__ = ["WorkbenchService"]
