"""Read-only, IDA-independent collection for the deobfuscation workbench."""

from __future__ import annotations

import json
import hashlib
import pathlib
from collections.abc import Callable, Mapping

from d810.core.deobfuscation_case import DeobfuscationCaseSnapshot
from d810.manager.deobfuscation_case_service import DeobfuscationCaseCollectionError
from d810.manager.effective_pipeline_schedule import (
    build_effective_maturity_schedule,
)
from d810.manager.project_runtime import ProjectRuntimeSnapshot
from d810.manager.workbench_models import (
    ArtifactRef,
    AttackSummary,
    BaselineRef,
    ConsumerOutcomeSnapshot,
    CountEntry,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    EffectiveStageDecisionSummary,
    ExecutionAttemptSummary,
    ExecutionLedgerSummary,
    ExecutionProfileCandidateSummary,
    ExecutionProfileSummary,
    FunctionRef,
    OutcomeStatus,
    PatchCountEntry,
    PipelineStageSnapshot,
    PreparationScriptSummary,
    PreparationTransactionSummary,
    PreparationWorkbenchSummary,
    ExecutionScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
    WorkbenchDiagnostic,
)
from d810.core.execution_profile import (
    ExecutionProfileKey,
    build_execution_profile_preview,
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
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.core.execution_scope import ExecutionPipeline


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(nested) for nested in value]
    return value


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
        suppressed_stages=(),
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
    return "rule-defined"


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


class WorkbenchService:
    """Collect immutable workbench truth from an existing manager runtime."""

    def __init__(
        self,
        manager: object,
        *,
        registry: object | None = None,
        maturity_name_provider: Callable[[int], str] = lambda value: f"MMAT_{value}",
    ) -> None:
        self._manager = manager
        self._registry = registry or operational_config_v2_pass_registry()
        self._generation = 0
        self._latest_function_ea: int | None = None
        self._latest_function_fingerprint: str | None = None
        self._maturity_name_provider = maturity_name_provider

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
            execution_scope = self._execution_scope(
                function_ea=function_ea,
                project_snapshot=project_snapshot,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            execution_scope = ExecutionScopeSummary(
                public_passes=tuple(project_snapshot.effective_pass_ids),
                function_tags=(),
                inference_names=(),
                decisions=(),
                unknown_targets=(),
            )
            errors.append(f"execution-scope: {exc}")

        try:
            execution_ledger = self._execution_ledger(function_ea)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            execution_ledger = ExecutionLedgerSummary(None, int(function_ea), (), 0, 0)
            errors.append(f"execution-ledger: {exc}")

        try:
            execution_profile = self._execution_profile(function_ea, attack)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            execution_profile = ExecutionProfileSummary(None, (), 0)
            errors.append(f"execution-profile: {exc}")

        try:
            statistics = self._statistics()
        except (RuntimeError, TypeError, ValueError) as exc:
            statistics = StatisticsSummary((), 0, ())
            errors.append(f"statistics: {exc}")

        try:
            preparation = self._preparation(function_ea)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            preparation = PreparationWorkbenchSummary(None)
            errors.append(f"preparation: {exc}")

        try:
            effective_schedule = self._effective_schedule(
                runtime_project,
                project_snapshot=project_snapshot,
            )
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            from d810.manager.workbench_models import EffectiveMaturitySchedule

            effective_schedule = EffectiveMaturitySchedule()
            errors.append(f"effective-schedule: {exc}")

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
            execution_scope=execution_scope,
            statistics=statistics,
            baseline=baseline or BaselineRef(False, None, None, None),
            latest_output=latest_output or D810OutputRef(False, None, None, None),
            artifacts=self._artifacts(project_snapshot),
            freshness=SnapshotFreshness.CURRENT,
            engine_started=bool(getattr(self._manager, "started", False)),
            collection_errors=tuple(errors),
            preparation=preparation,
            effective_schedule=effective_schedule,
            execution_ledger=execution_ledger,
            execution_profile=execution_profile,
            case=case,
        )

    def _effective_schedule(
        self,
        runtime_project: object,
        *,
        project_snapshot: ProjectRuntimeSnapshot | None = None,
    ):
        configs = pipeline_configs_from_project_config(runtime_project)
        if project_snapshot is None:
            project_snapshot = getattr(
                self._manager,
                "current_project_runtime_snapshot",
                None,
            )
        constant_schedule = (
            project_snapshot.constant_simplification_schedule
            if project_snapshot is not None
            else None
        )
        preparation_status = None
        status_provider = getattr(self._manager, "preparation_status", None)
        if callable(status_provider):
            preparation_status = status_provider()
        return build_effective_maturity_schedule(
            configs,
            registry=self._registry,
            implementations={
                ExecutionPipeline.INSTRUCTION: tuple(
                    getattr(self._manager, "instruction_optimizer_rules", ())
                ),
                ExecutionPipeline.FLOW: tuple(
                    getattr(self._manager, "block_optimizer_rules", ())
                ),
                ExecutionPipeline.CTREE: tuple(
                    getattr(self._manager, "ctree_optimizer_rules", ())
                ),
            },
            maturity_name_provider=self._maturity_name_provider,
            constant_simplification_schedule=constant_schedule,
            preparation_status=preparation_status,
        )

    @staticmethod
    def _coalesce_byte_ranges(eas: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
        ordered = tuple(sorted(set(eas)))
        if not ordered:
            return ()
        ranges: list[tuple[int, int]] = []
        start = previous = ordered[0]
        for ea in ordered[1:]:
            if ea != previous + 1:
                ranges.append((start, previous + 1))
                start = ea
            previous = ea
        ranges.append((start, previous + 1))
        return tuple(ranges)

    @staticmethod
    def _current_source_sha256(path: str) -> str | None:
        try:
            return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        except OSError:
            return None

    def _preparation(self, function_ea: int) -> PreparationWorkbenchSummary:
        """Project durable preparation truth without exposing gateway objects."""

        controller = getattr(self._manager, "pre_hex_preparation", None)
        journal = getattr(self._manager, "_idb_preparation_journal", None)
        gateway = getattr(self._manager, "_idb_preparation_gateway", None)
        if controller is None or journal is None or gateway is None:
            return PreparationWorkbenchSummary(None)

        database_identity = str(controller.database_identity)
        scripts: list[PreparationScriptSummary] = []
        for descriptor in controller.scripts:
            current_hash = self._current_source_sha256(descriptor.path)
            scripts.append(
                PreparationScriptSummary(
                    script_id=descriptor.script_id,
                    display_name=descriptor.display_name,
                    path=descriptor.path,
                    configured_source_sha256=descriptor.source_sha256,
                    current_source_sha256=current_hash,
                    source_hash_matches=current_hash == descriptor.source_sha256,
                    enabled=descriptor.enabled,
                    portable=descriptor.portable,
                )
            )

        transactions: list[PreparationTransactionSummary] = []
        for record in journal.transactions(database_identity):
            byte_deltas = tuple(journal.byte_deltas(record.transaction_id))
            type_deltas = tuple(journal.type_deltas(record.transaction_id))
            affected = tuple(journal.affected_functions(record.transaction_id))
            live_after_image = bool(
                gateway.transaction_matches_after_image(record.transaction_id)
            )
            if record.database_identity != database_identity:
                restore_blocker = "Foreign database transaction."
            elif record.state.value in {
                "prepared",
                "script_running",
                "capture_pending",
                "captured",
                "analysis_pending",
                "restoring",
                "rolling_back",
            }:
                restore_blocker = (
                    f"Transaction is still running ({record.state.value})."
                )
            elif record.state.value != "idb_prepared":
                restore_blocker = (
                    f"Transaction state {record.state.value} is not restorable."
                )
            elif not live_after_image:
                restore_blocker = (
                    "Exact after-image is absent; IDB interference must be "
                    "reconciled first."
                )
            else:
                restore_blocker = ""
            transactions.append(
                PreparationTransactionSummary(
                    transaction_id=record.transaction_id.value,
                    database_identity=record.database_identity,
                    anchor_function_ea=record.anchor_function_ea,
                    script_id=record.script_id,
                    script_path=record.script_path,
                    script_source_sha256=record.script_source_sha256,
                    state=record.state.value,
                    bytes_changed=len(byte_deltas),
                    byte_ranges=self._coalesce_byte_ranges(
                        tuple(delta.ea for delta in byte_deltas)
                    ),
                    type_annotations=len(type_deltas),
                    affected_function_eas=affected,
                    live_after_image=live_after_image,
                    restore_allowed=not restore_blocker,
                    restore_blocker=restore_blocker,
                    recovery_required=record.state.value
                    in {"recovery_required", "restore_failed"},
                )
            )
        return PreparationWorkbenchSummary(
            database_identity=database_identity,
            scripts=tuple(scripts),
            transactions=tuple(transactions),
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

    def execute_preview_preparation(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        """Refresh source attestations without executing a script."""

        invalid = self._validate_request(
            request,
            expected_command="preview_preparation",
        )
        if invalid is not None:
            return invalid
        return self._result(
            request,
            status=OutcomeStatus.READY,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message="Preparation preview refreshed; no IDB writes were performed",
        )

    def execute_prepare_only(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        """Run preparation without requesting a Hex-Rays decompilation."""

        invalid = self._validate_preparation_request(
            request,
            expected_command="prepare_only",
        )
        if invalid is not None:
            return invalid
        try:
            from d810.manager.pre_hexrays_preparation import PreparationMode

            receipt = self._manager.prepare_idb_for_hexrays(
                request.function_ea,
                PreparationMode.PREPARE_ONLY,
            )
        except Exception as exc:
            return self._failure(request, f"Preparation failed: {exc}")
        if not receipt.ok:
            return self._failure(
                request,
                receipt.failure_reason or "Preparation did not complete",
            )
        return self._result(
            request,
            status=OutcomeStatus.CHANGED,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message="IDB preparation completed without decompiling",
        )

    def execute_prepare_and_decompile(
        self,
        request: WorkbenchCommandRequest,
        *,
        lifecycle: Callable[[], object],
    ) -> WorkbenchCommandResult:
        """Run the manager-owned preparation plus decompilation lifecycle."""

        invalid = self._validate_preparation_request(
            request,
            expected_command="prepare_and_decompile",
        )
        if invalid is not None:
            return invalid
        try:
            result = lifecycle()
        except Exception as exc:
            return self._failure(request, f"Prepare & Decompile failed: {exc}")
        if result is None:
            return self._failure(request, "Prepare & Decompile returned no cfunc")
        return self._result(
            request,
            status=OutcomeStatus.CHANGED,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message="IDB preparation and decompilation completed",
        )

    def execute_restore_preparation(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        """Restore one exact transaction selected from the immutable history."""

        invalid = self._validate_preparation_request(
            request,
            expected_command="restore_preparation",
            require_transaction=True,
            validate_sources=False,
        )
        if invalid is not None:
            return invalid
        assert request.transaction_id is not None
        summary = self._preparation(request.function_ea)
        selected = next(
            (
                transaction
                for transaction in summary.transactions
                if transaction.transaction_id == request.transaction_id
            ),
            None,
        )
        if selected is None:
            return self._failure(request, "Preparation transaction is unavailable")
        if not selected.restore_allowed:
            return self._failure(
                request,
                selected.restore_blocker or "Preparation transaction is not restorable",
            )
        try:
            from d810.capabilities.idb_preparation import PreparationTransactionId

            receipt = self._manager.restore_idb_preparation(
                PreparationTransactionId(request.transaction_id)
            )
        except Exception as exc:
            return self._failure(request, f"Restore failed: {exc}")
        if not receipt.ok:
            return self._failure(
                request,
                receipt.failure_reason or "Restore did not complete",
            )
        return self._result(
            request,
            status=OutcomeStatus.CHANGED,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message="Preparation transaction restored",
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

    def _validate_preparation_request(
        self,
        request: WorkbenchCommandRequest,
        *,
        expected_command: str,
        require_transaction: bool = False,
        validate_sources: bool = True,
    ) -> WorkbenchCommandResult | None:
        invalid = self._validate_request(request, expected_command=expected_command)
        if invalid is not None:
            return invalid
        summary = self._preparation(request.function_ea)
        if (
            summary.database_identity is None
            or request.database_identity != summary.database_identity
        ):
            return self._stale_result(
                request,
                succeeded=False,
                message="Preparation command belongs to another database identity",
            )
        if validate_sources:
            current_hashes = tuple(
                (script.script_id, script.current_source_sha256 or "")
                for script in summary.scripts
                if script.enabled
            )
            if request.script_source_hashes != current_hashes:
                return self._stale_result(
                    request,
                    succeeded=False,
                    message="Preparation script sources changed; preview again",
                )
            drifted = tuple(
                script.script_id
                for script in summary.scripts
                if script.enabled and not script.source_hash_matches
            )
            if drifted:
                return self._failure(
                    request,
                    "Preparation source attestation changed for: " + ", ".join(drifted),
                )
        if require_transaction and not request.transaction_id:
            return self._failure(request, "Select a preparation transaction first")
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
            suppressed_stages=tuple(
                str(value) for value in getattr(hints, "suppress_stages", ())
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

    def _execution_scope(
        self,
        *,
        function_ea: int,
        project_snapshot: ProjectRuntimeSnapshot,
    ) -> ExecutionScopeSummary:
        report_loader = getattr(self._manager, "get_effective_execution_report", None)
        report = report_loader(int(function_ea)) if callable(report_loader) else None
        if report is None:
            decisions = ()
            tags: tuple[str, ...] = ()
            inference_names: tuple[str, ...] = ()
            unknown_targets: tuple[str, ...] = ()
        else:
            decisions = tuple(
                EffectiveStageDecisionSummary(
                    pass_id=str(decision.pass_id),
                    stage_id=str(decision.stage_id),
                    pipeline=str(
                        getattr(decision.pipeline, "value", decision.pipeline)
                    ),
                    maturities=tuple(int(value) for value in decision.maturities),
                    active=bool(decision.active),
                    reason=str(decision.reason),
                    detail=str(decision.detail),
                )
                for decision in report.decisions
            )
            tags = tuple(str(value) for value in report.function_tags)
            inference_names = tuple(str(value) for value in report.inference_names)
            unknown_targets = tuple(str(value) for value in report.unknown_targets)
        return ExecutionScopeSummary(
            public_passes=tuple(project_snapshot.effective_pass_ids),
            function_tags=tags,
            inference_names=inference_names,
            decisions=decisions,
            unknown_targets=unknown_targets,
        )

    def _statistics(self) -> StatisticsSummary:
        stats = getattr(self._manager, "stats", None)
        report = stats.last_report() if stats is not None else {}
        report = report or {}
        private_matches = report.get("rule_matches", {})
        cfg_patches = report.get("cfg_patches", {})
        implementation_to_stage: dict[str, str] = {}
        for pass_id in self._registry.public_pass_ids():
            for stage in self._registry.stages_for(pass_id):
                implementation_to_stage.setdefault(
                    stage.implementation_name,
                    f"{pass_id}/{stage.stage_id}",
                )
        stage_matches: dict[str, int] = {}
        for implementation_name, count in private_matches.items():
            stage_name = implementation_to_stage.get(str(implementation_name))
            if stage_name is not None:
                stage_matches[stage_name] = stage_matches.get(stage_name, 0) + int(
                    count
                )
        stage_patches: dict[str, dict[str, int]] = {}
        for implementation_name, values in cfg_patches.items():
            stage_name = implementation_to_stage.get(str(implementation_name))
            if stage_name is not None:
                stage_patches[stage_name] = values
        return StatisticsSummary(
            stage_matches=tuple(
                CountEntry(str(name), int(count))
                for name, count in sorted(stage_matches.items())
            ),
            total_stage_firings=sum(stage_matches.values()),
            stage_patches=tuple(
                PatchCountEntry(
                    str(name),
                    int(values.get("uses", 0)),
                    int(values.get("total_patches", 0)),
                )
                for name, values in sorted(stage_patches.items())
            ),
        )

    def _execution_ledger(self, function_ea: int) -> ExecutionLedgerSummary:
        lifecycle = getattr(self._manager, "decompilation_lifecycle", None)
        journal = getattr(lifecycle, "execution_journal", None)
        latest_session = getattr(journal, "latest_session_for_function", None)
        attempts_for_session = getattr(journal, "attempts_for_session", None)
        if not callable(latest_session) or not callable(attempts_for_session):
            return ExecutionLedgerSummary(None, int(function_ea), (), 0, 0)
        session_id = latest_session(int(function_ea))
        if session_id is None:
            return ExecutionLedgerSummary(None, int(function_ea), (), 0, 0)
        attempts = attempts_for_session(session_id)
        summaries = tuple(
            ExecutionAttemptSummary(
                sequence=int(attempt.attempt_id.sequence),
                parent_sequence=(
                    None
                    if attempt.parent_attempt_id is None
                    else int(attempt.parent_attempt_id.sequence)
                ),
                stage_id=str(attempt.stage_id),
                domain=str(attempt.domain.value),
                status=str(attempt.status.value),
                reason_code=attempt.reason_code,
                elapsed_ms=attempt.elapsed_ms,
                effect_refs_json=_canonical_json(
                    [
                        {
                            "kind": ref.kind,
                            "ref_id": ref.ref_id,
                            "detail": _plain_json(ref.detail),
                        }
                        for ref in attempt.effect_refs
                    ]
                ),
                details_json=_canonical_json(_plain_json(attempt.details)),
            )
            for attempt in attempts
        )
        terminal = sum(item.status != "started" for item in summaries)
        return ExecutionLedgerSummary(
            session_id=str(session_id.value),
            function_ea=int(function_ea),
            attempts=summaries,
            terminal_attempts=terminal,
            in_progress_attempts=len(summaries) - terminal,
        )

    def _execution_profile(
        self,
        function_ea: int,
        attack: AttackSummary,
    ) -> ExecutionProfileSummary:
        """Project exact-key history for display; never return a scheduler port."""
        lifecycle = getattr(self._manager, "decompilation_lifecycle", None)
        journal = getattr(lifecycle, "execution_journal", None)
        latest_key = getattr(journal, "latest_native_key_for_function", None)
        attempts_for_key = getattr(journal, "attempts_for_native_key", None)
        if not callable(latest_key) or not callable(attempts_for_key):
            return ExecutionProfileSummary(None, (), 0)
        native_key = latest_key(int(function_ea))
        if native_key is None:
            return ExecutionProfileSummary(None, (), 0)
        attempts = attempts_for_key(native_key)
        dimensioned = tuple(
            attempt
            for attempt in attempts
            if isinstance(attempt.details.get("maturity"), str)
            and bool(attempt.details.get("maturity"))
            and isinstance(attempt.details.get("structural_shape"), str)
            and bool(attempt.details.get("structural_shape"))
        )
        if not dimensioned:
            return ExecutionProfileSummary(None, (), 0)
        latest_dimension = dimensioned[-1]
        key = ExecutionProfileKey(
            database_identity=native_key.input_identity,
            function_fingerprint=native_key.function_fingerprint,
            config_fingerprint=native_key.profile_fingerprint,
            toolchain_fingerprint=native_key.sdk_fingerprint,
            maturity=str(latest_dimension.details["maturity"]),
            structural_shape=str(latest_dimension.details["structural_shape"]),
        )
        preview = build_execution_profile_preview(key, attempts)
        return ExecutionProfileSummary(
            identity_json=_canonical_json(key.to_dict()),
            candidates=tuple(
                ExecutionProfileCandidateSummary(
                    stage_id=candidate.stage_id,
                    domain=candidate.domain.value,
                    attempt_count=candidate.attempt_count,
                    attempt_to_effect_rate=candidate.attempt_to_effect_rate,
                    p95_elapsed_ms=candidate.p95_elapsed_ms,
                    priority_score=candidate.priority_score,
                    proof_failure_count=candidate.proof_failure_count,
                    mean_reduction=candidate.mean_reduction,
                    reason_counts_json=_canonical_json(dict(candidate.reason_counts)),
                )
                for candidate in preview.candidates
            ),
            ignored_in_progress_count=preview.ignored_in_progress_count,
            ignored_identity_mismatch_count=(preview.ignored_identity_mismatch_count),
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
                kind="function-recipe-storage",
                label="Function recipe storage",
                value=storage_path,
            ),
        )


__all__ = ["WorkbenchService"]
