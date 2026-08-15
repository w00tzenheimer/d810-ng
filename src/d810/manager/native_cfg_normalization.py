"""Manager-owned collection and lifecycle for one Stage C pipeline run."""

from __future__ import annotations

from dataclasses import dataclass, replace

from d810.backends.ida.native_patch.native_cfg_plan import (
    build_native_cfg_plan,
    capture_database_attestation,
)
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.native_range_projection import NativeRange
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationRequest,
    NativeNormalizationResult,
    authorize_and_apply,
)
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.transforms.native_cfg_normalization import (
    FrozenNativeCfgTopology,
    NativeCfgFreezeReason,
    NativeCfgPassMutationObservation,
    NativeCfgTopologyFreezeOutcome,
    bind_ctree_native_ranges,
    freeze_native_cfg_topology as _freeze_native_cfg_topology,
)

__all__ = [
    "ManagerOwnedNativeCfgNormalizer",
    "NativeCfgNormalizationCollector",
    "StageCNormalizationResult",
]


class NativeCfgNormalizationCollector:
    """One exact-function, exact-key, exact-session Stage C observation owner."""

    def __init__(
        self,
        *,
        function_ea: int,
        native_key: NativePreanalysisKey,
        session_id: DecompilationSessionId,
        parent_attempt_id: ExecutionAttemptId | None = None,
    ) -> None:
        if not isinstance(function_ea, int) or isinstance(function_ea, bool):
            raise TypeError("function_ea must be an int")
        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("native_key must be a NativePreanalysisKey")
        if not isinstance(session_id, DecompilationSessionId):
            raise TypeError("session_id must be a DecompilationSessionId")
        self.function_ea = function_ea
        self.native_key = native_key
        self.session_id = session_id
        self.parent_attempt_id = parent_attempt_id
        self._observations: list[NativeCfgPassMutationObservation] = []
        self._outcome: NativeCfgTopologyFreezeOutcome | None = None
        self._scheduled_pass_ids: tuple[str, ...] = ()
        self._frozen = False
        self._transferred = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def scheduled_pass_ids(self) -> tuple[str, ...]:
        return self._scheduled_pass_ids

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("native CFG collector is closed")

    def observe_native_cfg_mutation(
        self,
        observation: NativeCfgPassMutationObservation,
    ) -> None:
        self._require_open()
        if self._frozen:
            raise RuntimeError("native CFG collector is already frozen")
        if not isinstance(observation, NativeCfgPassMutationObservation):
            raise TypeError("observation must be a NativeCfgPassMutationObservation")
        if (
            observation.pre_graph.func_ea != self.function_ea
            or observation.post_graph.func_ea != self.function_ea
        ):
            raise ValueError("native CFG observation function mismatch")
        self._observations.append(observation)

    def freeze_native_cfg_topology(
        self,
        *,
        function_ea: int,
        maturity: IRMaturity,
        baseline_graph: FlowGraph,
        final_graph: FlowGraph,
        scheduled_pass_ids: tuple[str, ...],
    ) -> FrozenNativeCfgTopology | None:
        self._require_open()
        if self._frozen:
            raise RuntimeError("native CFG collector is already frozen")
        if not isinstance(scheduled_pass_ids, tuple) or not all(
            isinstance(pass_id, str) and pass_id.strip()
            for pass_id in scheduled_pass_ids
        ):
            raise TypeError("scheduled_pass_ids must contain non-empty strings")
        self._frozen = True
        self._scheduled_pass_ids = scheduled_pass_ids
        if function_ea != self.function_ea:
            self._outcome = NativeCfgTopologyFreezeOutcome(
                reason=NativeCfgFreezeReason.FUNCTION_MISMATCH
            )
            return None
        self._outcome = _freeze_native_cfg_topology(
            function_ea=function_ea,
            maturity=maturity,
            baseline_graph=baseline_graph,
            final_graph=final_graph,
            observations=tuple(self._observations),
        )
        return self._outcome.topology

    def take_topology_outcome(self) -> NativeCfgTopologyFreezeOutcome:
        self._require_open()
        if self._transferred:
            raise RuntimeError("native CFG topology outcome was already transferred")
        self._transferred = True
        if self._outcome is None:
            self._outcome = NativeCfgTopologyFreezeOutcome(
                reason=NativeCfgFreezeReason.MISSING_PIPELINE_FREEZE
            )
        return self._outcome

    def close(self) -> None:
        if self._closed:
            return
        self._observations.clear()
        self._closed = True


@dataclass(frozen=True, slots=True)
class StageCNormalizationResult:
    normalization: NativeNormalizationResult | None
    allow_stage_b: bool
    reason: str
    validated_cfunc: object | None = None


class ManagerOwnedNativeCfgNormalizer:
    """Turn one closed Stage C observation into one gateway transaction."""

    def __init__(
        self,
        *,
        gateway,
        execution_journal,
        reader,
        origin_mapper,
        encoder,
        input_attestation,
        capture_ranges,
        fingerprint_ctree,
        post_apply_observer,
        capture_attestation=capture_database_attestation,
        bind_ranges=bind_ctree_native_ranges,
        build_plan=build_native_cfg_plan,
        apply_plan=None,
    ) -> None:
        self._gateway = gateway
        self._execution_journal = execution_journal
        self._reader = reader
        self._origin_mapper = origin_mapper
        self._encoder = encoder
        self._input_attestation = input_attestation
        self._capture_ranges = capture_ranges
        self._fingerprint_ctree = fingerprint_ctree
        self._post_apply_observer = post_apply_observer
        self._capture_attestation = capture_attestation
        self._bind_ranges = bind_ranges
        self._build_plan = build_plan
        self._apply_plan = apply_plan

    def normalize(
        self,
        *,
        function_ea: int,
        topology_outcome: NativeCfgTopologyFreezeOutcome,
        decompilation_result: object,
        parent_attempt_id: ExecutionAttemptId,
    ) -> StageCNormalizationResult:
        attempt = self._execution_journal.begin_attempt(
            parent_attempt_id.session,
            parent_attempt_id=parent_attempt_id,
            stage_id="stage_c_native_cfg_normalizer",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
        if topology_outcome.topology is None:
            reason = (
                topology_outcome.reason.value
                if topology_outcome.reason is not None
                else "MISSING_PIPELINE_FREEZE"
            )
            if topology_outcome.detail:
                reason = f"{reason}: {topology_outcome.detail}"
            return self._abstain(attempt, reason)
        transaction_started = False
        validated_cfunc = None
        try:
            attestation = self._capture_attestation(
                function_ea=int(function_ea),
                reader=self._reader,
                input_attestation=self._input_attestation,
                authorizing_attempt_id=attempt.attempt_id,
            )
            if attestation is None:
                return self._abstain(attempt, "FUNCTION_ATTESTATION_UNAVAILABLE")
            function_ranges = tuple(
                NativeRange(item.start_ea, item.end_ea)
                for item in attestation.function_identity.chunk_ranges
            )
            target_projection = self._capture_ranges(
                decompilation_result,
                function_ranges=function_ranges,
            )
            target_structure = self._fingerprint_ctree(decompilation_result)
            bound = self._bind_ranges(
                frozen=topology_outcome.topology,
                target_projection=target_projection,
            )
            if bound.intent is None:
                reason = (
                    bound.reason.value if bound.reason is not None else "BIND_FAILED"
                )
                if bound.detail:
                    reason = f"{reason}: {bound.detail}"
                return self._abstain(attempt, reason)
            built = self._build_plan(
                intent=bound.intent,
                reader=self._reader,
                origin_mapper=self._origin_mapper,
                encoder=self._encoder,
                attestation=attestation,
            )
            if built.plan is None:
                return self._abstain(attempt, str(built.reason))
            plan = built.plan
            diagnostic_id = self._gateway.record_diagnostic_snapshot(plan)
            outcome = (
                self._apply_plan(plan)
                if self._apply_plan is not None
                else authorize_and_apply(
                    NativeNormalizationRequest(plan=plan, user_enabled=True),
                    gateway=self._gateway,
                )
            )
            transaction_started = outcome.apply_receipt is not None
            effects = [
                ExecutionEffectRef("native_patch_proposal", plan.plan_id),
                ExecutionEffectRef("native_patch_diagnostic_snapshot", diagnostic_id),
            ]
            if outcome.apply_receipt is not None:
                effects.append(
                    ExecutionEffectRef(
                        "native_patch_transaction",
                        outcome.apply_receipt.transaction_id.value,
                    )
                )
            if outcome.outcome is NativeNormalizationOutcome.APPLIED:
                try:
                    (
                        post_projection,
                        post_structure,
                        native_cfg_postcondition,
                        validated_cfunc,
                    ) = self._post_apply_observer(
                        function_ea=int(function_ea),
                        function_ranges=function_ranges,
                        plan=plan,
                        target_graph=topology_outcome.topology.final_graph,
                    )
                except Exception as error:
                    mismatch = (
                        "CTREE_POSTCONDITION_CAPTURE_FAILED: "
                        f"{type(error).__name__}: {error}"
                    )
                    restore = self._gateway.restore(
                        outcome.apply_receipt.transaction_id
                    )
                    if not restore.ok:
                        restore_reason = restore.failure_reason or restore.state.value
                        mismatch = f"{mismatch}; RESTORE_INCOMPLETE: {restore_reason}"
                    effects.append(
                        ExecutionEffectRef(
                            "native_patch_restore", restore.transaction_id.value
                        )
                    )
                    self._execution_journal.advance(
                        attempt,
                        status=ExecutionAttemptStatus.FAILED,
                        reason_code=mismatch,
                        effect_refs=tuple(effects),
                        details={"function_ea": int(function_ea)},
                    )
                    rejected = NativeNormalizationResult(
                        outcome=NativeNormalizationOutcome.REJECTED,
                        apply_receipt=outcome.apply_receipt,
                        certificate=None,
                        reason=mismatch,
                    )
                    return StageCNormalizationResult(rejected, False, mismatch)
                mismatch = None
                if not native_cfg_postcondition.matches:
                    mismatch = (
                        "NATIVE_CFG_POSTCONDITION_MISMATCH: "
                        f"{native_cfg_postcondition.reason or 'fingerprint mismatch'}; "
                        "expected="
                        f"{native_cfg_postcondition.expected.fingerprint}; "
                        "observed="
                        f"{native_cfg_postcondition.observed.fingerprint}"
                    )
                elif post_projection.fingerprint != target_projection.fingerprint:
                    mismatch = "CTREE_RANGE_POSTCONDITION_MISMATCH"
                elif post_structure != target_structure:
                    mismatch = "CTREE_STRUCTURE_POSTCONDITION_MISMATCH"
                if mismatch is None:
                    try:
                        receipt_id, updated_certificate = (
                            self._gateway.record_native_cfg_postcondition_receipt(
                                plan=plan,
                                certificate=outcome.certificate,
                                transaction_id=outcome.apply_receipt.transaction_id,
                                observed_native_cfg_fingerprint=(
                                    native_cfg_postcondition.observed.fingerprint
                                ),
                                live_flowchart_fingerprint=(
                                    native_cfg_postcondition.live_flowchart_fingerprint
                                ),
                            )
                        )
                        effects.append(
                            ExecutionEffectRef("native_cfg_postcondition", receipt_id)
                        )
                        outcome = replace(outcome, certificate=updated_certificate)
                    except Exception as error:
                        mismatch = (
                            "NATIVE_CFG_POSTCONDITION_PERSIST_FAILED: "
                            f"{type(error).__name__}: {error}"
                        )
                if mismatch is not None:
                    restore = self._gateway.restore(
                        outcome.apply_receipt.transaction_id
                    )
                    if not restore.ok:
                        restore_reason = restore.failure_reason or restore.state.value
                        mismatch = f"{mismatch}; RESTORE_INCOMPLETE: {restore_reason}"
                    effects.append(
                        ExecutionEffectRef(
                            "native_patch_restore", restore.transaction_id.value
                        )
                    )
                    self._execution_journal.advance(
                        attempt,
                        status=ExecutionAttemptStatus.FAILED,
                        reason_code=mismatch,
                        effect_refs=tuple(effects),
                        details={"function_ea": int(function_ea)},
                    )
                    rejected = NativeNormalizationResult(
                        outcome=NativeNormalizationOutcome.REJECTED,
                        apply_receipt=outcome.apply_receipt,
                        certificate=None,
                        reason=mismatch,
                    )
                    return StageCNormalizationResult(rejected, False, mismatch)
            status = {
                NativeNormalizationOutcome.APPLIED: ExecutionAttemptStatus.COMPLETED,
                NativeNormalizationOutcome.ALREADY_NORMALIZED: ExecutionAttemptStatus.ABSTAINED,
                NativeNormalizationOutcome.REJECTED: ExecutionAttemptStatus.REJECTED,
            }.get(outcome.outcome, ExecutionAttemptStatus.ABSTAINED)
            self._execution_journal.advance(
                attempt,
                status=status,
                reason_code=outcome.reason or outcome.outcome.value,
                effect_refs=tuple(effects),
                details={"function_ea": int(function_ea)},
            )
            allow_stage_b = (
                outcome.outcome is NativeNormalizationOutcome.REJECTED
                and not transaction_started
                and outcome.certificate is None
            )
            return StageCNormalizationResult(
                outcome,
                allow_stage_b,
                outcome.reason or outcome.outcome.value,
                validated_cfunc=(
                    validated_cfunc
                    if outcome.outcome is NativeNormalizationOutcome.APPLIED
                    else None
                ),
            )
        except Exception as error:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.FAILED,
                reason_code=f"{type(error).__name__}: {error}",
                details={"function_ea": int(function_ea)},
            )
            raise

    def _abstain(self, attempt, reason: str) -> StageCNormalizationResult:
        self._execution_journal.advance(
            attempt,
            status=ExecutionAttemptStatus.ABSTAINED,
            reason_code=reason,
        )
        return StageCNormalizationResult(None, True, reason)
