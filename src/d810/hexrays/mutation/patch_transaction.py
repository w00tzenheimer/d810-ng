"""Production participant for immutable PatchPlan CFG transactions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from d810.analyses.control_flow.graph_checks import (
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgGenerationPoisoned,
    CfgProjection,
    PatchPlanExecutionResult,
    PreparedCfgTransaction,
    TransactionAttemptId,
)
from d810.transforms.contract import CfgContract
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.plan import PatchLowerConditionalStateTransition, PatchPlan
from d810.hexrays.mutation.patch_binding import BoundPatchPlan, bind_patch_plan
from d810.hexrays.mutation.semantic_ownership import (
    find_patch_plan_semantic_ownership_overlap,
    format_patch_plan_semantic_ownership_overlap,
)


def _has_dispatcher_removal_obligation(plan_metadata: object) -> bool:
    """Whether a plan claims exact full dispatcher-corridor retirement."""
    if not isinstance(plan_metadata, dict):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    )

    coverage = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    if not isinstance(coverage, dict):
        return False
    raw_covered_corridors = coverage.get("covered_corridors")
    raw_residual_corridors = coverage.get("residual_corridors")
    if not isinstance(raw_covered_corridors, (tuple, list)) or not isinstance(
        raw_residual_corridors, (tuple, list)
    ):
        return False
    residual_corridors = tuple(raw_residual_corridors)
    return (
        bool(coverage.get("enumeration_complete", False))
        and not residual_corridors
        and coverage.get("planned_completion_status")
        == "planned_dispatcher_corridors_covered"
    )


def _has_dispatcher_coverage_metadata(plan_metadata: object) -> bool:
    if not isinstance(plan_metadata, Mapping):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    )

    return DISPATCHER_CORRIDOR_COVERAGE_METADATA in plan_metadata


def _has_dispatcher_removal_proof_metadata(plan_metadata: object) -> bool:
    if not isinstance(plan_metadata, Mapping):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    )

    return DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA in plan_metadata


def _conditional_lowering_projection_failure(
    plan: PatchPlan,
    snapshot: FlowGraph,
) -> str | None:
    """Return a fail-closed reason for an unresolvable typed lowering."""
    source_coordinates = dict(plan.source_coordinates)
    for step in plan.steps:
        match step:
            case PatchLowerConditionalStateTransition(
                source_serial=source,
                old_dispatcher_serial=old_dispatcher,
                false_target_serial=false_target,
                true_target_serial=true_target,
            ):
                refs = (
                    ("source_serial", source),
                    ("old_dispatcher_serial", old_dispatcher),
                    ("false_target_serial", false_target),
                    ("true_target_serial", true_target),
                )
            case _:
                continue
        missing: list[str] = []
        for field_name, ref in refs:
            if isinstance(ref, int) and not isinstance(ref, bool):
                serial = int(ref)
            else:
                serial = source_coordinates.get(ref)
            if serial is None:
                missing.append(field_name)
            elif int(serial) not in snapshot.blocks:
                missing.append(f"{field_name}={int(serial)}")
        if missing:
            return "missing source coordinates: " + ", ".join(missing)
    return None


class PatchTransactionPreflightRejected(RuntimeError):
    """An immutable PatchPlan obligation failed before any SDK write."""

    def __init__(
        self,
        message: str,
        *,
        projected_dispatcher_removal_validation: object | None = None,
        projected_dispatcher_coverage_validation: object | None = None,
    ) -> None:
        super().__init__(message)
        self.projected_dispatcher_removal_validation = (
            projected_dispatcher_removal_validation
        )
        self.projected_dispatcher_coverage_validation = (
            projected_dispatcher_coverage_validation
        )


class PatchTransactionPostObservationRejected(RuntimeError):
    """The realized live graph lost a preflighted reachability obligation."""

    def __init__(
        self,
        message: str,
        *,
        observed_dispatcher_removal_validation: object | None = None,
        observed_dispatcher_coverage_validation: object | None = None,
    ) -> None:
        super().__init__(message)
        self.observed_dispatcher_removal_validation = (
            observed_dispatcher_removal_validation
        )
        self.observed_dispatcher_coverage_validation = (
            observed_dispatcher_coverage_validation
        )


class PatchTransactionPoisoned(CfgGenerationPoisoned):
    """Poisoned live generation carrying already-observed CFG verdicts."""

    def __init__(
        self,
        failure: object,
        *,
        observed_dispatcher_removal_validation: object | None = None,
        observed_dispatcher_coverage_validation: object | None = None,
    ) -> None:
        super().__init__(failure)
        self.observed_dispatcher_removal_validation = (
            observed_dispatcher_removal_validation
        )
        self.observed_dispatcher_coverage_validation = (
            observed_dispatcher_coverage_validation
        )


@dataclass(frozen=True, slots=True)
class PatchTransactionExecution(PatchPlanExecutionResult):
    """Committed ordinary PatchPlan result returned by the shared coordinator."""

    applied_count: int
    graph: FlowGraph
    receipt: object
    creation_receipts: tuple[object, ...] = ()
    projected_dispatcher_removal_validation: object | None = None
    projected_dispatcher_coverage_validation: object | None = None
    observed_dispatcher_removal_validation: object | None = None
    observed_dispatcher_coverage_validation: object | None = None

    def __post_init__(self) -> None:
        PatchPlanExecutionResult.__post_init__(self)
        if self.applied_count <= 0:
            raise ValueError("patch execution requires a positive applied count")


@dataclass(frozen=True, slots=True)
class BoundPatchCfgTransaction(BoundCfgTransaction):
    """Generic transaction authority plus the exact final-boundary binding."""

    plan: PatchPlan | None = None
    patch_binding: BoundPatchPlan | None = None

    def __post_init__(self) -> None:
        BoundCfgTransaction.__post_init__(self)
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("bound patch transaction requires a PatchPlan")
        if not isinstance(self.patch_binding, BoundPatchPlan):
            raise TypeError("bound patch transaction requires final live binding")
        if (
            self.patch_binding.plan is not self.plan
            or self.patch_binding.attempt_id != self.prepared.attempt_id
            or self.patch_binding.session_id != self.session_id
            or self.patch_binding.generation != self.generation
            or self.patch_binding.bindings != self.bindings
        ):
            raise ValueError("bound patch transaction authority differs")


@dataclass(slots=True)
class HexRaysPatchTransactionParticipant:
    """Project, preflight, bind, realize, and observe one live PatchPlan."""

    gateway: object
    translator: object
    mba: object
    plan: PatchPlan
    contract: object | None = None
    post_apply_hook: object | None = None
    attempt_authority: TransactionAttemptId | None = None
    attempt_id: TransactionAttemptId = field(init=False)
    _projection: CfgProjection | None = field(default=None, init=False, repr=False)
    _snapshot: FlowGraph | None = field(default=None, init=False, repr=False)
    _prepared: PreparedCfgTransaction | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _bound: BoundPatchCfgTransaction | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _applied_count: int | None = field(default=None, init=False, repr=False)
    _observed_dispatcher_removal_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _observed_dispatcher_coverage_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _projected_dispatcher_removal_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _projected_dispatcher_coverage_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("patch participant requires a PatchPlan")
        identity_index = getattr(self.gateway, "identity_index", None)
        if identity_index is None:
            raise TypeError("patch participant requires an identity index")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch participant requires an idle gateway")
        expected_session_id = str(self.gateway.session_id)
        expected_generation = int(self.gateway.generation)
        attempt_authority = self.attempt_authority
        if attempt_authority is None:
            self.attempt_id = TransactionAttemptId.new(
                self.plan.plan_id,
                expected_session_id,
                expected_generation,
            )
        else:
            if not isinstance(attempt_authority, TransactionAttemptId):
                raise TypeError("patch participant requires TransactionAttemptId authority")
            if (
                attempt_authority.plan_id != self.plan.plan_id
                or attempt_authority.session_id != expected_session_id
                or attempt_authority.generation != expected_generation
            ):
                raise ValueError("patch participant attempt authority differs")
            self.attempt_id = attempt_authority

    def project(self, plan: object, snapshot: object) -> CfgProjection:
        if plan is not self.plan:
            raise ValueError("patch projection changed exact plan authority")
        if not isinstance(snapshot, FlowGraph):
            raise TypeError("patch projection requires an immutable FlowGraph")
        if self._projection is not None:
            raise RuntimeError("patch projection authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch projection requires an idle gateway")
        lowering_projection_failure = _conditional_lowering_projection_failure(
            self.plan,
            snapshot,
        )
        if lowering_projection_failure is not None:
            raise PatchTransactionPreflightRejected(
                "conditional state lowering projection rejected: "
                f"{lowering_projection_failure}"
            )
        self.gateway._record_cfg_attempt_planned(
            plan_id=self.plan.plan_id,
            plan_refs=tuple(spec.block_id for spec in self.plan.new_blocks),
            attempt=self.attempt_id,
        )
        projection = project_patch_plan(
            snapshot,
            self.plan,
            snapshot_id=self.plan.snapshot_id,
        )
        self.gateway._record_cfg_projected()
        self._snapshot = snapshot
        self._projection = projection
        return projection

    def _reject_committed_semantic_overlap(self) -> None:
        authority = getattr(self.gateway, "lifecycle_authority", None)
        if authority is None:
            return
        overlap = find_patch_plan_semantic_ownership_overlap(
            self.plan,
            self.gateway.identity_index,
            authority.committed_semantic_ownership(),
        )
        if overlap is not None:
            raise PatchTransactionPreflightRejected(
                format_patch_plan_semantic_ownership_overlap(overlap)
            )

    def preflight(self, projection: CfgProjection) -> PreparedCfgTransaction:
        if projection is not self._projection:
            raise ValueError("patch preflight changed immutable projection authority")
        if self._prepared is not None:
            raise RuntimeError("patch preflight authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch preflight requires an idle gateway")
        snapshot = self._snapshot
        if snapshot is None:
            raise RuntimeError("patch preflight lacks immutable source snapshot")
        self._reject_committed_semantic_overlap()
        terminal_reachability = check_terminal_reachability_preserved(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        entry_allowance_passed = False
        entry_allowance_reason: str | None = None
        entry_allowance = None
        projected_coverage_validation = None
        plan_metadata = self.plan.metadata_dict()
        if _has_dispatcher_coverage_metadata(plan_metadata):
            from d810.transforms.dispatcher_corridor_coverage import (
                has_unreachable_cyclic_switch_dispatcher_residue,
                validate_dispatcher_corridor_coverage_metadata,
                validate_dispatcher_removal_preflight_proof,
                validate_terminal_switch_cycle_break_allowance,
            )

            projected_coverage_validation = (
                validate_dispatcher_corridor_coverage_metadata(
                    snapshot,
                    post_graph=projection.graph,
                    plan_metadata=plan_metadata,
                )
            )
            self._projected_dispatcher_coverage_validation = (
                projected_coverage_validation
            )
            projected_switch_cycle_hazard = (
                has_unreachable_cyclic_switch_dispatcher_residue(
                    snapshot,
                    post_graph=projection.graph,
                    plan_metadata=plan_metadata,
                )
            )
        else:
            projected_switch_cycle_hazard = False
        dispatcher_removal_obligation = _has_dispatcher_removal_obligation(
            plan_metadata
        )
        has_dispatcher_removal_proof = _has_dispatcher_removal_proof_metadata(
            plan_metadata
        )
        if _has_dispatcher_coverage_metadata(plan_metadata) and (
            not entry_reachability.passed or has_dispatcher_removal_proof
        ):
            candidate_allowance = validate_dispatcher_removal_preflight_proof(
                snapshot,
                post_graph=projection.graph,
                plan_metadata=plan_metadata,
            )
            candidate_allowance = validate_terminal_switch_cycle_break_allowance(
                snapshot,
                post_graph=projection.graph,
                patch_plan=self.plan,
                removal_validation=candidate_allowance,
            )
            if (
                not entry_reachability.passed
                or projected_switch_cycle_hazard
                or candidate_allowance.passed
            ):
                entry_allowance = candidate_allowance
                self._projected_dispatcher_removal_validation = entry_allowance
                entry_allowance_reason = entry_allowance.reason
                if terminal_reachability.passed:
                    entry_allowance_passed = entry_allowance.passed
        dispatcher_removal_rejected = (
            dispatcher_removal_obligation
            and (
                projected_switch_cycle_hazard
                or (
                    not entry_reachability.passed
                    and (entry_allowance is None or not entry_allowance.passed)
                )
            )
        )
        projected_coverage_rejected = (
            projected_coverage_validation is not None
            and not projected_coverage_validation.passed
        )
        if not terminal_reachability.passed or (
            not entry_reachability.passed and not entry_allowance_passed
        ) or dispatcher_removal_rejected or projected_coverage_rejected:
            dispatcher_removal_detail = (
                ""
                if entry_allowance_reason is None
                else f"; dispatcher_removal={entry_allowance_reason}"
            )
            if (
                projected_coverage_validation is not None
                and not projected_coverage_validation.passed
            ):
                dispatcher_removal_detail += (
                    "; dispatcher_coverage="
                    f"{projected_coverage_validation.reason}"
                )
            raise PatchTransactionPreflightRejected(
                "projected reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"entry={entry_reachability.reason}"
                f"{dispatcher_removal_detail}",
                projected_dispatcher_removal_validation=entry_allowance,
                projected_dispatcher_coverage_validation=(
                    projected_coverage_validation
                ),
            )
        contract = self.contract
        if contract is None:
            CfgContract().verify_projection(projection, scope="full")
            obligations = ("cfg_projection",)
        else:
            contract.verify_projection(projection, scope="full")
            contract.verify(self.mba, projection=projection, phase="pre")
            obligations = ("cfg_projection", "live_pre_check")
        prepared = PreparedCfgTransaction(
            attempt_id=self.attempt_id,
            projection=projection,
            obligation_ids=obligations,
        )
        self.gateway._record_cfg_preflighted()
        self._prepared = prepared
        return prepared

    def bind(
        self,
        prepared: PreparedCfgTransaction,
        identity_index: object,
    ) -> BoundCfgTransaction:
        if prepared is not self._prepared:
            raise ValueError("patch binding changed immutable preflight authority")
        if identity_index is not self.gateway.identity_index:
            raise ValueError("patch binding received a foreign identity index")
        if self._bound is not None:
            raise RuntimeError("patch binding authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch binding requires an idle gateway")
        self.gateway._prepare_patch_binding(
            prepared.attempt_id,
            serial_quantity=int(getattr(self.mba, "qty", 0) or 0),
        )
        patch_binding = bind_patch_plan(
            self.plan,
            identity_index,
            prepared.attempt_id,
        )
        self.gateway.register_patch_plan_reservations(patch_binding.reservations)
        self.gateway._record_cfg_bound()
        bound = BoundPatchCfgTransaction(
            prepared=prepared,
            session_id=prepared.attempt_id.session_id,
            generation=prepared.attempt_id.generation,
            bindings=patch_binding.bindings,
            plan=self.plan,
            patch_binding=patch_binding,
        )
        self._bound = bound
        return bound

    def realize(self, bound: BoundCfgTransaction, gateway: object) -> object:
        if bound is not self._bound:
            raise ValueError("patch realization changed exact binding authority")
        if gateway is not self.gateway:
            raise ValueError("patch realization received a foreign gateway")
        return self.translator.lower(
            self.plan,
            self.mba,
            mutation_gateway=self.gateway,
            bound_transaction=bound,
            post_apply_hook=self.post_apply_hook,
        )

    def observe(self, receipt: object, live_graph: object) -> FlowGraph:
        if live_graph is not self.mba:
            raise ValueError("patch observation received a foreign live graph")
        if not isinstance(receipt, int) or isinstance(receipt, bool) or receipt <= 0:
            raise TypeError("patch observation requires a positive realization count")
        if self._bound is None:
            raise RuntimeError("patch observation lacks exact binding authority")
        observed = self.translator.lift(self.mba)
        if not isinstance(observed, FlowGraph):
            raise TypeError("patch observation requires a portable FlowGraph")
        self.gateway.observe_patch_realization(
            observed,
            applied_operation_count=receipt,
        )
        self._applied_count = receipt
        return observed

    @property
    def applied_count(self) -> int:
        if self._applied_count is None:
            raise RuntimeError("patch participant has no observed operation count")
        return self._applied_count


def _first_failure(error: Exception, phase: str) -> tuple[str, str]:
    reason = str(error) or type(error).__name__
    return reason, f"runtime:{phase}"


def _request_poison_restart(gateway: object, failure: object) -> None:
    authority = getattr(gateway, "lifecycle_authority", None)
    if authority is None:
        return
    request = getattr(authority, "request_cfg_generation_restart", None)
    if not callable(request):
        raise TypeError("CFG lifecycle authority lacks poisoned restart control")
    request(failure.attempt_id, failure)


@dataclass(slots=True)
class _PatchTransactionLifecycle:
    participant: HexRaysPatchTransactionParticipant
    bound: BoundPatchCfgTransaction
    gateway: object
    plan: PatchPlan
    prepared: PreparedCfgTransaction
    failure_phase: str = "begin"

    def begin(self, patch_plan: PatchPlan) -> BoundPatchCfgTransaction:
        self.failure_phase = "begin"
        if patch_plan is not self.plan or self.bound.prepared is not self.prepared:
            raise ValueError("coordinator changed exact patch authority")
        return self.bound

    def realize(
        self,
        patch_plan: PatchPlan,
        begun: BoundPatchCfgTransaction,
    ) -> object:
        self.failure_phase = "realization"
        if patch_plan is not self.plan or begun is not self.bound:
            raise ValueError("patch realization changed coordinator authority")
        return self.participant.realize(begun, self.gateway)

    def observe(self, patch_plan: PatchPlan, realized: object) -> FlowGraph:
        self.failure_phase = "observation"
        if patch_plan is not self.plan:
            raise ValueError("patch observation changed coordinator authority")
        return self.participant.observe(realized, self.participant.mba)

    def validate(self, patch_plan: PatchPlan, observed: object) -> FlowGraph:
        self.failure_phase = "post_observation_contract"
        if patch_plan is not self.plan or not isinstance(observed, FlowGraph):
            raise TypeError("patch validation requires its observed FlowGraph")
        source = self.participant._snapshot
        if source is None:
            raise RuntimeError("patch validation lacks immutable source authority")
        observed_validation_graph = observed
        plan_metadata = self.plan.metadata_dict()
        has_conditional_lowering = False
        for step in self.plan.steps:
            match step:
                case PatchLowerConditionalStateTransition():
                    has_conditional_lowering = True
                    break
        if has_conditional_lowering:
            from d810.transforms.dispatcher_corridor_coverage import (
                DispatcherCorridorCoverageValidation,
                canonicalize_observed_dispatcher_graph,
            )

            try:
                observed_validation_graph = canonicalize_observed_dispatcher_graph(
                    source,
                    observed,
                    self.plan,
                )
            except ValueError as error:
                observed_coverage_validation = (
                    DispatcherCorridorCoverageValidation(
                        passed=False,
                        reason="dispatcher_corridor_coverage_identity_drift",
                        function_ea=int(source.func_ea),
                    )
                    if _has_dispatcher_coverage_metadata(plan_metadata)
                    else None
                )
                self.participant._observed_dispatcher_coverage_validation = (
                    observed_coverage_validation
                )
                raise PatchTransactionPostObservationRejected(
                    f"observed CFG identity rejected: {error}",
                    observed_dispatcher_coverage_validation=(
                        observed_coverage_validation
                    ),
                ) from error
        terminal_reachability = check_terminal_reachability_preserved(
            source,
            post_cfg=observed_validation_graph,
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            source,
            post_cfg=observed_validation_graph,
        )
        entry_allowance_passed = False
        observed_validation = None
        observed_coverage_validation = None
        if _has_dispatcher_coverage_metadata(plan_metadata):
            from d810.transforms.dispatcher_corridor_coverage import (
                has_unreachable_cyclic_switch_dispatcher_residue,
                validate_dispatcher_corridor_coverage_metadata,
                validate_dispatcher_removal_preflight_proof,
                validate_terminal_switch_cycle_break_allowance,
            )

            observed_coverage_validation = (
                validate_dispatcher_corridor_coverage_metadata(
                    source,
                    post_graph=observed_validation_graph,
                    plan_metadata=plan_metadata,
                )
            )
            self.participant._observed_dispatcher_coverage_validation = (
                observed_coverage_validation
            )
            observed_switch_cycle_hazard = (
                has_unreachable_cyclic_switch_dispatcher_residue(
                    source,
                    post_graph=observed_validation_graph,
                    plan_metadata=plan_metadata,
                )
            )
        else:
            observed_switch_cycle_hazard = False
        dispatcher_removal_obligation = _has_dispatcher_removal_obligation(
            plan_metadata
        )
        has_dispatcher_removal_proof = _has_dispatcher_removal_proof_metadata(
            plan_metadata
        )
        if _has_dispatcher_coverage_metadata(plan_metadata) and (
            not entry_reachability.passed or has_dispatcher_removal_proof
        ):
            candidate_validation = validate_dispatcher_removal_preflight_proof(
                source,
                post_graph=observed_validation_graph,
                plan_metadata=plan_metadata,
            )
            candidate_validation = validate_terminal_switch_cycle_break_allowance(
                source,
                post_graph=observed_validation_graph,
                patch_plan=self.plan,
                removal_validation=candidate_validation,
            )
            if (
                not entry_reachability.passed
                or observed_switch_cycle_hazard
                or candidate_validation.passed
            ):
                observed_validation = candidate_validation
                self.participant._observed_dispatcher_removal_validation = (
                    observed_validation
                )
                if terminal_reachability.passed:
                    entry_allowance_passed = observed_validation.passed
        observed_removal_rejected = (
            dispatcher_removal_obligation
            and (
                observed_switch_cycle_hazard
                or (
                    not entry_reachability.passed
                    and (
                        observed_validation is None
                        or not observed_validation.passed
                    )
                )
            )
        )
        # A partial plan may lack a narrow full-retirement proof, but coverage
        # is still an applied diagnostic claim.  Recompute it from the observed
        # graph independently of proof validity before any applied publication.
        observed_coverage_rejected = (
            observed_coverage_validation is not None
            and not observed_coverage_validation.passed
        )
        if not terminal_reachability.passed or (
            not entry_reachability.passed and not entry_allowance_passed
        ) or observed_removal_rejected or observed_coverage_rejected:
            detail = (
                ""
                if observed_validation is None
                else f"; dispatcher_removal={observed_validation.reason}"
            )
            if (
                observed_coverage_validation is not None
                and not observed_coverage_validation.passed
            ):
                detail += (
                    "; dispatcher_coverage="
                    f"{observed_coverage_validation.reason}"
                )
            raise PatchTransactionPostObservationRejected(
                "observed reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"entry={entry_reachability.reason}{detail}",
                observed_dispatcher_removal_validation=observed_validation,
                observed_dispatcher_coverage_validation=(
                    observed_coverage_validation
                ),
            )
        post_projection = CfgProjection(
            plan_id=self.prepared.projection.plan_id,
            snapshot_id=self.prepared.projection.snapshot_id,
            graph=observed_validation_graph,
            focus_refs=self.prepared.projection.focus_refs,
        )
        contract = self.participant.contract
        if contract is None:
            CfgContract().verify_projection(post_projection, scope="full")
        else:
            contract.verify_projection(post_projection, scope="full")
        return observed

    def commit(
        self,
        patch_plan: PatchPlan,
        validated: object,
    ) -> PatchTransactionExecution:
        self.failure_phase = "commit"
        if patch_plan is not self.plan or not isinstance(validated, FlowGraph):
            raise TypeError("patch commit requires its validated FlowGraph")
        creation_receipts = tuple(self.gateway.plan_creation_receipts)
        receipt = self.gateway.commit()
        return PatchTransactionExecution(
            applied_count=self.participant.applied_count,
            graph=validated,
            receipt=receipt,
            creation_receipts=creation_receipts,
            projected_dispatcher_removal_validation=(
                self.participant._projected_dispatcher_removal_validation
            ),
            projected_dispatcher_coverage_validation=(
                self.participant._projected_dispatcher_coverage_validation
            ),
            observed_dispatcher_removal_validation=(
                self.participant._observed_dispatcher_removal_validation
            ),
            observed_dispatcher_coverage_validation=(
                self.participant._observed_dispatcher_coverage_validation
            ),
        )

    def fail(self, patch_plan: PatchPlan, error: Exception, phase: str) -> None:
        del patch_plan, phase
        if getattr(self.gateway, "generation_poisoned", False):
            failure = self.gateway.transaction_failure
            if failure is not None:
                _request_poison_restart(self.gateway, failure)
            return
        reason, obligation = _first_failure(error, self.failure_phase)
        if getattr(self.gateway, "mutation_started", False):
            failure = self.gateway._poison_cfg_generation(
                reason=reason,
                failure_phase=self.failure_phase,
                first_failed_obligation=obligation,
            )
            _request_poison_restart(self.gateway, failure)
            raise PatchTransactionPoisoned(
                failure,
                observed_dispatcher_removal_validation=(
                    self.participant._observed_dispatcher_removal_validation
                ),
                observed_dispatcher_coverage_validation=(
                    self.participant._observed_dispatcher_coverage_validation
                ),
            ) from error
        if self.gateway.transaction_failure is None:
            self.gateway._record_clean_cfg_failure(
                reason=reason,
                failure_phase=self.failure_phase,
                first_failed_obligation=obligation,
            )
        self.gateway.abort(reason=reason)


def execute_patch_transaction(
    root_gateway: object,
    translator: object,
    plan: PatchPlan,
    mba: object,
    *,
    pre_cfg: FlowGraph,
    contract: object | None = None,
    post_apply_hook: object | None = None,
    attempt_id: TransactionAttemptId | None = None,
) -> PatchTransactionExecution:
    """Execute one ordinary PatchPlan through immutable authority and one coordinator."""
    if not isinstance(plan, PatchPlan):
        raise TypeError("patch transaction requires a PatchPlan")
    if not isinstance(pre_cfg, FlowGraph):
        raise TypeError("patch transaction requires an immutable pre-CFG")
    gateway = root_gateway.new_transaction()
    participant = HexRaysPatchTransactionParticipant(
        gateway=gateway,
        translator=translator,
        mba=mba,
        plan=plan,
        contract=contract,
        post_apply_hook=post_apply_hook,
        attempt_authority=attempt_id,
    )
    phase = "projection"
    try:
        projected = participant.project(plan, pre_cfg)
        phase = "preflight"
        prepared = participant.preflight(projected)
        phase = "binding"
        bound = participant.bind(prepared, gateway.identity_index)
    except Exception as error:
        reason, obligation = _first_failure(error, phase)
        if gateway.current_transaction_attempt is not None:
            gateway._record_clean_cfg_failure(
                reason=reason,
                failure_phase=phase,
                first_failed_obligation=obligation,
            )
            gateway.abort(reason=reason)
        raise
    if not isinstance(bound, BoundPatchCfgTransaction):
        raise TypeError("patch participant returned invalid binding authority")
    from d810.transforms.fragment_to_patch import (
        CfgTransactionCoordinator,
        PatchTransactionParticipant,
    )

    lifecycle = _PatchTransactionLifecycle(
        participant=participant,
        bound=bound,
        gateway=gateway,
        plan=plan,
        prepared=prepared,
    )
    return CfgTransactionCoordinator(lifecycle).execute(
        PatchTransactionParticipant(),
        plan,
    )


__all__ = [
    "BoundPatchCfgTransaction",
    "HexRaysPatchTransactionParticipant",
    "PatchTransactionExecution",
    "PatchTransactionPoisoned",
    "PatchTransactionPostObservationRejected",
    "PatchTransactionPreflightRejected",
    "execute_patch_transaction",
]
